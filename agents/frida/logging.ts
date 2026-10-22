import ObjC from "frida-objc-bridge";
import { Args } from "./common.js";

// Buffer in the agent: no send() for individual logs and no unbounded host queue.
const listeners: InvocationListener[] = [];
let entries: Args[] = [], sequence = 0, dropped = 0, characters = 0;
let capacity = 200, maxLength = 512;
let sources: string[] = [], unavailable: string[] = [];
let failures: Args[] = [];
const reading = new Set<number>();

function cString(pointer: NativePointer, bytes = maxLength * 4): string {
  let length = 0;
  while (length < bytes && pointer.add(length).readU8()) length++;
  // A UTF-8 code point can straddle the byte bound.
  for (let end = length; end >= Math.max(0, length - 3); end--) {
    try { return pointer.readUtf8String(end) || ""; } catch (_) { /* Try a complete prefix. */ }
  }
  return "";
}
function nsString(object: ObjC.Object): string {
  return String(object.substringToIndex_(Math.min(Number(object.length()), maxLength + 1)));
}

function append(source: string, level: string, text: string, kind: string): void {
  const message = text.slice(0, maxLength);
  if (!message) return;
  const entry = { sequence: ++sequence, timestamp_ms: Date.now(), source, level, message,
    message_kind: kind, truncated: text.length > maxLength };
  entries.push(entry); characters += message.length;
  while (entries.length > capacity || characters > 65536) {
    characters -= entries.shift()!.message.length; dropped++;
  }
}

function hook(name: string, source: string, read: (args: InvocationArguments) => void): void {
  const address = Module.findGlobalExportByName(name);
  if (!address) { unavailable.push(name); return; }
  try { listeners.push(Interceptor.attach(address, { onEnter(args) {
    if (reading.has(this.threadId)) return;
    reading.add(this.threadId);
    try { read(args); } catch (_) { /* A malformed log must not affect the app. */ }
    finally { reading.delete(this.threadId); }
  } })); }
  catch (error) { unavailable.push(name); failures.push({ name, reason: String(error).slice(0, 160) }); return; }
  if (!sources.includes(source)) sources.push(source);
}

function start(args: Args): void {
  if (listeners.length) return;
  capacity = args.capacity; maxLength = args.max_message_length;
  unavailable = []; sources = []; failures = [];
  if (args.sources.includes("os_log")) hook("_os_log_impl", "os_log", values => {
    const level = ({ 0: "default", 1: "info", 2: "debug", 16: "error", 17: "fault" } as Args)[values[2].toInt32()] || "default";
    // os_log's private, encoded argument buffer is not a formatted C string.
    // Label the format explicitly instead of inventing expanded values.
    append("os_log", level, cString(values[3]), "format");
  });
  if (args.sources.includes("nslog")) {
    hook("NSLog", "nslog", values => append("nslog", "default", nsString(new ObjC.Object(values[0])), "format"));
    hook("NSLogv", "nslog", values => {
      const pool = ObjC.classes.NSAutoreleasePool.alloc().init();
      let formatted: ObjC.Object | null = null;
      try {
        formatted = ObjC.classes.NSString.alloc().initWithFormat_arguments_(new ObjC.Object(values[0]), values[1]);
        append("nslog", "default", nsString(formatted!), "rendered");
      } finally { if (formatted) formatted.release(); pool.release(); }
    });
  }
  if (args.sources.includes("stdio")) {
    const read = (values: InvocationArguments) => {
      const fd = values[0].toInt32();
      if (fd !== 1 && fd !== 2) return;
      const count = Math.min(Number(values[2].toString()), maxLength);
      if (count > 0) append(fd === 1 ? "stdout" : "stderr", fd === 1 ? "info" : "error", cString(values[1], count), "rendered");
    };
    hook("write", "stdio", read);
    hook("__write_nocancel", "stdio", read);
  }
}

export async function run(args: Args): Promise<Args> {
  if (args.action === "stop") {
    dispose();
    return { active: false, stopped: true, next_cursor: sequence, dropped };
  }
  start(args);
  if (args.wait_ms) await new Promise(resolve => setTimeout(resolve, args.wait_ms));
  const reset = args.after > sequence;
  const eligible = entries.filter(e => e.sequence > (reset ? 0 : args.after));
  const matching = eligible.filter(e => (!args.level || e.level === args.level) && (!args.contains || e.message.includes(args.contains)));
  const page = matching.slice(0, args.limit);
  const next = matching.length > page.length ? page[page.length - 1].sequence : sequence;
  return { active: listeners.length > 0, sources, unavailable, failures, entries: page, next_cursor: next,
    has_more: matching.length > page.length, cursor_reset: reset, dropped, buffered: entries.length,
    oldest_cursor: entries[0]?.sequence ?? sequence + 1, capacity, max_message_length: maxLength };
}

export function dispose(): void {
  for (const listener of listeners) listener.detach();
  listeners.length = 0; entries = []; characters = 0; reading.clear();
}
