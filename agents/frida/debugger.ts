import { Args } from "./common.js";

export function inspect(args: Args): Args {
  let threads = Process.enumerateThreads();
  if (args.thread_id != null) threads = threads.filter(t => t.id === args.thread_id);
  else threads = threads.slice(0, args.max_threads);
  if (args.thread_id != null && !threads.length) throw new Error("Thread is no longer present in this process");
  const rows = threads.map(thread => {
    const result: Args = { thread_id: thread.id, state: thread.state };
    if (thread.name) result.name = thread.name;
    if (args.mode === "backtrace") {
      try {
        result.frames = Thread.backtrace(thread.context, Backtracer.ACCURATE).slice(0, args.max_frames).map((address, index) => {
          const frame: Args = { index, address: address.toString() };
          if (args.symbols) { frame.symbol = DebugSymbol.fromAddress(address).toString(); const image = Process.findModuleByAddress(address.strip()); if (image) frame.image = image.name; }
          return frame;
        });
      } catch (_) { result.unavailable = "Thread context could not be unwound"; }
    }
    if (args.mode === "registers") {
      const names = args.register_names.length ? args.register_names : ["pc", "sp", "fp", "lr"];
      result.registers = Object.fromEntries(names.filter((name: string) => name in thread.context).map((name: string) => [name, String((thread.context as any)[name])]));
    }
    return result;
  });
  return { backend: "frida", pid: Process.id, threads: rows, observed: true, consistent_stop: false };
}
