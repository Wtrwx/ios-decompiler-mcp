import ObjC from "frida-objc-bridge";

export type Args = { [key: string]: any };
export const state = {
  session: "",
  bundle: "",
  serial: 0,
  objects: new Map<string, ObjC.Object>(),
  byPointer: new Map<string, string>(),
};

export function requireRuntime(): void {
  if (!ObjC.available) throw new Error("Objective-C runtime is unavailable; pure Swift metadata is not reconstructed");
}

export function main<T>(work: () => T): Promise<T> {
  requireRuntime();
  return new Promise((resolve, reject) => {
    ObjC.schedule(ObjC.mainQueue, () => {
      try { resolve(work()); } catch (error) { reject(error); }
    });
  });
}

// Explicit retains make IDs safe across UI tree updates. Bound the registry and
// release on main-thread disposal. IDs never cross process/script generations.
export function objectId(object: ObjC.Object | null): string | null {
  if (object === null || object.handle.isNull()) return null;
  const address = object.handle.toString();
  const known = state.byPointer.get(address);
  if (known) return known;
  if (state.objects.size >= 2048) throw new Error("Object registry limit reached; close this session and attach again");
  const id = `${state.session}:object_${++state.serial}`;
  object.retain();
  state.objects.set(id, object);
  state.byPointer.set(address, id);
  return id;
}

export function objectFor(id: string): ObjC.Object {
  if (!id.startsWith(state.session + ":")) throw new Error("Object belongs to another process session");
  const object = state.objects.get(id);
  if (!object) throw new Error("Unknown session-scoped object ID");
  return object;
}

export function releaseObjects(): void {
  for (const object of state.objects.values()) object.release();
  state.objects.clear();
  state.byPointer.clear();
}

export function array(collection: any, limit = 10000): ObjC.Object[] {
  const values: ObjC.Object[] = [];
  if (collection == null || collection.handle?.isNull()) return values;
  const count = Math.min(Number(collection.count()), limit);
  for (let i = 0; i < count; i++) values.push(collection.objectAtIndex_(i));
  return values;
}

export function nullableString(value: any, max = 512): string | null {
  if (value == null || value.handle?.isNull()) return null;
  return String(value).slice(0, max);
}

export function classFor(name: string): ObjC.Object {
  requireRuntime();
  const klass = ObjC.classes[name];
  if (!klass) throw new Error(`Class is not registered: ${name}`);
  return klass;
}

export function methodFor(args: Args): ObjC.ObjectMethod {
  const klass = classFor(args.class_name);
  const key = `${args.class_method ? "+" : "-"} ${args.selector}`;
  const method = klass[key] as ObjC.ObjectMethod;
  if (!method) throw new Error(`Method does not exist: ${args.class_name} ${key}`);
  return method;
}

export function imageFor(address: NativePointer): Args | null {
  const stripped = Process.arch === "arm64" ? address.strip() : address;
  const image = Process.findModuleByAddress(stripped);
  if (!image) return null;
  let uuid: string | null = null;
  let architecture: string = Process.arch;
  // Read only the Mach-O header/load commands, never arbitrary application data.
  try {
    if (image.base.readU32() === 0xfeedfacf) {
      if ((image.base.add(8).readU32() & 0xffffff) === 2 && Process.arch === "arm64") architecture = "arm64e";
      const count = Math.min(image.base.add(16).readU32(), 4096);
      const bytes = Math.min(image.base.add(20).readU32(), 1048576);
      let cursor = image.base.add(32);
      const end = cursor.add(bytes);
      for (let i = 0; i < count && cursor.compare(end) < 0; i++) {
        const command = cursor.readU32();
        const size = cursor.add(4).readU32();
        if (size < 8 || cursor.add(size).compare(end) > 0) break;
        if (command === 0x1b && size >= 24) {
          const raw = new Uint8Array(cursor.add(8).readByteArray(16)!);
          const hex = Array.from(raw, b => b.toString(16).padStart(2, "0")).join("");
          uuid = [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
          break;
        }
        cursor = cursor.add(size);
      }
    }
  } catch (_) { /* UUID is unknown: correlation must refuse an asserted match. */ }
  return { name: image.name, path: image.path, runtime_base: image.base.toString(), size: image.size, uuid,
    canonical_address: stripped.toString(), pac_stripped: !stripped.equals(address), architecture };
}
