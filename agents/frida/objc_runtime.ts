import ObjC from "frida-objc-bridge";
import { Args, classFor, imageFor, methodFor, objectFor, objectId } from "./common.js";

function metadata(method: ObjC.ObjectMethod, key: string): Args {
  const implementation = method.implementation;
  return { selector: key.slice(2), class_method: key.startsWith("+"), type_encoding: method.types,
    return_type: method.returnType, argument_types: method.argumentTypes, implementation: implementation.toString(),
    image: imageFor(implementation), observed: true };
}

function copyList(klass: ObjC.Object, copyName: string, read: (entry: NativePointer) => Args): Args[] {
  const count = Memory.alloc(4); count.writeU32(0);
  const copy = ObjC.api[copyName] || new NativeFunction(Module.getGlobalExportByName(copyName), "pointer", ["pointer", "pointer"]);
  const entries = copy(klass.handle, count) as NativePointer;
  const result: Args[] = [];
  try {
    for (let i = 0; i < Math.min(count.readU32(), 10000); i++) {
      result.push(read(entries.add(i * Process.pointerSize).readPointer()));
    }
  } finally {
    if (!entries.isNull()) new NativeFunction(Module.getGlobalExportByName("free"), "void", ["pointer"])(entries);
  }
  return result;
}

export function searchClasses(args: Args): Args {
  const query = String(args.query || "").toLowerCase();
  const names = Object.keys(ObjC.classes).filter(name => name.toLowerCase().includes(query)).sort();
  const offset = args.offset || 0, limit = args.limit || 100;
  return { classes: names.slice(offset, offset + limit), total: names.length,
    next_offset: offset + limit < names.length ? offset + limit : null, observed: true };
}

export function methods(args: Args): Args {
  const klass = classFor(args.class_name);
  const names = args.include_inherited ? klass.$methods : klass.$ownMethods;
  const filtered = names.filter(key => args.class_method == null || key.startsWith(args.class_method ? "+" : "-"));
  const offset = args.offset || 0, limit = args.limit || 100;
  return { methods: filtered.slice(offset, offset + limit).map(key => metadata(klass[key] as ObjC.ObjectMethod, key)),
    total: filtered.length, next_offset: offset + limit < filtered.length ? offset + limit : null, observed: true };
}

export function properties(args: Args): Args {
  const klass = classFor(args.class_name);
  const values = copyList(klass, "class_copyPropertyList", entry => ({
    name: ObjC.api.property_getName(entry).readUtf8String(),
    attributes: new NativeFunction(Module.getGlobalExportByName("property_getAttributes"), "pointer", ["pointer"])(entry).readUtf8String(), observed: true,
  }));
  const offset = args.offset || 0, limit = args.limit || 100;
  return { properties: values.slice(offset, offset + limit), total: values.length,
    next_offset: offset + limit < values.length ? offset + limit : null };
}

export function ivars(args: Args): Args {
  const values = copyList(classFor(args.class_name), "class_copyIvarList", entry => ({
    name: ObjC.api.ivar_getName(entry).readUtf8String(),
    type_encoding: ObjC.api.ivar_getTypeEncoding(entry).readUtf8String(),
    offset: Number(ObjC.api.ivar_getOffset(entry)), observed: true,
  }));
  const offset = args.offset || 0, limit = args.limit || 100;
  return { ivars: values.slice(offset, offset + limit), total: values.length,
    next_offset: offset + limit < values.length ? offset + limit : null };
}

export function dumpClass(args: Args): Args {
  const klass = classFor(args.class_name);
  const hierarchy: string[] = [];
  let current: ObjC.Object | null = klass;
  while (current && hierarchy.length < 64) { hierarchy.push(current.$className); current = current.$superClass; }
  const cap = { ...args, offset: 0, limit: args.limit || 200 };
  return { class_name: args.class_name, superclass: klass.$superClass?.$className || null, hierarchy,
    protocols: Object.keys(klass.$protocols), methods: methods(cap), properties: properties(cap), ivars: ivars(cap),
    image: klass.$moduleName, observed: true, swift_limitations: "Only Objective-C-exposed Swift classes and methods are visible" };
}

export function inspectObject(args: Args): Args {
  const object = objectFor(args.object_id);
  if (args.include_values || args.field_names) return readObject(object, args);
  return { object_id: args.object_id, class_name: object.$className, kind: object.$kind,
    protocols: Object.keys(object.$protocols), methods: object.$ownMethods.slice(0, args.limit || 100),
    ivar_names: Object.keys(object.$ivars).slice(0, args.limit || 100), observed: true };
}

export function implementation(args: Args): Args {
  const method = methodFor(args);
  return { class_name: args.class_name, ...metadata(method, `${args.class_method ? "+" : "-"} ${args.selector}`) };
}

const sensitive = /password|passwd|secret|authorization|cookie|credential|access.?token|private.?key/i;

function isKind(object: ObjC.Object, name: string): boolean {
  return !!ObjC.classes[name] && !!object.isKindOfClass_(ObjC.classes[name]);
}
function boundedString(value: ObjC.Object, maximum: number): string {
  const length = Number(value.length());
  return String(length > maximum ? value.substringToIndex_(maximum) : value);
}
function valueOf(value: any, args: Args, depth = 0, seen = new Set<string>()): any {
  const budget = args._value_budget;
  if (++budget.nodes > 1000 || budget.characters >= 32768) return { truncated: "value_budget" };
  if (value == null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") {
    const text = value.slice(0, Math.min(args.max_string_length || 128, 32768 - budget.characters));
    budget.characters += text.length; return text;
  }
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return depth >= (args.max_depth ?? 1) ? { array_length: value.length } :
    value.slice(0, args.max_items || 5).map(item => valueOf(item, args, depth + 1, seen));
  if (!value.handle) return { scalar: String(value).slice(0, 128) }; // NativePointer/Int64; never dereference.
  if (value.handle.isNull()) return null;
  const maximum = Math.min(args.max_string_length || 128, 32768 - budget.characters);
  if (isKind(value, "NSString")) {
    const text = boundedString(value, maximum); budget.characters += text.length; return text;
  }
  if (isKind(value, "NSNumber")) return { number: String(value.stringValue()) };
  if (isKind(value, "NSNull")) return null;
  const id = objectId(value), result: Args = { object_id: id, class_name: value.$className };
  if (isKind(value, "NSData")) return { ...result, bytes: Number(value.length()) };
  if (depth >= (args.max_depth ?? 1) || seen.has(id!)) return result;
  seen.add(id!);
  const maximumItems = args.max_items || 5;
  if (isKind(value, "NSArray")) {
    const count = Number(value.count());
    result.items = Array.from({ length: Math.min(count, maximumItems) }, (_, i) => valueOf(value.objectAtIndex_(i), args, depth + 1, seen));
    result.total = count;
  } else if (isKind(value, "NSDictionary")) {
    result.entries = []; result.total = Number(value.count());
    const enumerator = value.keyEnumerator();
    for (let i = 0; i < maximumItems; i++) {
      const key = enumerator.nextObject();
      if (!key || key.handle.isNull()) break;
      const stringKey = isKind(key, "NSString"), fullName = stringKey ? boundedString(key, 4096) : `[${key.$className}]`;
      const secret = sensitive.test(fullName) || (stringKey && Number(key.length()) > 4096);
      result.entries.push({ key: fullName.slice(0, maximum), value: secret ? "[REDACTED]" : valueOf(value.objectForKey_(key), args, depth + 1, seen) });
    }
  }
  return result;
}

export function readObject(object: ObjC.Object, args: Args): Args {
  args._value_budget ||= { nodes: 0, characters: 0 };
  const available = Object.keys(object.$ivars), names: string[] = args.field_names ?? available.slice(0, args.max_fields || 8);
  const values: Args = Object.create(null);
  for (const name of names) {
    if (sensitive.test(name)) { values[name] = "[REDACTED]"; continue; }
    if (!available.includes(name)) { values[name] = { unavailable: "ivar_not_found" }; continue; }
    try { values[name] = valueOf(object.$ivars[name], args); }
    catch (error) { values[name] = { unavailable: error instanceof Error ? error.name : "read_failed" }; }
  }
  return { object_id: objectId(object), class_name: object.$className, values,
    total_ivars: available.length, fields_truncated: !args.field_names && available.length > names.length,
    values_truncated: args._value_budget.nodes > 1000 || args._value_budget.characters >= 32768 };
}

export function inspectObjects(args: Args): Args {
  return { instances: args.object_ids.map((id: string) => readObject(objectFor(id), args)), source: "leased_handles" };
}

export function findInstances(args: Args): Args {
  const values: Args[] = [], limit = args.limit || 100, offset = args.offset || 0;
  let visited = 0;
  // frida-objc-bridge choose() invokes its callbacks synchronously. Keeping
  // collection synchronous also keeps every retain inside its main-thread lease.
  ObjC.choose({ class: classFor(args.class_name), subclasses: args.include_subclasses ?? true }, {
    onMatch(object) {
      if (visited++ < offset) return;
      values.push(args.include_values ? readObject(object, args) : { object_id: objectId(object), class_name: object.$className });
      if (values.length >= limit) return "stop";
    },
    onComplete() {},
  });
  return { instances: values, limit_reached: values.length >= limit, supported: true,
    warning: "Heap enumeration scans the allocator and may pause the target; cached pages and leased handles avoid rescanning" };
}
