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
  // Never call arbitrary descriptions/getters or dump ivar values: they may contain secrets.
  return { object_id: args.object_id, class_name: object.$className, kind: object.$kind,
    protocols: Object.keys(object.$protocols), methods: object.$ownMethods.slice(0, args.limit || 100),
    ivar_names: Object.keys(object.$ivars).slice(0, args.limit || 100), observed: true };
}

export function implementation(args: Args): Args {
  const method = methodFor(args);
  return { class_name: args.class_name, ...metadata(method, `${args.class_method ? "+" : "-"} ${args.selector}`) };
}

export function findInstances(args: Args): Promise<Args> {
  const values: Args[] = [], limit = args.limit || 100;
  return new Promise((resolve, reject) => {
    try {
      ObjC.choose(classFor(args.class_name), {
        onMatch(object) {
          values.push({ object_id: objectId(object), class_name: object.$className, observed: true });
          if (values.length >= limit) return "stop";
        },
        onComplete() { resolve({ instances: values, limit_reached: values.length >= limit, supported: true,
          warning: "Heap enumeration is best effort and may pause the target process" }); },
      });
    } catch (error) { reject(error); }
  });
}
