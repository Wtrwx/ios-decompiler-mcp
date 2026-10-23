📦
164121 /agents/frida/index.js
✄
// node_modules/frida-objc-bridge/lib/api.js
var cachedApi = null;
var defaultInvocationOptions = {
  exceptions: "propagate"
};
function getApi() {
  if (cachedApi !== null) {
    return cachedApi;
  }
  const temporaryApi = {};
  const pending = [
    {
      module: "libsystem_malloc.dylib",
      functions: {
        "free": ["void", ["pointer"]]
      }
    },
    {
      module: "libobjc.A.dylib",
      functions: {
        "objc_msgSend": function(address) {
          this.objc_msgSend = address;
        },
        "objc_msgSend_stret": function(address) {
          this.objc_msgSend_stret = address;
        },
        "objc_msgSend_fpret": function(address) {
          this.objc_msgSend_fpret = address;
        },
        "objc_msgSendSuper": function(address) {
          this.objc_msgSendSuper = address;
        },
        "objc_msgSendSuper_stret": function(address) {
          this.objc_msgSendSuper_stret = address;
        },
        "objc_msgSendSuper_fpret": function(address) {
          this.objc_msgSendSuper_fpret = address;
        },
        "objc_getClassList": ["int", ["pointer", "int"]],
        "objc_lookUpClass": ["pointer", ["pointer"]],
        "objc_allocateClassPair": ["pointer", ["pointer", "pointer", "pointer"]],
        "objc_disposeClassPair": ["void", ["pointer"]],
        "objc_registerClassPair": ["void", ["pointer"]],
        "class_isMetaClass": ["bool", ["pointer"]],
        "class_getName": ["pointer", ["pointer"]],
        "class_getImageName": ["pointer", ["pointer"]],
        "class_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "class_copyMethodList": ["pointer", ["pointer", "pointer"]],
        "class_getClassMethod": ["pointer", ["pointer", "pointer"]],
        "class_getInstanceMethod": ["pointer", ["pointer", "pointer"]],
        "class_getSuperclass": ["pointer", ["pointer"]],
        "class_addProtocol": ["bool", ["pointer", "pointer"]],
        "class_addMethod": ["bool", ["pointer", "pointer", "pointer", "pointer"]],
        "class_copyIvarList": ["pointer", ["pointer", "pointer"]],
        "objc_getProtocol": ["pointer", ["pointer"]],
        "objc_copyProtocolList": ["pointer", ["pointer"]],
        "objc_allocateProtocol": ["pointer", ["pointer"]],
        "objc_registerProtocol": ["void", ["pointer"]],
        "protocol_getName": ["pointer", ["pointer"]],
        "protocol_copyMethodDescriptionList": ["pointer", ["pointer", "bool", "bool", "pointer"]],
        "protocol_copyPropertyList": ["pointer", ["pointer", "pointer"]],
        "protocol_copyProtocolList": ["pointer", ["pointer", "pointer"]],
        "protocol_addProtocol": ["void", ["pointer", "pointer"]],
        "protocol_addMethodDescription": ["void", ["pointer", "pointer", "pointer", "bool", "bool"]],
        "ivar_getName": ["pointer", ["pointer"]],
        "ivar_getTypeEncoding": ["pointer", ["pointer"]],
        "ivar_getOffset": ["pointer", ["pointer"]],
        "object_isClass": ["bool", ["pointer"]],
        "object_getClass": ["pointer", ["pointer"]],
        "object_getClassName": ["pointer", ["pointer"]],
        "method_getName": ["pointer", ["pointer"]],
        "method_getTypeEncoding": ["pointer", ["pointer"]],
        "method_getImplementation": ["pointer", ["pointer"]],
        "method_setImplementation": ["pointer", ["pointer", "pointer"]],
        "property_getName": ["pointer", ["pointer"]],
        "property_copyAttributeList": ["pointer", ["pointer", "pointer"]],
        "sel_getName": ["pointer", ["pointer"]],
        "sel_registerName": ["pointer", ["pointer"]],
        "class_getInstanceSize": ["pointer", ["pointer"]]
      },
      optionals: {
        "objc_msgSend_stret": "ABI",
        "objc_msgSend_fpret": "ABI",
        "objc_msgSendSuper_stret": "ABI",
        "objc_msgSendSuper_fpret": "ABI",
        "object_isClass": "iOS8"
      }
    },
    {
      module: "libdispatch.dylib",
      functions: {
        "dispatch_async_f": ["void", ["pointer", "pointer", "pointer"]]
      },
      variables: {
        "_dispatch_main_q": function(address) {
          this._dispatch_main_q = address;
        }
      }
    }
  ];
  let remaining = 0;
  pending.forEach(function(api2) {
    const functions = api2.functions || {};
    const variables = api2.variables || {};
    const optionals = api2.optionals || {};
    remaining += Object.keys(functions).length + Object.keys(variables).length;
    const exportByName = (Process.findModuleByName(api2.module)?.enumerateExports() ?? []).reduce(function(result, exp) {
      result[exp.name] = exp;
      return result;
    }, {});
    Object.keys(functions).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "function") {
        const signature2 = functions[name];
        if (typeof signature2 === "function") {
          signature2.call(temporaryApi, exp.address);
        } else {
          temporaryApi[name] = new NativeFunction(exp.address, signature2[0], signature2[1], defaultInvocationOptions);
        }
        remaining--;
      } else {
        const optional = optionals[name];
        if (optional)
          remaining--;
      }
    });
    Object.keys(variables).forEach(function(name) {
      const exp = exportByName[name];
      if (exp !== void 0 && exp.type === "variable") {
        const handler = variables[name];
        handler.call(temporaryApi, exp.address);
        remaining--;
      }
    });
  });
  if (remaining === 0) {
    if (!temporaryApi.objc_msgSend_stret)
      temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSend_fpret)
      temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
    if (!temporaryApi.objc_msgSendSuper_stret)
      temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
    if (!temporaryApi.objc_msgSendSuper_fpret)
      temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;
    cachedApi = temporaryApi;
  }
  return cachedApi;
}

// node_modules/frida-objc-bridge/lib/fastpaths.js
var code = `#include <glib.h>
#include <ptrauth.h>

#define KERN_SUCCESS 0
#define MALLOC_PTR_IN_USE_RANGE_TYPE 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define OBJC_ISA_MASK 0x7ffffffffff8ULL
#elif defined (HAVE_ARM64)
# define OBJC_ISA_MASK 0xffffffff8ULL
#endif

typedef struct _ChooseContext ChooseContext;

typedef struct _malloc_zone_t malloc_zone_t;
typedef struct _malloc_introspection_t malloc_introspection_t;
typedef struct _vm_range_t vm_range_t;

typedef gpointer Class;
typedef int kern_return_t;
typedef guint mach_port_t;
typedef mach_port_t task_t;
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

struct _ChooseContext
{
  GHashTable * classes;
  GArray * matches;
};

struct _malloc_zone_t
{
  void * reserved1;
  void * reserved2;
  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);
  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);
  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);
  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);
  void (* free) (struct _malloc_zone_t * zone, void * ptr);
  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);
  void (* destroy) (struct _malloc_zone_t * zone);
  const char * zone_name;

  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);
  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);

  malloc_introspection_t * introspect;
};

typedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);
typedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
typedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
      vm_range_recorder_t recorder);

struct _malloc_introspection_t
{
  enumerator_func enumerator;
};

struct _vm_range_t
{
  vm_address_t address;
  vm_size_t size;
};

extern int objc_getClassList (Class * buffer, int buffer_count);
extern Class class_getSuperclass (Class cls);
extern size_t class_getInstanceSize (Class cls);
extern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);

static void collect_subclasses (Class klass, GHashTable * result);
static void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);

extern mach_port_t selfTask;

gpointer *
choose (Class * klass,
        gboolean consider_subclasses,
        guint * count)
{
  ChooseContext ctx;
  GHashTable * classes;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count, i;

  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  ctx.classes = classes;
  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  if (consider_subclasses)
    collect_subclasses (klass, classes);
  else
    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));

  malloc_zone_count = 0;
  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;
    enumerator_func enumerator;

    if (zone != NULL && zone->introspect != NULL &&
        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)
    {
      enumerator = ptrauth_sign_unauthenticated (
          ptrauth_strip (enumerator, ptrauth_key_asia),
          ptrauth_key_asia, 0);

      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,
          collect_matches_in_ranges);
    }
  }

  g_hash_table_unref (classes);

  *count = ctx.matches->len;

  return (gpointer *) g_array_free (ctx.matches, FALSE);
}

void
destroy (gpointer mem)
{
  g_free (mem);
}

static void
collect_subclasses (Class klass,
                    GHashTable * result)
{
  Class * classes;
  int buffer_count, count, i;

  buffer_count = objc_getClassList (NULL, 0);
  classes = g_malloc (buffer_count * sizeof (gpointer));
  count = objc_getClassList (classes, buffer_count);
  if (count > buffer_count)
    count = buffer_count;

  for (i = 0; i != count; i++)
  {
    Class candidate = classes[i];
    Class c;

    c = candidate;
    do
    {
      if (c == klass)
      {
        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));
        break;
      }

      c = class_getSuperclass (c);
    }
    while (c != NULL);
  }

  g_free (classes);
}

static void
collect_matches_in_ranges (task_t task,
                           void * user_data,
                           unsigned type,
                           vm_range_t * ranges,
                           unsigned count)
{
  ChooseContext * ctx = user_data;
  GHashTable * classes = ctx->classes;
  unsigned i;

  for (i = 0; i != count; i++)
  {
    const vm_range_t * range = &ranges[i];
    gconstpointer candidate = GSIZE_TO_POINTER (range->address);
    gconstpointer isa;
    guint instance_size;

    isa = *(gconstpointer *) candidate;
#ifdef OBJC_ISA_MASK
    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);
#endif

    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));
    if (instance_size != 0 && range->size >= instance_size)
    {
      g_array_append_val (ctx->matches, candidate);
    }
  }
}

static kern_return_t
read_local_memory (task_t remote_task,
                   vm_address_t remote_address,
                   vm_size_t size,
                   void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}
`;
var { pointerSize: pointerSize2 } = Process;
var cachedModule = null;
function get() {
  if (cachedModule === null)
    cachedModule = compileModule();
  return cachedModule;
}
function compileModule() {
  const {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize
  } = getApi();
  const selfTask = Memory.alloc(4);
  selfTask.writeU32(Module.getGlobalExportByName("mach_task_self_").readU32());
  const cm = new CModule(code, {
    objc_getClassList,
    class_getSuperclass,
    class_getInstanceSize,
    malloc_get_all_zones: Process.getModuleByName("/usr/lib/system/libsystem_malloc.dylib").getExportByName("malloc_get_all_zones"),
    selfTask
  });
  const _choose = new NativeFunction(cm.choose, "pointer", ["pointer", "bool", "pointer"]);
  const _destroy = new NativeFunction(cm.destroy, "void", ["pointer"]);
  return {
    handle: cm,
    choose(klass, considerSubclasses) {
      const result = [];
      const countPtr = Memory.alloc(4);
      const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
      try {
        const count = countPtr.readU32();
        for (let i = 0; i !== count; i++)
          result.push(matches.add(i * pointerSize2).readPointer());
      } finally {
        _destroy(matches);
      }
      return result;
    }
  };
}

// node_modules/frida-objc-bridge/index.js
function Runtime() {
  const pointerSize = Process.pointerSize;
  let api = null;
  let apiError = null;
  const realizedClasses = /* @__PURE__ */ new Set();
  const classRegistry = new ClassRegistry();
  const protocolRegistry = new ProtocolRegistry();
  const replacedMethods = /* @__PURE__ */ new Map();
  const scheduledWork = /* @__PURE__ */ new Map();
  let nextId = 1;
  let workCallback = null;
  let NSAutoreleasePool = null;
  const bindings = /* @__PURE__ */ new Map();
  let readObjectIsa = null;
  const msgSendBySignatureId = /* @__PURE__ */ new Map();
  const msgSendSuperBySignatureId = /* @__PURE__ */ new Map();
  let cachedNSString = null;
  let cachedNSStringCtor = null;
  let cachedNSNumber = null;
  let cachedNSNumberCtor = null;
  let singularTypeById = null;
  let modifiers = null;
  try {
    tryInitialize();
  } catch (e) {
  }
  function tryInitialize() {
    if (api !== null)
      return true;
    if (apiError !== null)
      throw apiError;
    try {
      api = getApi();
    } catch (e) {
      apiError = e;
      throw e;
    }
    return api !== null;
  }
  function dispose() {
    for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
      const methodHandle = ptr(rawMethodHandle);
      const [oldImp, newImp] = impls;
      if (api.method_getImplementation(methodHandle).equals(newImp))
        api.method_setImplementation(methodHandle, oldImp);
    }
    replacedMethods.clear();
  }
  Script.bindWeak(this, dispose);
  Object.defineProperty(this, "available", {
    enumerable: true,
    get() {
      return tryInitialize();
    }
  });
  Object.defineProperty(this, "api", {
    enumerable: true,
    get() {
      return getApi();
    }
  });
  Object.defineProperty(this, "classes", {
    enumerable: true,
    value: classRegistry
  });
  Object.defineProperty(this, "protocols", {
    enumerable: true,
    value: protocolRegistry
  });
  Object.defineProperty(this, "Object", {
    enumerable: true,
    value: ObjCObject
  });
  Object.defineProperty(this, "Protocol", {
    enumerable: true,
    value: ObjCProtocol
  });
  Object.defineProperty(this, "Block", {
    enumerable: true,
    value: Block
  });
  Object.defineProperty(this, "mainQueue", {
    enumerable: true,
    get() {
      return api?._dispatch_main_q ?? null;
    }
  });
  Object.defineProperty(this, "registerProxy", {
    enumerable: true,
    value: registerProxy
  });
  Object.defineProperty(this, "registerClass", {
    enumerable: true,
    value: registerClass
  });
  Object.defineProperty(this, "registerProtocol", {
    enumerable: true,
    value: registerProtocol
  });
  Object.defineProperty(this, "bind", {
    enumerable: true,
    value: bind
  });
  Object.defineProperty(this, "unbind", {
    enumerable: true,
    value: unbind
  });
  Object.defineProperty(this, "getBoundData", {
    enumerable: true,
    value: getBoundData
  });
  Object.defineProperty(this, "enumerateLoadedClasses", {
    enumerable: true,
    value: enumerateLoadedClasses
  });
  Object.defineProperty(this, "enumerateLoadedClassesSync", {
    enumerable: true,
    value: enumerateLoadedClassesSync
  });
  Object.defineProperty(this, "choose", {
    enumerable: true,
    value: choose
  });
  Object.defineProperty(this, "chooseSync", {
    enumerable: true,
    value(specifier) {
      const instances = [];
      choose(specifier, {
        onMatch(i) {
          instances.push(i);
        },
        onComplete() {
        }
      });
      return instances;
    }
  });
  this.schedule = function(queue, work) {
    const id = ptr(nextId++);
    scheduledWork.set(id.toString(), work);
    if (workCallback === null) {
      workCallback = new NativeCallback(performScheduledWorkItem, "void", ["pointer"]);
    }
    Script.pin();
    api.dispatch_async_f(queue, id, workCallback);
  };
  function performScheduledWorkItem(rawId) {
    const id = rawId.toString();
    const work = scheduledWork.get(id);
    scheduledWork.delete(id);
    if (NSAutoreleasePool === null)
      NSAutoreleasePool = classRegistry.NSAutoreleasePool;
    const pool = NSAutoreleasePool.alloc().init();
    let pendingException = null;
    try {
      work();
    } catch (e) {
      pendingException = e;
    }
    pool.release();
    setImmediate(performScheduledWorkCleanup, pendingException);
  }
  function performScheduledWorkCleanup(pendingException) {
    Script.unpin();
    if (pendingException !== null) {
      throw pendingException;
    }
  }
  this.implement = function(method2, fn) {
    return new NativeCallback(fn, method2.returnType, method2.argumentTypes);
  };
  this.selector = selector;
  this.selectorAsString = selectorAsString;
  function selector(name) {
    return api.sel_registerName(Memory.allocUtf8String(name));
  }
  function selectorAsString(sel2) {
    return api.sel_getName(sel2).readCString();
  }
  const registryBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ClassRegistry() {
    const cachedClasses = /* @__PURE__ */ new Map();
    let numCachedClasses = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf2;
          default:
            const klass = findClass(property);
            return klass !== null ? klass : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        let numClasses = api.objc_getClassList(NULL, 0);
        if (numClasses !== numCachedClasses) {
          const bufferSize = numClasses;
          const classHandles = Memory.alloc(bufferSize * pointerSize);
          numClasses = api.objc_getClassList(classHandles, bufferSize);
          if (numClasses > bufferSize)
            numClasses = bufferSize;
          for (let i = 0; i !== numClasses; i++) {
            const handle2 = classHandles.add(i * pointerSize).readPointer();
            const name = api.class_getName(handle2).readCString();
            cachedClasses.set(name, handle2);
          }
          numCachedClasses = numClasses;
        }
        return Array.from(cachedClasses.keys());
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findClass(name) !== null;
    }
    function getClass(name) {
      const cls = findClass(name);
      if (cls === null)
        throw new Error("Unable to find class '" + name + "'");
      return cls;
    }
    function findClass(name) {
      let handle2 = cachedClasses.get(name);
      if (handle2 === void 0) {
        handle2 = api.objc_lookUpClass(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedClasses.set(name, handle2);
        numCachedClasses++;
      }
      return new ObjCObject(handle2, void 0, true);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = getClass(name).toJSON();
        return r;
      }, {});
    }
    function toString() {
      return "ClassRegistry";
    }
    function valueOf2() {
      return "ClassRegistry";
    }
    return registry;
  }
  function ProtocolRegistry() {
    const cachedProtocols = /* @__PURE__ */ new Map();
    let numCachedProtocols = 0;
    const registry = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf2;
          default:
            const proto = findProtocol(property);
            return proto !== null ? proto : void 0;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (api === null)
          return [];
        const numProtocolsBuf = Memory.alloc(pointerSize);
        const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
        try {
          const numProtocols = numProtocolsBuf.readUInt();
          if (numProtocols !== numCachedProtocols) {
            cachedProtocols.clear();
            for (let i = 0; i !== numProtocols; i++) {
              const handle2 = protocolHandles.add(i * pointerSize).readPointer();
              const name = api.protocol_getName(handle2).readCString();
              cachedProtocols.set(name, handle2);
            }
            numCachedProtocols = numProtocols;
          }
        } finally {
          api.free(protocolHandles);
        }
        return Array.from(cachedProtocols.keys());
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    function hasProperty(name) {
      if (registryBuiltins.has(name))
        return true;
      return findProtocol(name) !== null;
    }
    function findProtocol(name) {
      let handle2 = cachedProtocols.get(name);
      if (handle2 === void 0) {
        handle2 = api.objc_getProtocol(Memory.allocUtf8String(name));
        if (handle2.isNull())
          return null;
        cachedProtocols.set(name, handle2);
        numCachedProtocols++;
      }
      return new ObjCProtocol(handle2);
    }
    function toJSON() {
      return Object.keys(registry).reduce(function(r, name) {
        r[name] = { handle: cachedProtocols.get(name) };
        return r;
      }, {});
    }
    function toString() {
      return "ProtocolRegistry";
    }
    function valueOf2() {
      return "ProtocolRegistry";
    }
    return registry;
  }
  const objCObjectBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "handle",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf",
    "equals",
    "$kind",
    "$super",
    "$superClass",
    "$class",
    "$className",
    "$moduleName",
    "$protocols",
    "$methods",
    "$ownMethods",
    "$ivars"
  ]);
  function ObjCObject(handle2, protocol, cachedIsClass, superSpecifier2) {
    let cachedClassHandle = null;
    let cachedKind = null;
    let cachedSuper = null;
    let cachedSuperClass = null;
    let cachedClass = null;
    let cachedClassName = null;
    let cachedModuleName = null;
    let cachedProtocols = null;
    let cachedMethodNames = null;
    let cachedProtocolMethods = null;
    let respondsToSelector = null;
    const cachedMethods = /* @__PURE__ */ new Map();
    let cachedNativeMethodNames = null;
    let cachedOwnMethodNames = null;
    let cachedIvars = null;
    handle2 = getHandle(handle2);
    if (cachedIsClass === void 0) {
      const klass = api.object_getClass(handle2);
      const key = klass.toString();
      if (!realizedClasses.has(key)) {
        api.objc_lookUpClass(api.class_getName(klass));
        realizedClasses.add(key);
      }
    }
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "handle":
            return handle2;
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
          case "valueOf":
            const descriptionImpl = receiver.description;
            if (descriptionImpl !== void 0) {
              const description = descriptionImpl.call(receiver);
              if (description !== null)
                return description.UTF8String.bind(description);
            }
            return function() {
              return receiver.$className;
            };
          case "equals":
            return equals;
          case "$kind":
            if (cachedKind === null) {
              if (isClass())
                cachedKind = api.class_isMetaClass(handle2) ? "meta-class" : "class";
              else
                cachedKind = "instance";
            }
            return cachedKind;
          case "$super":
            if (cachedSuper === null) {
              const superHandle = api.class_getSuperclass(classHandle());
              if (!superHandle.isNull()) {
                const specifier = Memory.alloc(2 * pointerSize);
                specifier.writePointer(handle2);
                specifier.add(pointerSize).writePointer(superHandle);
                cachedSuper = [new ObjCObject(handle2, void 0, cachedIsClass, specifier)];
              } else {
                cachedSuper = [null];
              }
            }
            return cachedSuper[0];
          case "$superClass":
            if (cachedSuperClass === null) {
              const superClassHandle = api.class_getSuperclass(classHandle());
              if (!superClassHandle.isNull()) {
                cachedSuperClass = [new ObjCObject(superClassHandle)];
              } else {
                cachedSuperClass = [null];
              }
            }
            return cachedSuperClass[0];
          case "$class":
            if (cachedClass === null)
              cachedClass = new ObjCObject(api.object_getClass(handle2), void 0, true);
            return cachedClass;
          case "$className":
            if (cachedClassName === null) {
              if (superSpecifier2)
                cachedClassName = api.class_getName(superSpecifier2.add(pointerSize).readPointer()).readCString();
              else if (isClass())
                cachedClassName = api.class_getName(handle2).readCString();
              else
                cachedClassName = api.object_getClassName(handle2).readCString();
            }
            return cachedClassName;
          case "$moduleName":
            if (cachedModuleName === null) {
              cachedModuleName = api.class_getImageName(classHandle()).readCString();
            }
            return cachedModuleName;
          case "$protocols":
            if (cachedProtocols === null) {
              cachedProtocols = {};
              const numProtocolsBuf = Memory.alloc(pointerSize);
              const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
              if (!protocolHandles.isNull()) {
                try {
                  const numProtocols = numProtocolsBuf.readUInt();
                  for (let i = 0; i !== numProtocols; i++) {
                    const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                    const p = new ObjCProtocol(protocolHandle);
                    cachedProtocols[p.name] = p;
                  }
                } finally {
                  api.free(protocolHandles);
                }
              }
            }
            return cachedProtocols;
          case "$methods":
            if (cachedNativeMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const names = /* @__PURE__ */ new Set();
              let cur = meta;
              do {
                for (let methodName of collectMethodNames(cur, "+ "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cur = klass;
              do {
                for (let methodName of collectMethodNames(cur, "- "))
                  names.add(methodName);
                cur = api.class_getSuperclass(cur);
              } while (!cur.isNull());
              cachedNativeMethodNames = Array.from(names);
            }
            return cachedNativeMethodNames;
          case "$ownMethods":
            if (cachedOwnMethodNames === null) {
              const klass = superSpecifier2 ? superSpecifier2.add(pointerSize).readPointer() : classHandle();
              const meta = api.object_getClass(klass);
              const classMethods = collectMethodNames(meta, "+ ");
              const instanceMethods = collectMethodNames(klass, "- ");
              cachedOwnMethodNames = classMethods.concat(instanceMethods);
            }
            return cachedOwnMethodNames;
          case "$ivars":
            if (cachedIvars === null) {
              if (isClass())
                cachedIvars = {};
              else
                cachedIvars = new ObjCIvars(self, classHandle());
            }
            return cachedIvars;
          default:
            if (typeof property === "symbol") {
              return target[property];
            }
            if (protocol) {
              const details = findProtocolMethod(property);
              if (details === null || !details.implemented)
                return void 0;
            }
            const wrapper = findMethodWrapper(property);
            if (wrapper === null)
              return void 0;
            return wrapper;
        }
      },
      set(target, property, value, receiver) {
        return false;
      },
      ownKeys(target) {
        if (cachedMethodNames === null) {
          if (!protocol) {
            const jsNames = {};
            const nativeNames = {};
            let cur = api.object_getClass(handle2);
            do {
              const numMethodsBuf = Memory.alloc(pointerSize);
              const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
              const fullNamePrefix = isClass() ? "+ " : "- ";
              try {
                const numMethods = numMethodsBuf.readUInt();
                for (let i = 0; i !== numMethods; i++) {
                  const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                  const sel2 = api.method_getName(methodHandle);
                  const nativeName = api.sel_getName(sel2).readCString();
                  if (nativeNames[nativeName] !== void 0)
                    continue;
                  nativeNames[nativeName] = nativeName;
                  const jsName = jsMethodName(nativeName);
                  let serial2 = 2;
                  let name = jsName;
                  while (jsNames[name] !== void 0) {
                    serial2++;
                    name = jsName + serial2;
                  }
                  jsNames[name] = true;
                  const fullName = fullNamePrefix + nativeName;
                  if (!cachedMethods.has(fullName)) {
                    const details = {
                      sel: sel2,
                      handle: methodHandle,
                      wrapper: null
                    };
                    cachedMethods.set(fullName, details);
                    cachedMethods.set(name, details);
                  }
                }
              } finally {
                api.free(methodHandles);
              }
              cur = api.class_getSuperclass(cur);
            } while (!cur.isNull());
            cachedMethodNames = Object.keys(jsNames);
          } else {
            const methodNames = [];
            const protocolMethods = allProtocolMethods();
            Object.keys(protocolMethods).forEach(function(methodName) {
              if (methodName[0] !== "+" && methodName[0] !== "-") {
                const details = protocolMethods[methodName];
                if (details.implemented) {
                  methodNames.push(methodName);
                }
              }
            });
            cachedMethodNames = methodNames;
          }
        }
        return ["handle"].concat(cachedMethodNames);
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: false,
          configurable: true,
          enumerable: true
        };
      }
    });
    if (protocol) {
      respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
    }
    return self;
    function hasProperty(name) {
      if (objCObjectBuiltins.has(name))
        return true;
      if (protocol) {
        const details = findProtocolMethod(name);
        return !!(details !== null && details.implemented);
      }
      return findMethod(name) !== null;
    }
    function classHandle() {
      if (cachedClassHandle === null)
        cachedClassHandle = isClass() ? handle2 : api.object_getClass(handle2);
      return cachedClassHandle;
    }
    function isClass() {
      if (cachedIsClass === void 0) {
        if (api.object_isClass)
          cachedIsClass = !!api.object_isClass(handle2);
        else
          cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle2));
      }
      return cachedIsClass;
    }
    function findMethod(rawName) {
      let method2 = cachedMethods.get(rawName);
      if (method2 !== void 0)
        return method2;
      const tokens = parseMethodName(rawName);
      const fullName = tokens[2];
      method2 = cachedMethods.get(fullName);
      if (method2 !== void 0) {
        cachedMethods.set(rawName, method2);
        return method2;
      }
      const kind2 = tokens[0];
      const name = tokens[1];
      const sel2 = selector(name);
      const defaultKind = isClass() ? "+" : "-";
      if (protocol) {
        const details = findProtocolMethod(fullName);
        if (details !== null) {
          method2 = {
            sel: sel2,
            types: details.types,
            wrapper: null,
            kind: kind2
          };
        }
      }
      if (method2 === void 0) {
        const methodHandle = kind2 === "+" ? api.class_getClassMethod(classHandle(), sel2) : api.class_getInstanceMethod(classHandle(), sel2);
        if (!methodHandle.isNull()) {
          method2 = {
            sel: sel2,
            handle: methodHandle,
            wrapper: null,
            kind: kind2
          };
        } else {
          if (isClass() || kind2 !== "-" || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
            return null;
          }
          let target = self;
          if ("- forwardingTargetForSelector:" in self) {
            const forwardingTarget = self.forwardingTargetForSelector_(sel2);
            if (forwardingTarget !== null && forwardingTarget.$kind === "instance") {
              target = forwardingTarget;
            } else {
              return null;
            }
          } else {
            return null;
          }
          const methodHandle2 = api.class_getInstanceMethod(api.object_getClass(target.handle), sel2);
          if (methodHandle2.isNull()) {
            return null;
          }
          let types2 = api.method_getTypeEncoding(methodHandle2).readCString();
          if (types2 === null || types2 === "") {
            types2 = stealTypesFromProtocols(target, fullName);
            if (types2 === null)
              types2 = stealTypesFromProtocols(self, fullName);
            if (types2 === null)
              return null;
          }
          method2 = {
            sel: sel2,
            types: types2,
            wrapper: null,
            kind: kind2
          };
        }
      }
      cachedMethods.set(fullName, method2);
      cachedMethods.set(rawName, method2);
      if (kind2 === defaultKind)
        cachedMethods.set(jsMethodName(name), method2);
      return method2;
    }
    function stealTypesFromProtocols(klass, fullName) {
      const candidates = Object.keys(klass.$protocols).map((protocolName) => flatProtocolMethods({}, klass.$protocols[protocolName])).reduce((allMethods, methods3) => {
        Object.assign(allMethods, methods3);
        return allMethods;
      }, {});
      const method2 = candidates[fullName];
      if (method2 === void 0) {
        return null;
      }
      return method2.types;
    }
    function flatProtocolMethods(result, protocol2) {
      if (protocol2.methods !== void 0) {
        Object.assign(result, protocol2.methods);
      }
      if (protocol2.protocol !== void 0) {
        flatProtocolMethods(result, protocol2.protocol);
      }
      return result;
    }
    function findProtocolMethod(rawName) {
      const protocolMethods = allProtocolMethods();
      const details = protocolMethods[rawName];
      return details !== void 0 ? details : null;
    }
    function allProtocolMethods() {
      if (cachedProtocolMethods === null) {
        const methods3 = {};
        const protocols = collectProtocols(protocol);
        const defaultKind = isClass() ? "+" : "-";
        Object.keys(protocols).forEach(function(name) {
          const p = protocols[name];
          const m2 = p.methods;
          Object.keys(m2).forEach(function(fullMethodName) {
            const method2 = m2[fullMethodName];
            const methodName = fullMethodName.substr(2);
            const kind2 = fullMethodName[0];
            let didCheckImplemented = false;
            let implemented = false;
            const details = {
              types: method2.types
            };
            Object.defineProperty(details, "implemented", {
              get() {
                if (!didCheckImplemented) {
                  if (method2.required) {
                    implemented = true;
                  } else {
                    implemented = respondsToSelector !== null && respondsToSelector.call(self, selector(methodName));
                  }
                  didCheckImplemented = true;
                }
                return implemented;
              }
            });
            methods3[fullMethodName] = details;
            if (kind2 === defaultKind)
              methods3[jsMethodName(methodName)] = details;
          });
        });
        cachedProtocolMethods = methods3;
      }
      return cachedProtocolMethods;
    }
    function findMethodWrapper(name) {
      const method2 = findMethod(name);
      if (method2 === null)
        return null;
      let wrapper = method2.wrapper;
      if (wrapper === null) {
        wrapper = makeMethodInvocationWrapper(method2, self, superSpecifier2, defaultInvocationOptions);
        method2.wrapper = wrapper;
      }
      return wrapper;
    }
    function parseMethodName(rawName) {
      const match = /([+\-])\s(\S+)/.exec(rawName);
      let name, kind2;
      if (match === null) {
        kind2 = isClass() ? "+" : "-";
        name = objcMethodName(rawName);
      } else {
        kind2 = match[1];
        name = match[2];
      }
      const fullName = [kind2, name].join(" ");
      return [kind2, name, fullName];
    }
    function toJSON() {
      return {
        handle: handle2.toString()
      };
    }
    function equals(ptr2) {
      return handle2.equals(getHandle(ptr2));
    }
  }
  function getReplacementMethodImplementation(methodHandle) {
    const existingEntry = replacedMethods.get(methodHandle.toString());
    if (existingEntry === void 0)
      return null;
    const [, newImp] = existingEntry;
    return newImp;
  }
  function replaceMethodImplementation(methodHandle, imp) {
    const key = methodHandle.toString();
    let oldImp;
    const existingEntry = replacedMethods.get(key);
    if (existingEntry !== void 0)
      [oldImp] = existingEntry;
    else
      oldImp = api.method_getImplementation(methodHandle);
    if (!imp.equals(oldImp))
      replacedMethods.set(key, [oldImp, imp]);
    else
      replacedMethods.delete(key);
    api.method_setImplementation(methodHandle, imp);
  }
  function collectMethodNames(klass, prefix) {
    const names = [];
    const numMethodsBuf = Memory.alloc(pointerSize);
    const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
    try {
      const numMethods = numMethodsBuf.readUInt();
      for (let i = 0; i !== numMethods; i++) {
        const methodHandle = methodHandles.add(i * pointerSize).readPointer();
        const sel2 = api.method_getName(methodHandle);
        const nativeName = api.sel_getName(sel2).readCString();
        names.push(prefix + nativeName);
      }
    } finally {
      api.free(methodHandles);
    }
    return names;
  }
  function ObjCProtocol(handle2) {
    let cachedName = null;
    let cachedProtocols = null;
    let cachedProperties = null;
    let cachedMethods = null;
    Object.defineProperty(this, "handle", {
      value: handle2,
      enumerable: true
    });
    Object.defineProperty(this, "name", {
      get() {
        if (cachedName === null)
          cachedName = api.protocol_getName(handle2).readCString();
        return cachedName;
      },
      enumerable: true
    });
    Object.defineProperty(this, "protocols", {
      get() {
        if (cachedProtocols === null) {
          cachedProtocols = {};
          const numProtocolsBuf = Memory.alloc(pointerSize);
          const protocolHandles = api.protocol_copyProtocolList(handle2, numProtocolsBuf);
          if (!protocolHandles.isNull()) {
            try {
              const numProtocols = numProtocolsBuf.readUInt();
              for (let i = 0; i !== numProtocols; i++) {
                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                const protocol = new ObjCProtocol(protocolHandle);
                cachedProtocols[protocol.name] = protocol;
              }
            } finally {
              api.free(protocolHandles);
            }
          }
        }
        return cachedProtocols;
      },
      enumerable: true
    });
    Object.defineProperty(this, "properties", {
      get() {
        if (cachedProperties === null) {
          cachedProperties = {};
          const numBuf = Memory.alloc(pointerSize);
          const propertyHandles = api.protocol_copyPropertyList(handle2, numBuf);
          if (!propertyHandles.isNull()) {
            try {
              const numProperties = numBuf.readUInt();
              for (let i = 0; i !== numProperties; i++) {
                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                const propName = api.property_getName(propertyHandle).readCString();
                const attributes = {};
                const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                if (!attributeEntries.isNull()) {
                  try {
                    const numAttributeValues = numBuf.readUInt();
                    for (let j = 0; j !== numAttributeValues; j++) {
                      const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                      const name = attributeEntry.readPointer().readCString();
                      const value = attributeEntry.add(pointerSize).readPointer().readCString();
                      attributes[name] = value;
                    }
                  } finally {
                    api.free(attributeEntries);
                  }
                }
                cachedProperties[propName] = attributes;
              }
            } finally {
              api.free(propertyHandles);
            }
          }
        }
        return cachedProperties;
      },
      enumerable: true
    });
    Object.defineProperty(this, "methods", {
      get() {
        if (cachedMethods === null) {
          cachedMethods = {};
          const numBuf = Memory.alloc(pointerSize);
          collectMethods(cachedMethods, numBuf, { required: true, instance: false });
          collectMethods(cachedMethods, numBuf, { required: false, instance: false });
          collectMethods(cachedMethods, numBuf, { required: true, instance: true });
          collectMethods(cachedMethods, numBuf, { required: false, instance: true });
        }
        return cachedMethods;
      },
      enumerable: true
    });
    function collectMethods(methods3, numBuf, spec) {
      const methodDescValues = api.protocol_copyMethodDescriptionList(handle2, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
      if (methodDescValues.isNull())
        return;
      try {
        const numMethodDescValues = numBuf.readUInt();
        for (let i = 0; i !== numMethodDescValues; i++) {
          const methodDesc = methodDescValues.add(i * (2 * pointerSize));
          const name = (spec.instance ? "- " : "+ ") + selectorAsString(methodDesc.readPointer());
          const types2 = methodDesc.add(pointerSize).readPointer().readCString();
          methods3[name] = {
            required: spec.required,
            types: types2
          };
        }
      } finally {
        api.free(methodDescValues);
      }
    }
  }
  const objCIvarsBuiltins = /* @__PURE__ */ new Set([
    "prototype",
    "constructor",
    "hasOwnProperty",
    "toJSON",
    "toString",
    "valueOf"
  ]);
  function ObjCIvars(instance, classHandle) {
    const ivars2 = {};
    let cachedIvarNames = null;
    let classHandles = [];
    let currentClassHandle = classHandle;
    do {
      classHandles.unshift(currentClassHandle);
      currentClassHandle = api.class_getSuperclass(currentClassHandle);
    } while (!currentClassHandle.isNull());
    const numIvarsBuf = Memory.alloc(pointerSize);
    classHandles.forEach((c) => {
      const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
      try {
        const numIvars = numIvarsBuf.readUInt();
        for (let i = 0; i !== numIvars; i++) {
          const handle2 = ivarHandles.add(i * pointerSize).readPointer();
          const name = api.ivar_getName(handle2).readCString();
          ivars2[name] = [handle2, null];
        }
      } finally {
        api.free(ivarHandles);
      }
    });
    const self = new Proxy(this, {
      has(target, property) {
        return hasProperty(property);
      },
      get(target, property, receiver) {
        switch (property) {
          case "prototype":
            return target.prototype;
          case "constructor":
            return target.constructor;
          case "hasOwnProperty":
            return hasProperty;
          case "toJSON":
            return toJSON;
          case "toString":
            return toString;
          case "valueOf":
            return valueOf2;
          default:
            const ivar = findIvar(property);
            if (ivar === null)
              return void 0;
            return ivar.get();
        }
      },
      set(target, property, value, receiver) {
        const ivar = findIvar(property);
        if (ivar === null)
          throw new Error("Unknown ivar");
        ivar.set(value);
        return true;
      },
      ownKeys(target) {
        if (cachedIvarNames === null)
          cachedIvarNames = Object.keys(ivars2);
        return cachedIvarNames;
      },
      getOwnPropertyDescriptor(target, property) {
        return {
          writable: true,
          configurable: true,
          enumerable: true
        };
      }
    });
    return self;
    function findIvar(name) {
      const entry = ivars2[name];
      if (entry === void 0)
        return null;
      let impl = entry[1];
      if (impl === null) {
        const ivar = entry[0];
        const offset = api.ivar_getOffset(ivar).toInt32();
        const address = instance.handle.add(offset);
        const type = parseType(api.ivar_getTypeEncoding(ivar).readCString());
        const fromNative = type.fromNative || identityTransform;
        const toNative = type.toNative || identityTransform;
        let read, write;
        if (name === "isa") {
          read = readObjectIsa;
          write = function() {
            throw new Error("Unable to set the isa instance variable");
          };
        } else {
          read = type.read;
          write = type.write;
        }
        impl = {
          get() {
            return fromNative.call(instance, read(address));
          },
          set(value) {
            write(address, toNative.call(instance, value));
          }
        };
        entry[1] = impl;
      }
      return impl;
    }
    function hasProperty(name) {
      if (objCIvarsBuiltins.has(name))
        return true;
      return ivars2.hasOwnProperty(name);
    }
    function toJSON() {
      return Object.keys(self).reduce(function(result, name) {
        result[name] = self[name];
        return result;
      }, {});
    }
    function toString() {
      return "ObjCIvars";
    }
    function valueOf2() {
      return "ObjCIvars";
    }
  }
  let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
  let blockSize, blockOffsets;
  if (pointerSize === 4) {
    blockDescriptorAllocSize = 16;
    blockDescriptorDeclaredSize = 20;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 4,
      rest: 8
    };
    blockSize = 20;
    blockOffsets = {
      isa: 0,
      flags: 4,
      reserved: 8,
      invoke: 12,
      descriptor: 16
    };
  } else {
    blockDescriptorAllocSize = 32;
    blockDescriptorDeclaredSize = 32;
    blockDescriptorOffsets = {
      reserved: 0,
      size: 8,
      rest: 16
    };
    blockSize = 32;
    blockOffsets = {
      isa: 0,
      flags: 8,
      reserved: 12,
      invoke: 16,
      descriptor: 24
    };
  }
  const BLOCK_HAS_COPY_DISPOSE = 1 << 25;
  const BLOCK_HAS_CTOR = 1 << 26;
  const BLOCK_IS_GLOBAL = 1 << 28;
  const BLOCK_HAS_STRET = 1 << 29;
  const BLOCK_HAS_SIGNATURE = 1 << 30;
  function Block(target, options = defaultInvocationOptions) {
    this._options = options;
    if (target instanceof NativePointer) {
      const descriptor = target.add(blockOffsets.descriptor).readPointer();
      this.handle = target;
      const flags = target.add(blockOffsets.flags).readU32();
      if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
        const signatureOffset = (flags & BLOCK_HAS_COPY_DISPOSE) !== 0 ? 2 : 0;
        this.types = descriptor.add(blockDescriptorOffsets.rest + signatureOffset * pointerSize).readPointer().readCString();
        this._signature = parseSignature(this.types);
      } else {
        this._signature = null;
      }
    } else {
      this.declare(target);
      const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
      const block2 = descriptor.add(blockDescriptorAllocSize);
      const typesStr = Memory.allocUtf8String(this.types);
      descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
      descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
      descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);
      block2.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
      block2.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
      block2.add(blockOffsets.reserved).writeU32(0);
      block2.add(blockOffsets.descriptor).writePointer(descriptor);
      this.handle = block2;
      this._storage = [descriptor, typesStr];
      this.implementation = target.implementation;
    }
  }
  Object.defineProperties(Block.prototype, {
    implementation: {
      enumerable: true,
      get() {
        const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
        const signature2 = this._getSignature();
        return makeBlockInvocationWrapper(this, signature2, new NativeFunction(
          address.sign(),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          }),
          this._options
        ));
      },
      set(func) {
        const signature2 = this._getSignature();
        const callback = new NativeCallback(
          makeBlockImplementationWrapper(this, signature2, func),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        this._callback = callback;
        const location = this.handle.add(blockOffsets.invoke);
        const prot = Memory.queryProtection(location);
        const writable = prot.includes("w");
        if (!writable)
          Memory.protect(location, Process.pointerSize, "rw-");
        location.writePointer(callback.strip().sign("ia", location));
        if (!writable)
          Memory.protect(location, Process.pointerSize, prot);
      }
    },
    declare: {
      value(signature2) {
        let types2 = signature2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(signature2.retType, ["block"].concat(signature2.argTypes));
        }
        this.types = types2;
        this._signature = parseSignature(types2);
      }
    },
    _getSignature: {
      value() {
        const signature2 = this._signature;
        if (signature2 === null)
          throw new Error("block is missing signature; call declare()");
        return signature2;
      }
    }
  });
  function collectProtocols(p, acc) {
    acc = acc || {};
    acc[p.name] = p;
    const parentProtocols = p.protocols;
    Object.keys(parentProtocols).forEach(function(name) {
      collectProtocols(parentProtocols[name], acc);
    });
    return acc;
  }
  function registerProxy(properties2) {
    const protocols = properties2.protocols || [];
    const methods3 = properties2.methods || {};
    const events = properties2.events || {};
    const supportedSelectors = new Set(
      Object.keys(methods3).filter((m2) => /([+\-])\s(\S+)/.exec(m2) !== null).map((m2) => m2.split(" ")[1])
    );
    const proxyMethods = {
      "- dealloc": function() {
        const target = this.data.target;
        if ("- release" in target)
          target.release();
        unbind(this.self);
        this.super.dealloc();
        const callback = this.data.events.dealloc;
        if (callback !== void 0)
          callback.call(this);
      },
      "- respondsToSelector:": function(sel2) {
        const selector2 = selectorAsString(sel2);
        if (supportedSelectors.has(selector2))
          return true;
        return this.data.target.respondsToSelector_(sel2);
      },
      "- forwardingTargetForSelector:": function(sel2) {
        const callback = this.data.events.forward;
        if (callback !== void 0)
          callback.call(this, selectorAsString(sel2));
        return this.data.target;
      },
      "- methodSignatureForSelector:": function(sel2) {
        return this.data.target.methodSignatureForSelector_(sel2);
      },
      "- forwardInvocation:": function(invocation) {
        invocation.invokeWithTarget_(this.data.target);
      }
    };
    for (var key in methods3) {
      if (methods3.hasOwnProperty(key)) {
        if (proxyMethods.hasOwnProperty(key))
          throw new Error("The '" + key + "' method is reserved");
        proxyMethods[key] = methods3[key];
      }
    }
    const ProxyClass = registerClass({
      name: properties2.name,
      super: classRegistry.NSProxy,
      protocols,
      methods: proxyMethods
    });
    return function(target, data) {
      target = target instanceof NativePointer ? new ObjCObject(target) : target;
      data = data || {};
      const instance = ProxyClass.alloc().autorelease();
      const boundData = getBoundData(instance);
      boundData.target = "- retain" in target ? target.retain() : target;
      boundData.events = events;
      for (var key2 in data) {
        if (data.hasOwnProperty(key2)) {
          if (boundData.hasOwnProperty(key2))
            throw new Error("The '" + key2 + "' property is reserved");
          boundData[key2] = data[key2];
        }
      }
      this.handle = instance.handle;
    };
  }
  function registerClass(properties2) {
    let name = properties2.name;
    if (name === void 0)
      name = makeClassName();
    const superClass = properties2.super !== void 0 ? properties2.super : classRegistry.NSObject;
    const protocols = properties2.protocols || [];
    const methods3 = properties2.methods || {};
    const methodCallbacks = [];
    const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
    if (classHandle.isNull())
      throw new Error("Unable to register already registered class '" + name + "'");
    const metaClassHandle = api.object_getClass(classHandle);
    try {
      protocols.forEach(function(protocol) {
        api.class_addProtocol(classHandle, protocol.handle);
      });
      Object.keys(methods3).forEach(function(rawMethodName) {
        const match = /([+\-])\s(\S+)/.exec(rawMethodName);
        if (match === null)
          throw new Error("Invalid method name");
        const kind2 = match[1];
        const name2 = match[2];
        let method2;
        const value = methods3[rawMethodName];
        if (typeof value === "function") {
          let types3 = null;
          if (rawMethodName in superClass) {
            types3 = superClass[rawMethodName].types;
          } else {
            for (let protocol of protocols) {
              const method3 = protocol.methods[rawMethodName];
              if (method3 !== void 0) {
                types3 = method3.types;
                break;
              }
            }
          }
          if (types3 === null)
            throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
          method2 = {
            types: types3,
            implementation: value
          };
        } else {
          method2 = value;
        }
        const target = kind2 === "+" ? metaClassHandle : classHandle;
        let types2 = method2.types;
        if (types2 === void 0) {
          types2 = unparseSignature(method2.retType, [kind2 === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
        }
        const signature2 = parseSignature(types2);
        const implementation3 = new NativeCallback(
          makeMethodImplementationWrapper(signature2, method2.implementation),
          signature2.retType.type,
          signature2.argTypes.map(function(arg) {
            return arg.type;
          })
        );
        methodCallbacks.push(implementation3);
        api.class_addMethod(target, selector(name2), implementation3, Memory.allocUtf8String(types2));
      });
    } catch (e) {
      api.objc_disposeClassPair(classHandle);
      throw e;
    }
    api.objc_registerClassPair(classHandle);
    classHandle._methodCallbacks = methodCallbacks;
    Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));
    return new ObjCObject(classHandle);
  }
  function makeClassDestructor(classHandle) {
    return function() {
      api.objc_disposeClassPair(classHandle);
    };
  }
  function registerProtocol(properties2) {
    let name = properties2.name;
    if (name === void 0)
      name = makeProtocolName();
    const protocols = properties2.protocols || [];
    const methods3 = properties2.methods || {};
    protocols.forEach(function(protocol) {
      if (!(protocol instanceof ObjCProtocol))
        throw new Error("Expected protocol");
    });
    const methodSpecs = Object.keys(methods3).map(function(rawMethodName) {
      const method2 = methods3[rawMethodName];
      const match = /([+\-])\s(\S+)/.exec(rawMethodName);
      if (match === null)
        throw new Error("Invalid method name");
      const kind2 = match[1];
      const name2 = match[2];
      let types2 = method2.types;
      if (types2 === void 0) {
        types2 = unparseSignature(method2.retType, [kind2 === "+" ? "class" : "object", "selector"].concat(method2.argTypes));
      }
      return {
        kind: kind2,
        name: name2,
        types: types2,
        optional: method2.optional
      };
    });
    const handle2 = api.objc_allocateProtocol(Memory.allocUtf8String(name));
    if (handle2.isNull())
      throw new Error("Unable to register already registered protocol '" + name + "'");
    protocols.forEach(function(protocol) {
      api.protocol_addProtocol(handle2, protocol.handle);
    });
    methodSpecs.forEach(function(spec) {
      const isRequiredMethod = spec.optional ? 0 : 1;
      const isInstanceMethod = spec.kind === "-" ? 1 : 0;
      api.protocol_addMethodDescription(handle2, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
    });
    api.objc_registerProtocol(handle2);
    return new ObjCProtocol(handle2);
  }
  function getHandle(obj) {
    if (obj instanceof NativePointer)
      return obj;
    else if (typeof obj === "object" && obj.hasOwnProperty("handle"))
      return obj.handle;
    else
      throw new Error("Expected NativePointer or ObjC.Object instance");
  }
  function bind(obj, data) {
    const handle2 = getHandle(obj);
    const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
    bindings.set(handle2.toString(), {
      self,
      super: self.$super,
      data
    });
  }
  function unbind(obj) {
    const handle2 = getHandle(obj);
    bindings.delete(handle2.toString());
  }
  function getBoundData(obj) {
    return getBinding(obj).data;
  }
  function getBinding(obj) {
    const handle2 = getHandle(obj);
    const key = handle2.toString();
    let binding = bindings.get(key);
    if (binding === void 0) {
      const self = obj instanceof ObjCObject ? obj : new ObjCObject(handle2);
      binding = {
        self,
        super: self.$super,
        data: {}
      };
      bindings.set(key, binding);
    }
    return binding;
  }
  function enumerateLoadedClasses(...args) {
    const allModules = new ModuleMap();
    let unfiltered = false;
    let callbacks;
    let modules2;
    if (args.length === 1) {
      callbacks = args[0];
    } else {
      callbacks = args[1];
      const options = args[0];
      modules2 = options.ownedBy;
    }
    if (modules2 === void 0) {
      modules2 = allModules;
      unfiltered = true;
    }
    const classGetName = api.class_getName;
    const onMatch = callbacks.onMatch.bind(callbacks);
    const swiftNominalTypeDescriptorOffset = (pointerSize === 8 ? 8 : 11) * pointerSize;
    const numClasses = api.objc_getClassList(NULL, 0);
    const classHandles = Memory.alloc(numClasses * pointerSize);
    api.objc_getClassList(classHandles, numClasses);
    for (let i = 0; i !== numClasses; i++) {
      const classHandle = classHandles.add(i * pointerSize).readPointer();
      const rawName = classGetName(classHandle);
      let name = null;
      let modulePath = modules2.findPath(rawName);
      const possiblySwift = modulePath === null && (unfiltered || allModules.findPath(rawName) === null);
      if (possiblySwift) {
        name = rawName.readCString();
        const probablySwift = name.indexOf(".") !== -1;
        if (probablySwift) {
          const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
          modulePath = modules2.findPath(nominalTypeDescriptor);
        }
      }
      if (modulePath !== null) {
        if (name === null)
          name = rawName.readCString();
        onMatch(name, modulePath);
      }
    }
    callbacks.onComplete();
  }
  function enumerateLoadedClassesSync(options = {}) {
    const result = {};
    enumerateLoadedClasses(options, {
      onMatch(name, owner2) {
        let group = result[owner2];
        if (group === void 0) {
          group = [];
          result[owner2] = group;
        }
        group.push(name);
      },
      onComplete() {
      }
    });
    return result;
  }
  function choose(specifier, callbacks) {
    let cls = specifier;
    let subclasses = true;
    if (!(specifier instanceof ObjCObject) && typeof specifier === "object") {
      cls = specifier.class;
      if (specifier.hasOwnProperty("subclasses"))
        subclasses = specifier.subclasses;
    }
    if (!(cls instanceof ObjCObject && (cls.$kind === "class" || cls.$kind === "meta-class")))
      throw new Error("Expected an ObjC.Object for a class or meta-class");
    const matches = get().choose(cls, subclasses).map((handle2) => new ObjCObject(handle2));
    for (const match of matches) {
      const result = callbacks.onMatch(match);
      if (result === "stop")
        break;
    }
    callbacks.onComplete();
  }
  function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
    const sel = method.sel;
    let handle = method.handle;
    let types;
    if (handle === void 0) {
      handle = null;
      types = method.types;
    } else {
      types = api.method_getTypeEncoding(handle).readCString();
    }
    const signature = parseSignature(types);
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(2);
    const objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature, invocationOptions) : getMsgSendImpl(signature, invocationOptions);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = [
      superSpecifier ? "superSpecifier" : "this",
      "sel"
    ].concat(argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    }));
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    Object.defineProperty(m, "handle", {
      enumerable: true,
      get: getMethodHandle
    });
    m.selector = sel;
    Object.defineProperty(m, "implementation", {
      enumerable: true,
      get() {
        const h = getMethodHandle();
        const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);
        const newImp = getReplacementMethodImplementation(h);
        if (newImp !== null)
          impl._callback = newImp;
        return impl;
      },
      set(imp) {
        replaceMethodImplementation(getMethodHandle(), imp);
      }
    });
    m.returnType = retType.type;
    m.argumentTypes = signature.argTypes.map((t) => t.type);
    m.types = types;
    Object.defineProperty(m, "symbol", {
      enumerable: true,
      get() {
        return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
      }
    });
    m.clone = function(options) {
      return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
    };
    function getMethodHandle() {
      if (handle === null) {
        if (owner.$kind === "instance") {
          let cur = owner;
          do {
            if ("- forwardingTargetForSelector:" in cur) {
              const target = cur.forwardingTargetForSelector_(sel);
              if (target === null)
                break;
              if (target.$kind !== "instance")
                break;
              const h = api.class_getInstanceMethod(target.$class.handle, sel);
              if (!h.isNull())
                handle = h;
              else
                cur = target;
            } else {
              break;
            }
          } while (handle === null);
        }
        if (handle === null)
          throw new Error("Unable to find method handle of proxied function");
      }
      return handle;
    }
    return m;
  }
  function makeMethodImplementationWrapper(signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else if (i === 1)
        return "sel";
      else
        return "a" + (i - 1);
    });
    const callArgs = argTypes.slice(2).map(function(t, i) {
      const argVariableName = argVariableNames[2 + i];
      if (t.fromNative) {
        return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(self, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { var binding = getBinding(handle);var self = binding.self;" + returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    return m;
  }
  function makeBlockInvocationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes.slice(1);
    const argVariableNames = argTypes.map(function(t, i) {
      return "a" + (i + 1);
    });
    const callArgs = argTypes.map(function(t, i) {
      if (t.toNative) {
        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
      }
      return argVariableNames[i];
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.fromNative) {
      returnCaptureLeft = "return retType.fromNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function makeBlockImplementationWrapper(block, signature, implementation) {
    const retType = signature.retType;
    const argTypes = signature.argTypes;
    const argVariableNames = argTypes.map(function(t, i) {
      if (i === 0)
        return "handle";
      else
        return "a" + i;
    });
    const callArgs = argTypes.slice(1).map(function(t, i) {
      const argVariableName = argVariableNames[1 + i];
      if (t.fromNative) {
        return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
      }
      return argVariableName;
    });
    let returnCaptureLeft;
    let returnCaptureRight;
    if (retType.type === "void") {
      returnCaptureLeft = "";
      returnCaptureRight = "";
    } else if (retType.toNative) {
      returnCaptureLeft = "return retType.toNative.call(this, ";
      returnCaptureRight = ")";
    } else {
      returnCaptureLeft = "return ";
      returnCaptureRight = "";
    }
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { if (!this.handle.equals(handle))this.handle = handle;" + returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function rawFridaType(t) {
    return t === "object" ? "pointer" : t;
  }
  function makeClassName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousClass" + i;
      if (!(name in classRegistry)) {
        return name;
      }
    }
  }
  function makeProtocolName() {
    for (let i = 1; true; i++) {
      const name = "FridaAnonymousProtocol" + i;
      if (!(name in protocolRegistry)) {
        return name;
      }
    }
  }
  function objcMethodName(name) {
    return name.replace(/_/g, ":");
  }
  function jsMethodName(name) {
    let result = name.replace(/:/g, "_");
    if (objCObjectBuiltins.has(result))
      result += "2";
    return result;
  }
  const isaMasks = {
    x64: "0x7ffffffffff8",
    arm64: "0xffffffff8"
  };
  const rawMask = isaMasks[Process.arch];
  if (rawMask !== void 0) {
    const mask = ptr(rawMask);
    readObjectIsa = function(p) {
      return p.readPointer().and(mask);
    };
  } else {
    readObjectIsa = function(p) {
      return p.readPointer();
    };
  }
  function getMsgSendImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendBySignatureId, signature2, invocationOptions2, false);
  }
  function getMsgSendSuperImpl(signature2, invocationOptions2) {
    return resolveMsgSendImpl(msgSendSuperBySignatureId, signature2, invocationOptions2, true);
  }
  function resolveMsgSendImpl(cache, signature2, invocationOptions2, isSuper) {
    if (invocationOptions2 !== defaultInvocationOptions)
      return makeMsgSendImpl(signature2, invocationOptions2, isSuper);
    const { id } = signature2;
    let impl = cache.get(id);
    if (impl === void 0) {
      impl = makeMsgSendImpl(signature2, invocationOptions2, isSuper);
      cache.set(id, impl);
    }
    return impl;
  }
  function makeMsgSendImpl(signature2, invocationOptions2, isSuper) {
    const retType2 = signature2.retType.type;
    const argTypes2 = signature2.argTypes.map(function(t) {
      return t.type;
    });
    const components = ["objc_msgSend"];
    if (isSuper)
      components.push("Super");
    const returnsStruct = retType2 instanceof Array;
    if (returnsStruct && !typeFitsInRegisters(retType2))
      components.push("_stret");
    else if (retType2 === "float" || retType2 === "double")
      components.push("_fpret");
    const name = components.join("");
    return new NativeFunction(api[name], retType2, argTypes2, invocationOptions2);
  }
  function typeFitsInRegisters(type) {
    if (Process.arch !== "x64")
      return false;
    const size = sizeOfTypeOnX64(type);
    return size <= 16;
  }
  function sizeOfTypeOnX64(type) {
    if (type instanceof Array)
      return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);
    switch (type) {
      case "bool":
      case "char":
      case "uchar":
        return 1;
      case "int16":
      case "uint16":
        return 2;
      case "int":
      case "int32":
      case "uint":
      case "uint32":
      case "float":
        return 4;
      default:
        return 8;
    }
  }
  function unparseSignature(retType2, argTypes2) {
    const retTypeId = typeIdFromAlias(retType2);
    const argTypeIds = argTypes2.map(typeIdFromAlias);
    const argSizes = argTypeIds.map((id) => singularTypeById[id].size);
    const frameSize = argSizes.reduce((total, size) => total + size, 0);
    let frameOffset = 0;
    return retTypeId + frameSize + argTypeIds.map((id, i) => {
      const result = id + frameOffset;
      frameOffset += argSizes[i];
      return result;
    }).join("");
  }
  function parseSignature(sig) {
    const cursor = [sig, 0];
    parseQualifiers(cursor);
    const retType2 = readType(cursor);
    readNumber(cursor);
    const argTypes2 = [];
    let id = JSON.stringify(retType2.type);
    while (dataAvailable(cursor)) {
      parseQualifiers(cursor);
      const argType = readType(cursor);
      readNumber(cursor);
      argTypes2.push(argType);
      id += JSON.stringify(argType.type);
    }
    return {
      id,
      retType: retType2,
      argTypes: argTypes2
    };
  }
  function parseType(type) {
    const cursor = [type, 0];
    return readType(cursor);
  }
  function readType(cursor) {
    let id = readChar(cursor);
    if (id === "@") {
      let next = peekChar(cursor);
      if (next === "?") {
        id += next;
        skipChar(cursor);
        if (peekChar(cursor) === "<")
          skipExtendedBlock(cursor);
      } else if (next === '"') {
        skipChar(cursor);
        readUntil('"', cursor);
      }
    } else if (id === "^") {
      let next = peekChar(cursor);
      if (next === "@") {
        id += next;
        skipChar(cursor);
      }
    }
    const type = singularTypeById[id];
    if (type !== void 0) {
      return type;
    } else if (id === "[") {
      const length = readNumber(cursor);
      const elementType = readType(cursor);
      skipChar(cursor);
      return arrayType(length, elementType);
    } else if (id === "{") {
      if (!tokenExistsAhead("=", "}", cursor)) {
        readUntil("}", cursor);
        return structType([]);
      }
      readUntil("=", cursor);
      const structFields = [];
      let ch;
      while ((ch = peekChar(cursor)) !== "}") {
        if (ch === '"') {
          skipChar(cursor);
          readUntil('"', cursor);
        }
        structFields.push(readType(cursor));
      }
      skipChar(cursor);
      return structType(structFields);
    } else if (id === "(") {
      readUntil("=", cursor);
      const unionFields = [];
      while (peekChar(cursor) !== ")")
        unionFields.push(readType(cursor));
      skipChar(cursor);
      return unionType(unionFields);
    } else if (id === "b") {
      readNumber(cursor);
      return singularTypeById.i;
    } else if (id === "^") {
      readType(cursor);
      return singularTypeById["?"];
    } else if (modifiers.has(id)) {
      return readType(cursor);
    } else {
      throw new Error("Unable to handle type " + id);
    }
  }
  function skipExtendedBlock(cursor) {
    let ch;
    skipChar(cursor);
    while ((ch = peekChar(cursor)) !== ">") {
      if (peekChar(cursor) === "<") {
        skipExtendedBlock(cursor);
      } else {
        skipChar(cursor);
        if (ch === '"')
          readUntil('"', cursor);
      }
    }
    skipChar(cursor);
  }
  function readNumber(cursor) {
    let result = "";
    while (dataAvailable(cursor)) {
      const c = peekChar(cursor);
      const v = c.charCodeAt(0);
      const isDigit = v >= 48 && v <= 57;
      if (isDigit) {
        result += c;
        skipChar(cursor);
      } else {
        break;
      }
    }
    return parseInt(result);
  }
  function readUntil(token, cursor) {
    const buffer = cursor[0];
    const offset = cursor[1];
    const index = buffer.indexOf(token, offset);
    if (index === -1)
      throw new Error("Expected token '" + token + "' not found");
    const result = buffer.substring(offset, index);
    cursor[1] = index + 1;
    return result;
  }
  function readChar(cursor) {
    return cursor[0][cursor[1]++];
  }
  function peekChar(cursor) {
    return cursor[0][cursor[1]];
  }
  function tokenExistsAhead(token, terminator, cursor) {
    const [buffer, offset] = cursor;
    const tokenIndex = buffer.indexOf(token, offset);
    if (tokenIndex === -1)
      return false;
    const terminatorIndex = buffer.indexOf(terminator, offset);
    if (terminatorIndex === -1)
      throw new Error("Expected to find terminator: " + terminator);
    return tokenIndex < terminatorIndex;
  }
  function skipChar(cursor) {
    cursor[1]++;
  }
  function dataAvailable(cursor) {
    return cursor[1] !== cursor[0].length;
  }
  const qualifierById = {
    "r": "const",
    "n": "in",
    "N": "inout",
    "o": "out",
    "O": "bycopy",
    "R": "byref",
    "V": "oneway"
  };
  function parseQualifiers(cursor) {
    const qualifiers = [];
    while (true) {
      const q = qualifierById[peekChar(cursor)];
      if (q === void 0)
        break;
      qualifiers.push(q);
      skipChar(cursor);
    }
    return qualifiers;
  }
  const idByAlias = {
    "char": "c",
    "int": "i",
    "int16": "s",
    "int32": "i",
    "int64": "q",
    "uchar": "C",
    "uint": "I",
    "uint16": "S",
    "uint32": "I",
    "uint64": "Q",
    "float": "f",
    "double": "d",
    "bool": "B",
    "void": "v",
    "string": "*",
    "object": "@",
    "block": "@?",
    "class": "#",
    "selector": ":",
    "pointer": "^v"
  };
  function typeIdFromAlias(alias) {
    if (typeof alias === "object" && alias !== null)
      return `@"${alias.type}"`;
    const id = idByAlias[alias];
    if (id === void 0)
      throw new Error("No known encoding for type " + alias);
    return id;
  }
  const fromNativeId = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new ObjCObject(h);
    }
  };
  const toNativeId = function(v) {
    if (v === null)
      return NULL;
    const type = typeof v;
    if (type === "string") {
      if (cachedNSStringCtor === null) {
        cachedNSString = classRegistry.NSString;
        cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
      }
      return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
    } else if (type === "number") {
      if (cachedNSNumberCtor === null) {
        cachedNSNumber = classRegistry.NSNumber;
        cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
      }
      return cachedNSNumberCtor.call(cachedNSNumber, v);
    }
    return v;
  };
  const fromNativeBlock = function(h) {
    if (h.isNull()) {
      return null;
    } else if (h.toString(16) === this.handle.toString(16)) {
      return this;
    } else {
      return new Block(h);
    }
  };
  const toNativeBlock = function(v) {
    return v !== null ? v : NULL;
  };
  const toNativeObjectArray = function(v) {
    if (v instanceof Array) {
      const length = v.length;
      const array2 = Memory.alloc(length * pointerSize);
      for (let i = 0; i !== length; i++)
        array2.add(i * pointerSize).writePointer(toNativeId(v[i]));
      return array2;
    }
    return v;
  };
  function arrayType(length, elementType) {
    return {
      type: "pointer",
      read(address) {
        const result = [];
        const elementSize = elementType.size;
        for (let index = 0; index !== length; index++) {
          result.push(elementType.read(address.add(index * elementSize)));
        }
        return result;
      },
      write(address, values) {
        const elementSize = elementType.size;
        values.forEach((value, index) => {
          elementType.write(address.add(index * elementSize), value);
        });
      }
    };
  }
  function structType(fieldTypes) {
    let fromNative, toNative;
    if (fieldTypes.some(function(t) {
      return !!t.fromNative;
    })) {
      const fromTransforms = fieldTypes.map(function(t) {
        if (t.fromNative)
          return t.fromNative;
        else
          return identityTransform;
      });
      fromNative = function(v) {
        return v.map(function(e, i) {
          return fromTransforms[i].call(this, e);
        });
      };
    } else {
      fromNative = identityTransform;
    }
    if (fieldTypes.some(function(t) {
      return !!t.toNative;
    })) {
      const toTransforms = fieldTypes.map(function(t) {
        if (t.toNative)
          return t.toNative;
        else
          return identityTransform;
      });
      toNative = function(v) {
        return v.map(function(e, i) {
          return toTransforms[i].call(this, e);
        });
      };
    } else {
      toNative = identityTransform;
    }
    const [totalSize, fieldOffsets] = fieldTypes.reduce(function(result, t) {
      const [previousOffset, offsets] = result;
      const { size } = t;
      const offset = align(previousOffset, size);
      offsets.push(offset);
      return [offset + size, offsets];
    }, [0, []]);
    return {
      type: fieldTypes.map((t) => t.type),
      size: totalSize,
      read(address) {
        return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
      },
      write(address, values) {
        values.forEach((value, index) => {
          fieldTypes[index].write(address.add(fieldOffsets[index]), value);
        });
      },
      fromNative,
      toNative
    };
  }
  function unionType(fieldTypes) {
    const largestType = fieldTypes.reduce(function(largest, t) {
      if (t.size > largest.size)
        return t;
      else
        return largest;
    }, fieldTypes[0]);
    let fromNative, toNative;
    if (largestType.fromNative) {
      const fromTransform = largestType.fromNative;
      fromNative = function(v) {
        return fromTransform.call(this, v[0]);
      };
    } else {
      fromNative = function(v) {
        return v[0];
      };
    }
    if (largestType.toNative) {
      const toTransform = largestType.toNative;
      toNative = function(v) {
        return [toTransform.call(this, v)];
      };
    } else {
      toNative = function(v) {
        return [v];
      };
    }
    return {
      type: [largestType.type],
      size: largestType.size,
      read: largestType.read,
      write: largestType.write,
      fromNative,
      toNative
    };
  }
  const longBits = pointerSize == 8 && Process.platform !== "windows" ? 64 : 32;
  modifiers = /* @__PURE__ */ new Set([
    "j",
    // complex
    "A",
    // atomic
    "r",
    // const
    "n",
    // in
    "N",
    // inout
    "o",
    // out
    "O",
    // by copy
    "R",
    // by ref
    "V",
    // one way
    "+"
    // GNU register
  ]);
  singularTypeById = {
    "c": {
      type: "char",
      size: 1,
      read: (address) => address.readS8(),
      write: (address, value) => {
        address.writeS8(value);
      },
      toNative(v) {
        if (typeof v === "boolean") {
          return v ? 1 : 0;
        }
        return v;
      }
    },
    "i": {
      type: "int",
      size: 4,
      read: (address) => address.readInt(),
      write: (address, value) => {
        address.writeInt(value);
      }
    },
    "s": {
      type: "int16",
      size: 2,
      read: (address) => address.readS16(),
      write: (address, value) => {
        address.writeS16(value);
      }
    },
    "l": {
      type: "int32",
      size: 4,
      read: (address) => address.readS32(),
      write: (address, value) => {
        address.writeS32(value);
      }
    },
    "q": {
      type: "int64",
      size: 8,
      read: (address) => address.readS64(),
      write: (address, value) => {
        address.writeS64(value);
      }
    },
    "C": {
      type: "uchar",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      }
    },
    "I": {
      type: "uint",
      size: 4,
      read: (address) => address.readUInt(),
      write: (address, value) => {
        address.writeUInt(value);
      }
    },
    "S": {
      type: "uint16",
      size: 2,
      read: (address) => address.readU16(),
      write: (address, value) => {
        address.writeU16(value);
      }
    },
    "L": {
      type: "uint" + longBits,
      size: longBits / 8,
      read: (address) => address.readULong(),
      write: (address, value) => {
        address.writeULong(value);
      }
    },
    "Q": {
      type: "uint64",
      size: 8,
      read: (address) => address.readU64(),
      write: (address, value) => {
        address.writeU64(value);
      }
    },
    "f": {
      type: "float",
      size: 4,
      read: (address) => address.readFloat(),
      write: (address, value) => {
        address.writeFloat(value);
      }
    },
    "d": {
      type: "double",
      size: 8,
      read: (address) => address.readDouble(),
      write: (address, value) => {
        address.writeDouble(value);
      }
    },
    "B": {
      type: "bool",
      size: 1,
      read: (address) => address.readU8(),
      write: (address, value) => {
        address.writeU8(value);
      },
      fromNative(v) {
        return v ? true : false;
      },
      toNative(v) {
        return v ? 1 : 0;
      }
    },
    "v": {
      type: "void",
      size: 0
    },
    "*": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative(h) {
        return h.readCString();
      }
    },
    "@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    "@?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeBlock,
      toNative: toNativeBlock
    },
    "^@": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      toNative: toNativeObjectArray
    },
    "^v": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "#": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    ":": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    },
    "?": {
      type: "pointer",
      size: pointerSize,
      read: (address) => address.readPointer(),
      write: (address, value) => {
        address.writePointer(value);
      }
    }
  };
  function identityTransform(v) {
    return v;
  }
  function align(value, boundary) {
    const remainder = value % boundary;
    return remainder === 0 ? value : value + (boundary - remainder);
  }
}
var runtime = new Runtime();
var frida_objc_bridge_default = runtime;

// agents/frida/common.ts
var state = {
  session: "",
  bundle: "",
  serial: 0,
  disposing: false,
  objects: /* @__PURE__ */ new Map(),
  byPointer: /* @__PURE__ */ new Map()
};
var leases = /* @__PURE__ */ new Map();
var owners = /* @__PURE__ */ new Map();
var expiredLeases = /* @__PURE__ */ new Set();
var currentLease = "";
var leaseSerial = 0;
var ObjectLimitError = class extends Error {
};
function own(id) {
  if (!currentLease)
    throw new Error("Object access requires a main-thread lease");
  leases.get(currentLease).objects.add(id);
  if (!owners.has(id))
    owners.set(id, /* @__PURE__ */ new Set());
  owners.get(id).add(currentLease);
}
function releaseLease(id) {
  if (id === currentLease)
    return;
  const lease = leases.get(id);
  if (!lease || lease.held)
    return;
  for (const objectId2 of lease.objects) {
    const refs = owners.get(objectId2);
    refs.delete(id);
    if (refs.size)
      continue;
    const object = state.objects.get(objectId2);
    state.byPointer.delete(object.handle.toString());
    state.objects.delete(objectId2);
    owners.delete(objectId2);
    object.release();
  }
  leases.delete(id);
  expiredLeases.add(id);
}
function expireLeases(now = Date.now()) {
  for (const [id, lease] of leases)
    if (lease.expires <= now)
      releaseLease(id);
}
function takeExpiredLeases() {
  const result = Array.from(expiredLeases);
  expiredLeases.clear();
  return result;
}
function withObjectLease(args, work) {
  const id = args._lease_id || `${state.session}:rpc_${++leaseSerial}`;
  currentLease = id;
  const lease = leases.get(id) || { objects: /* @__PURE__ */ new Set(), expires: 0 };
  lease.expires = Date.now() + Math.max(1, args._lease_ttl || 60) * 1e3;
  if (args._hold_lease)
    lease.held = true;
  leases.set(id, lease);
  try {
    const inputs = ["view_id", "root_view_id", "object_id", "window_id"].map((key) => args[key]).concat(args._input_handles || []);
    for (const input of inputs) {
      if (input && state.objects.has(input))
        own(input);
    }
    for (const stale of args._release_leases || [])
      releaseLease(stale);
    expireLeases();
    for (const stale of Array.from(leases.keys())) {
      if (leases.size <= 64)
        break;
      releaseLease(stale);
    }
    return work();
  } catch (error) {
    currentLease = "";
    lease.held = false;
    releaseLease(id);
    throw error;
  } finally {
    currentLease = "";
    if (leases.get(id)?.objects.size === 0 && !lease.held)
      leases.delete(id);
  }
}
function finishObjectLease(id, ttl) {
  const lease = leases.get(id);
  if (lease) {
    lease.held = false;
    lease.expires = Date.now() + Math.max(1, ttl || 60) * 1e3;
  }
}
function objectStats() {
  return { objects: state.objects.size, leases: leases.size, limit: 2048 };
}
function requireRuntime() {
  if (!frida_objc_bridge_default.available)
    throw new Error("Objective-C runtime is unavailable; pure Swift metadata is not reconstructed");
}
function processIdentity() {
  requireRuntime();
  const pool = frida_objc_bridge_default.classes.NSAutoreleasePool.alloc().init();
  try {
    const bundle = frida_objc_bridge_default.classes.NSBundle.mainBundle();
    return {
      bundle_id: String(bundle.bundleIdentifier()),
      pid: Process.id,
      architecture: Process.arch,
      executable: String(bundle.executablePath()),
      observed: true
    };
  } finally {
    pool.drain();
  }
}
function main(work) {
  requireRuntime();
  return new Promise((resolve2, reject) => {
    frida_objc_bridge_default.schedule(frida_objc_bridge_default.mainQueue, () => {
      try {
        resolve2(work());
      } catch (error) {
        reject(error);
      }
    });
  });
}
function objectId(object) {
  if (object === null || object.handle.isNull())
    return null;
  const address = object.handle.toString();
  const known = state.byPointer.get(address);
  if (known) {
    own(known);
    return known;
  }
  if (state.objects.size >= 2048) {
    for (const stale of Array.from(leases.keys())) {
      releaseLease(stale);
      if (state.objects.size < 2048)
        break;
    }
    if (state.objects.size >= 2048)
      throw new ObjectLimitError("Current operation reached the 2048-object bound; reduce max_nodes");
  }
  const id = `${state.session}:object_${++state.serial}`;
  object.retain();
  state.objects.set(id, object);
  state.byPointer.set(address, id);
  own(id);
  return id;
}
function objectFor(id) {
  if (!id.startsWith(state.session + ":"))
    throw new Error("Object belongs to another process session");
  const object = state.objects.get(id);
  if (!object)
    throw new Error("Unknown session-scoped object ID");
  own(id);
  return object;
}
function releaseObjects() {
  for (const object of state.objects.values())
    object.release();
  state.objects.clear();
  state.byPointer.clear();
  leases.clear();
  owners.clear();
  expiredLeases.clear();
}
function array(collection, limit = 1e4) {
  const values = [];
  if (collection == null || collection.handle?.isNull())
    return values;
  const count = Math.min(Number(collection.count()), limit);
  for (let i = 0; i < count; i++)
    values.push(collection.objectAtIndex_(i));
  return values;
}
function nullableString(value, max = 512) {
  if (value == null || value.handle?.isNull())
    return null;
  return String(value).slice(0, max);
}
function classFor(name) {
  requireRuntime();
  const klass = frida_objc_bridge_default.classes[name];
  if (!klass)
    throw new Error(`Class is not registered: ${name}`);
  return klass;
}
function methodFor(args) {
  const klass = classFor(args.class_name);
  const key = `${args.class_method ? "+" : "-"} ${args.selector}`;
  const method2 = klass[key];
  if (!method2)
    throw new Error(`Method does not exist: ${args.class_name} ${key}`);
  return method2;
}
function imageFor(address) {
  const stripped = Process.arch === "arm64" ? address.strip() : address;
  const image = Process.findModuleByAddress(stripped);
  if (!image)
    return null;
  let uuid = null;
  let architecture = Process.arch;
  try {
    if (image.base.readU32() === 4277009103) {
      if ((image.base.add(8).readU32() & 16777215) === 2 && Process.arch === "arm64")
        architecture = "arm64e";
      const count = Math.min(image.base.add(16).readU32(), 4096);
      const bytes = Math.min(image.base.add(20).readU32(), 1048576);
      let cursor = image.base.add(32);
      const end = cursor.add(bytes);
      for (let i = 0; i < count && cursor.compare(end) < 0; i++) {
        const command = cursor.readU32();
        const size = cursor.add(4).readU32();
        if (size < 8 || cursor.add(size).compare(end) > 0)
          break;
        if (command === 27 && size >= 24) {
          const raw = new Uint8Array(cursor.add(8).readByteArray(16));
          const hex = Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
          uuid = [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
          break;
        }
        cursor = cursor.add(size);
      }
    }
  } catch (_) {
  }
  return {
    name: image.name,
    path: image.path,
    runtime_base: image.base.toString(),
    size: image.size,
    uuid,
    canonical_address: stripped.toString(),
    pac_stripped: !stripped.equals(address),
    architecture
  };
}

// agents/frida/objc_runtime.ts
function metadata(method2, key) {
  const implementation3 = method2.implementation;
  return {
    selector: key.slice(2),
    class_method: key.startsWith("+"),
    type_encoding: method2.types,
    return_type: method2.returnType,
    argument_types: method2.argumentTypes,
    implementation: implementation3.toString(),
    image: imageFor(implementation3),
    observed: true
  };
}
function copyList(klass, copyName, read) {
  const count = Memory.alloc(4);
  count.writeU32(0);
  const copy = frida_objc_bridge_default.api[copyName] || new NativeFunction(Module.getGlobalExportByName(copyName), "pointer", ["pointer", "pointer"]);
  const entries2 = copy(klass.handle, count);
  const result = [];
  try {
    for (let i = 0; i < Math.min(count.readU32(), 1e4); i++) {
      result.push(read(entries2.add(i * Process.pointerSize).readPointer()));
    }
  } finally {
    if (!entries2.isNull())
      new NativeFunction(Module.getGlobalExportByName("free"), "void", ["pointer"])(entries2);
  }
  return result;
}
function searchClasses(args) {
  const query = String(args.query || "").toLowerCase();
  const names = Object.keys(frida_objc_bridge_default.classes).filter((name) => name.toLowerCase().includes(query)).sort();
  const offset = args.offset || 0, limit = args.limit || 100;
  return {
    classes: names.slice(offset, offset + limit),
    total: names.length,
    next_offset: offset + limit < names.length ? offset + limit : null,
    observed: true
  };
}
function methods(args) {
  const klass = classFor(args.class_name);
  const names = args.include_inherited ? klass.$methods : klass.$ownMethods;
  const filtered = names.filter((key) => args.class_method == null || key.startsWith(args.class_method ? "+" : "-"));
  const offset = args.offset || 0, limit = args.limit || 100;
  return {
    methods: filtered.slice(offset, offset + limit).map((key) => metadata(klass[key], key)),
    total: filtered.length,
    next_offset: offset + limit < filtered.length ? offset + limit : null,
    observed: true
  };
}
function properties(args) {
  const klass = classFor(args.class_name);
  const values = copyList(klass, "class_copyPropertyList", (entry) => ({
    name: frida_objc_bridge_default.api.property_getName(entry).readUtf8String(),
    attributes: new NativeFunction(Module.getGlobalExportByName("property_getAttributes"), "pointer", ["pointer"])(entry).readUtf8String(),
    observed: true
  }));
  const offset = args.offset || 0, limit = args.limit || 100;
  return {
    properties: values.slice(offset, offset + limit),
    total: values.length,
    next_offset: offset + limit < values.length ? offset + limit : null
  };
}
function ivars(args) {
  const values = copyList(classFor(args.class_name), "class_copyIvarList", (entry) => ({
    name: frida_objc_bridge_default.api.ivar_getName(entry).readUtf8String(),
    type_encoding: frida_objc_bridge_default.api.ivar_getTypeEncoding(entry).readUtf8String(),
    offset: Number(frida_objc_bridge_default.api.ivar_getOffset(entry)),
    observed: true
  }));
  const offset = args.offset || 0, limit = args.limit || 100;
  return {
    ivars: values.slice(offset, offset + limit),
    total: values.length,
    next_offset: offset + limit < values.length ? offset + limit : null
  };
}
function dumpClass(args) {
  const klass = classFor(args.class_name);
  const hierarchy = [];
  let current = klass;
  while (current && hierarchy.length < 64) {
    hierarchy.push(current.$className);
    current = current.$superClass;
  }
  const cap = { ...args, offset: 0, limit: args.limit || 200 };
  return {
    class_name: args.class_name,
    superclass: klass.$superClass?.$className || null,
    hierarchy,
    protocols: Object.keys(klass.$protocols),
    methods: methods(cap),
    properties: properties(cap),
    ivars: ivars(cap),
    image: klass.$moduleName,
    observed: true,
    swift_limitations: "Only Objective-C-exposed Swift classes and methods are visible"
  };
}
function inspectObject(args) {
  const object = objectFor(args.object_id);
  if (args.include_values || args.field_names)
    return readObject(object, args);
  return {
    object_id: args.object_id,
    class_name: object.$className,
    kind: object.$kind,
    protocols: Object.keys(object.$protocols),
    methods: object.$ownMethods.slice(0, args.limit || 100),
    ivar_names: Object.keys(object.$ivars).slice(0, args.limit || 100),
    observed: true
  };
}
function implementation2(args) {
  const method2 = methodFor(args);
  return { class_name: args.class_name, ...metadata(method2, `${args.class_method ? "+" : "-"} ${args.selector}`) };
}
var sensitive = /password|passwd|secret|authorization|cookie|credential|access.?token|private.?key/i;
function isKind(object, name) {
  return !!frida_objc_bridge_default.classes[name] && !!object.isKindOfClass_(frida_objc_bridge_default.classes[name]);
}
function boundedString(value, maximum) {
  const length = Number(value.length());
  return String(length > maximum ? value.substringToIndex_(maximum) : value);
}
function valueOf(value, args, depth = 0, seen = /* @__PURE__ */ new Set()) {
  const budget = args._value_budget;
  if (++budget.nodes > 1e3 || budget.characters >= 32768)
    return { truncated: "value_budget" };
  if (value == null || typeof value === "boolean" || typeof value === "number")
    return value;
  if (typeof value === "string") {
    const text2 = value.slice(0, Math.min(args.max_string_length || 128, 32768 - budget.characters));
    budget.characters += text2.length;
    return text2;
  }
  if (typeof value === "bigint")
    return value.toString();
  if (Array.isArray(value))
    return depth >= (args.max_depth ?? 1) ? { array_length: value.length } : value.slice(0, args.max_items || 5).map((item) => valueOf(item, args, depth + 1, seen));
  if (!value.handle)
    return { scalar: String(value).slice(0, 128) };
  if (value.handle.isNull())
    return null;
  const maximum = Math.min(args.max_string_length || 128, 32768 - budget.characters);
  if (isKind(value, "NSString")) {
    const text2 = boundedString(value, maximum);
    budget.characters += text2.length;
    return text2;
  }
  if (isKind(value, "NSNumber"))
    return { number: String(value.stringValue()) };
  if (isKind(value, "NSNull"))
    return null;
  const id = objectId(value), result = { object_id: id, class_name: value.$className };
  if (isKind(value, "NSData"))
    return { ...result, bytes: Number(value.length()) };
  if (depth >= (args.max_depth ?? 1) || seen.has(id))
    return result;
  seen.add(id);
  const maximumItems = args.max_items || 5;
  if (isKind(value, "NSArray")) {
    const count = Number(value.count());
    result.items = Array.from({ length: Math.min(count, maximumItems) }, (_, i) => valueOf(value.objectAtIndex_(i), args, depth + 1, seen));
    result.total = count;
  } else if (isKind(value, "NSDictionary")) {
    result.entries = [];
    result.total = Number(value.count());
    const enumerator = value.keyEnumerator();
    for (let i = 0; i < maximumItems; i++) {
      const key = enumerator.nextObject();
      if (!key || key.handle.isNull())
        break;
      const stringKey = isKind(key, "NSString"), fullName = stringKey ? boundedString(key, 4096) : `[${key.$className}]`;
      const secret = sensitive.test(fullName) || stringKey && Number(key.length()) > 4096;
      result.entries.push({ key: fullName.slice(0, maximum), value: secret ? "[REDACTED]" : valueOf(value.objectForKey_(key), args, depth + 1, seen) });
    }
  }
  return result;
}
function readObject(object, args) {
  args._value_budget ||= { nodes: 0, characters: 0 };
  const available = Object.keys(object.$ivars), names = args.field_names ?? available.slice(0, args.max_fields || 8);
  const values = /* @__PURE__ */ Object.create(null);
  for (const name of names) {
    if (sensitive.test(name)) {
      values[name] = "[REDACTED]";
      continue;
    }
    if (!available.includes(name)) {
      values[name] = { unavailable: "ivar_not_found" };
      continue;
    }
    try {
      values[name] = valueOf(object.$ivars[name], args);
    } catch (error) {
      values[name] = { unavailable: error instanceof Error ? error.name : "read_failed" };
    }
  }
  return {
    object_id: objectId(object),
    class_name: object.$className,
    values,
    total_ivars: available.length,
    fields_truncated: !args.field_names && available.length > names.length,
    values_truncated: args._value_budget.nodes > 1e3 || args._value_budget.characters >= 32768
  };
}
function inspectObjects(args) {
  return { instances: args.object_ids.map((id) => readObject(objectFor(id), args)), source: "leased_handles" };
}
function findInstances(args) {
  const values = [], limit = args.limit || 100, offset = args.offset || 0;
  let visited = 0;
  frida_objc_bridge_default.choose({ class: classFor(args.class_name), subclasses: args.include_subclasses ?? true }, {
    onMatch(object) {
      if (visited++ < offset)
        return;
      values.push(args.include_values ? readObject(object, args) : { object_id: objectId(object), class_name: object.$className });
      if (values.length >= limit)
        return "stop";
    },
    onComplete() {
    }
  });
  return {
    instances: values,
    limit_reached: values.length >= limit,
    supported: true,
    warning: "Heap enumeration scans the allocator and may pause the target; cached pages and leased handles avoid rescanning"
  };
}

// agents/frida/ui_inspector.ts
function rect(value) {
  if (Array.isArray(value))
    return { x: Number(value[0][0]), y: Number(value[0][1]), width: Number(value[1][0]), height: Number(value[1][1]) };
  return { x: Number(value.origin.x), y: Number(value.origin.y), width: Number(value.size.width), height: Number(value.size.height) };
}
function isKind2(object, name) {
  return !!frida_objc_bridge_default.classes[name] && !!object.isKindOfClass_(frida_objc_bridge_default.classes[name]);
}
function viewFor(id) {
  const object = objectFor(id);
  if (!isKind2(object, "UIView"))
    throw new Error("Object is not a UIView");
  return object;
}
function controller(view, cache = /* @__PURE__ */ new Map()) {
  const path = [view.handle.toString()];
  let responder = view.nextResponder();
  for (let i = 0; i < 64 && responder && !responder.handle.isNull(); i++) {
    const key = responder.handle.toString();
    let owner2 = cache.get(key);
    if (owner2 === void 0 && isKind2(responder, "UIViewController"))
      owner2 = { object_id: objectId(responder), class_name: responder.$className, observed: true, basis: "nextResponder chain" };
    if (owner2 !== void 0) {
      for (const id of path)
        cache.set(id, owner2);
      return owner2;
    }
    path.push(key);
    responder = responder.nextResponder();
  }
  for (const id of path)
    cache.set(id, null);
  return null;
}
function text(view) {
  if (view.respondsToSelector_(frida_objc_bridge_default.selector("isSecureTextEntry")) && view.isSecureTextEntry())
    return "[REDACTED]";
  const identifier = nullableString(view.accessibilityIdentifier()) || "";
  if (/password|passwd|secret|token|credential|private.?key/i.test(identifier))
    return "[REDACTED]";
  if (isKind2(view, "UIButton"))
    return nullableString(view.currentTitle());
  if (isKind2(view, "UILabel") || isKind2(view, "UITextField") || isKind2(view, "UITextView"))
    return nullableString(view.text());
  return null;
}
function windows() {
  const app = frida_objc_bridge_default.classes.UIApplication?.sharedApplication();
  if (!app)
    throw new Error("UIKit is unavailable in this process");
  const found = /* @__PURE__ */ new Map(), scenes = [];
  if (app.respondsToSelector_(frida_objc_bridge_default.selector("connectedScenes"))) {
    for (const scene of array(app.connectedScenes().allObjects(), 100)) {
      const sceneId = nullableString(scene.session().persistentIdentifier());
      const sceneInfo = { scene_id: sceneId, activation_state: Number(scene.activationState()), class_name: scene.$className, windows: [] };
      if (scene.respondsToSelector_(frida_objc_bridge_default.selector("windows"))) {
        for (const window of array(scene.windows(), 100)) {
          found.set(window.handle.toString(), window);
          sceneInfo.windows.push(objectId(window));
        }
      }
      scenes.push(sceneInfo);
    }
  }
  for (const window of array(app.windows(), 100))
    found.set(window.handle.toString(), window);
  const values = Array.from(found.values()).map((window) => ({
    view_id: objectId(window),
    class_name: window.$className,
    key_window: !!window.isKeyWindow(),
    hidden: !!window.isHidden(),
    alpha: Number(window.alpha()),
    frame: rect(window.frame()),
    window_level: Number(window.windowLevel()),
    root_controller: window.rootViewController()?.$className || null,
    observed: true
  }));
  return { windows: values, scenes, observed: true };
}
function targets(view) {
  if (!isKind2(view, "UIControl"))
    return [];
  const result = [];
  const events = [1, 2, 4, 8, 16, 32, 64, 128, 256, 4096, 8192, 65536, 131072, 262144, 524288];
  for (const target of array(view.allTargets().allObjects(), 32)) {
    for (const event of events) {
      for (const selector2 of array(view.actionsForTarget_forControlEvent_(target, event), 32)) {
        result.push({ target_id: objectId(target), target_class: target.$className, selector: String(selector2), control_event: event, observed: true });
        if (result.length >= 128)
          return result;
      }
    }
  }
  return result;
}
function screenFrame(view) {
  return rect(view.convertRect_toView_(view.bounds(), view.window()));
}
function ancestry(view) {
  let current = view.superview(), hidden = false, alpha = 1, interaction = true;
  for (let i = 0; i < 128 && current && !current.handle.isNull(); i++) {
    hidden ||= !!current.isHidden();
    alpha *= Number(current.alpha());
    interaction &&= !!current.isUserInteractionEnabled();
    current = current.superview();
  }
  return { hidden, alpha, interaction };
}
function interactive(view) {
  if (!view.isUserInteractionEnabled())
    return false;
  if (isKind2(view, "UIControl") || Number(view.gestureRecognizers()?.count() || 0) > 0 || !!view.isAccessibilityElement())
    return true;
  const klass = frida_objc_bridge_default.classes[view.$className];
  return ["touchesBegan:withEvent:", "touchesEnded:withEvent:", "hitTest:withEvent:"].some((selector2) => {
    const method2 = klass["- " + selector2], base = frida_objc_bridge_default.classes.UIView["- " + selector2];
    return method2 && base && !method2.implementation.equals(base.implementation);
  });
}
var summaryFields = ["view_id", "class_name", "frame", "screen_frame", "parent_id", "depth", "interactive", "accessibility_identifier"];
var detailFields = [...summaryFields, "bounds", "is_button", "hidden", "alpha", "effective_alpha", "visible", "user_interaction_enabled", "controller", "observed"];
function describe(view, includeText, detailed = false, fields, owners2 = /* @__PURE__ */ new Map(), visibility) {
  const selected = new Set(fields || (detailed ? [...detailFields, "superview_id", "subviews", "translates_autoresizing_mask", "targets"] : summaryFields));
  const result = { view_id: objectId(view), class_name: view.$className };
  if (selected.has("frame"))
    result.frame = rect(view.frame());
  if (selected.has("screen_frame"))
    result.screen_frame = screenFrame(view);
  if (selected.has("bounds"))
    result.bounds = rect(view.bounds());
  if (selected.has("is_button"))
    result.is_button = isKind2(view, "UIButton");
  if (selected.has("hidden"))
    result.hidden = !!view.isHidden();
  if (selected.has("alpha"))
    result.alpha = Number(view.alpha());
  if (selected.has("effective_alpha"))
    result.effective_alpha = visibility?.alpha ?? ancestry(view).alpha * Number(view.alpha());
  if (selected.has("visible")) {
    const ancestors = visibility || ancestry(view);
    result.visible = !(ancestors.hidden || view.isHidden()) && Number(view.alpha()) * (visibility ? 1 : ancestors.alpha) > 0.01 && (visibility ? visibility.visible : true);
  }
  if (selected.has("user_interaction_enabled"))
    result.user_interaction_enabled = !!view.isUserInteractionEnabled();
  if (selected.has("interactive"))
    result.interactive = visibility?.interactive ?? (interactive(view) && ancestry(view).interaction);
  if (selected.has("accessibility_identifier"))
    result.accessibility_identifier = nullableString(view.accessibilityIdentifier());
  if (selected.has("controller"))
    result.controller = controller(view, owners2);
  if (selected.has("observed"))
    result.observed = true;
  if (includeText && (!fields || selected.has("text")))
    result.text = text(view);
  if (selected.has("superview_id"))
    result.superview_id = objectId(view.superview());
  if (selected.has("subviews"))
    result.subviews = array(view.subviews(), 500).map(objectId);
  if (selected.has("translates_autoresizing_mask"))
    result.translates_autoresizing_mask = !!view.translatesAutoresizingMaskIntoConstraints();
  if (selected.has("targets"))
    result.targets = targets(view);
  return result;
}
function snapshot(args, windowInfo = windows()) {
  const started = Date.now();
  const roots = args.root_view_id ? [viewFor(args.root_view_id)] : windowInfo.windows.map((w) => objectFor(w.view_id));
  const queue = roots.map((view) => ({ view, depth: 0, parent_id: null, ancestors: ancestry(view) }));
  const nodes = [], visited = /* @__PURE__ */ new Set(), owners2 = /* @__PURE__ */ new Map();
  const depthLimit = args.depth ?? 8, maximum = args.max_nodes ?? 1e3;
  const detail = args.format === "detail", visibleOnly = args.visible_only ?? true, controlsOnly = args.controls_only ?? true;
  const fields = args.fields || [...detail ? detailFields : summaryFields, ...args.include_text ? ["text"] : []];
  let truncated = false, index = 0, objectLimit = false;
  for (; index < queue.length && visited.size < maximum; index++) {
    const { view, depth, parent_id, ancestors } = queue[index];
    if (visited.has(view.handle.toString()))
      continue;
    visited.add(view.handle.toString());
    const hidden = ancestors.hidden || !!view.isHidden(), alpha = ancestors.alpha * Number(view.alpha());
    const box = screenFrame(view), window = view.window();
    const windowBox = window && !window.handle.isNull() ? rect(window.bounds()) : null;
    const visible = !hidden && alpha > 0.01 && box.width > 0 && box.height > 0 && !!windowBox && box.x < windowBox.x + windowBox.width && box.y < windowBox.y + windowBox.height && box.x + box.width > windowBox.x && box.y + box.height > windowBox.y;
    if (visibleOnly && (hidden || alpha <= 0.01))
      continue;
    const matches = (!args.class_name || view.$className === args.class_name) && (!args.accessibility_identifier || nullableString(view.accessibilityIdentifier()) === args.accessibility_identifier) && (args.hidden == null || !!view.isHidden() === args.hidden) && (args.user_interaction_enabled == null || !!view.isUserInteractionEnabled() === args.user_interaction_enabled) && (args.text == null || String(text(view) || "").toLowerCase().includes(String(args.text).toLowerCase()));
    let selectedParent = parent_id;
    const isInteractive = matches && (!visibleOnly || visible) && (controlsOnly || fields.includes("interactive")) ? ancestors.interaction && interactive(view) : void 0;
    const isContent = !controlsOnly || isInteractive || matches && (!visibleOnly || visible) && (isKind2(view, "UILabel") || isKind2(view, "UITextView") || !!view.isAccessibilityElement());
    if (matches && (!visibleOnly || visible) && isContent) {
      try {
        const description = describe(view, !!args.include_text, false, fields, owners2, { hidden, alpha, interaction: ancestors.interaction, interactive: isInteractive, visible });
        if (fields.includes("parent_id"))
          description.parent_id = parent_id;
        if (fields.includes("depth"))
          description.depth = depth;
        nodes.push(description);
        selectedParent = description.view_id;
      } catch (error) {
        if (!(error instanceof ObjectLimitError))
          throw error;
        objectLimit = true;
        break;
      }
    }
    const children = array(view.subviews(), maximum + 1);
    if (depth < depthLimit)
      for (const child of children) {
        if (queue.length >= maximum * 2) {
          truncated = true;
          break;
        }
        queue.push({
          view: child,
          depth: depth + 1,
          parent_id: selectedParent,
          ancestors: { hidden, alpha, interaction: ancestors.interaction && !!view.isUserInteractionEnabled() }
        });
      }
    else if (children.length)
      truncated = true;
  }
  return {
    ...detail ? windowInfo : {},
    views: nodes,
    total_visited: visited.size,
    captured_at: new Date(started).toISOString(),
    collection_ms: Date.now() - started,
    truncated: truncated || index < queue.length,
    object_limit_reached: objectLimit,
    coordinate_space: "screen_frame is in window UIKit points; frame is in superview points",
    session_scoped: true,
    observed: true
  };
}
function inspectView(args) {
  return describe(viewFor(args.view_id), !!args.include_text, true, args.fields);
}
function constraints(args) {
  const view = viewFor(args.view_id);
  const constraints2 = array(view.constraints(), 1e3);
  const offset = args.offset || 0, limit = args.limit || 100;
  return { constraints: constraints2.slice(offset, offset + limit).map((item) => ({
    object_id: objectId(item),
    identifier: nullableString(item.identifier()),
    first_item: objectId(item.firstItem()),
    second_item: objectId(item.secondItem()),
    first_attribute: Number(item.firstAttribute()),
    second_attribute: Number(item.secondAttribute()),
    relation: Number(item.relation()),
    multiplier: Number(item.multiplier()),
    constant: Number(item.constant()),
    priority: Number(item.priority()),
    active: !!item.isActive(),
    observed: true
  })), total: constraints2.length, next_offset: offset + limit < constraints2.length ? offset + limit : null };
}
function responders(args) {
  let current = viewFor(args.view_id);
  const result = [], visited = /* @__PURE__ */ new Set();
  while (current && !current.handle.isNull() && result.length < 64 && !visited.has(current.handle.toString())) {
    visited.add(current.handle.toString());
    result.push({ object_id: objectId(current), class_name: current.$className, observed: true });
    current = current.nextResponder();
  }
  return { responders: result, truncated: result.length >= 64 };
}
function hitTest(args) {
  const available = windows().windows;
  const selected = args.window_id ? available.find((item) => item.view_id === args.window_id) : available.find((item) => item.key_window);
  if (!selected)
    throw new Error("Select an observed window; no unique key window is available");
  const window = viewFor(selected.view_id);
  const hit = window.hitTest_withEvent_([args.x, args.y], NULL);
  return {
    coordinate_space: "window bounds in UIKit points",
    window_id: selected.view_id,
    hit: hit == null ? null : describe(hit, !!args.include_text, true),
    observed: true
  };
}
function findViews(args) {
  return snapshot({
    ...args,
    format: args.format || "detail",
    controls_only: args.controls_only ?? false,
    visible_only: args.visible_only ?? false,
    include_text: !!args.include_text
  });
}
function screenshot(args, available = windows().windows) {
  const started = Date.now();
  const selected = args.window_id ? available.find((item) => item.view_id === args.window_id) : available.find((item) => item.key_window);
  if (!selected)
    throw new Error("A window must be selected for a screenshot");
  const window = viewFor(selected.view_id);
  const size = window.bounds()[1];
  if (Number(size[0]) * Number(size[1]) > 4e6)
    throw new Error("Window exceeds screenshot size limit");
  const renderer = frida_objc_bridge_default.classes.UIGraphicsImageRenderer.alloc().initWithSize_(size);
  try {
    const block2 = new frida_objc_bridge_default.Block({ retType: "void", argTypes: ["object"], implementation() {
      window.drawViewHierarchyInRect_afterScreenUpdates_(window.bounds(), true);
    } });
    const image = renderer.imageWithActions_(block2);
    const rendered = Date.now();
    const png = new NativeFunction(Module.getGlobalExportByName("UIImagePNGRepresentation"), "pointer", ["pointer"])(image.handle);
    const data = new frida_objc_bridge_default.Object(png);
    if (Number(data.length()) > 8388608)
      throw new Error("PNG exceeds screenshot size limit");
    const encoded = Date.now();
    const binary = args._image_transport !== "base64";
    const payload = binary ? { _png: data.bytes().readByteArray(Number(data.length())) } : { base64: String(data.base64EncodedStringWithOptions_(0)) };
    return {
      mime_type: "image/png",
      ...payload,
      frida_transport: binary ? "binary" : "base64",
      window_id: selected.view_id,
      observed: true,
      width_points: Number(size[0]),
      height_points: Number(size[1]),
      scale: Number(image.scale()),
      timings_ms: { render: rendered - started, png_encode: encoded - rendered, payload_prepare: Date.now() - encoded }
    };
  } finally {
    renderer.release();
  }
}
function capture(args) {
  const result = {}, windowInfo = windows();
  if (args.mode === "summary" || args.mode === "both")
    result.summary = snapshot(args, windowInfo);
  if (args.mode === "screenshot" || args.mode === "both")
    result.screenshot = screenshot(args, windowInfo.windows);
  return result;
}

// agents/frida/tracer.ts
var hooks = /* @__PURE__ */ new Map();
var serial = 0;
function scalar(value, type) {
  if (["bool", "char", "uchar", "short", "ushort", "int", "uint"].includes(type))
    return { type, value: value.toInt32(), observed: true };
  return { type, address: value.toString(), decoded: false };
}
function hookMethod(args) {
  if (hooks.size >= 128)
    throw new Error("Hook limit reached");
  const method2 = methodFor(args), id = `${state.session}:hook_${++serial}`;
  const hook2 = { id, args, listener: null, calls: 0, emitted: 0, enabled: true };
  const limit = args.max_events || 1e3;
  const listener = Interceptor.attach(method2.implementation, {
    onEnter(callArgs2) {
      this.capture = false;
      if (!hook2.enabled)
        return;
      try {
        const receiver = new frida_objc_bridge_default.Object(callArgs2[0]);
        const matches = args.class_method ? receiver.isSubclassOfClass_(frida_objc_bridge_default.classes[args.class_name]) : receiver.isKindOfClass_(frida_objc_bridge_default.classes[args.class_name]);
        if (!matches || frida_objc_bridge_default.selectorAsString(callArgs2[1]) !== args.selector)
          return;
      } catch (_) {
        return;
      }
      hook2.calls++;
      if (hook2.emitted >= limit)
        return;
      this.capture = true;
      this.invocation = hook2.calls;
      const event = {
        type: "method_enter",
        hook_id: id,
        invocation: hook2.calls,
        timestamp_ms: Date.now(),
        thread_id: this.threadId,
        class_name: args.class_name,
        selector: args.selector
      };
      if (args.capture_arguments)
        event.arguments = method2.argumentTypes.slice(2, 10).map((type, i) => scalar(callArgs2[i + 2], type));
      if (args.backtrace)
        event.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 32).map((address) => ({ address: address.toString(), symbol: DebugSymbol.fromAddress(address).toString(), image: imageFor(address) }));
      hook2.emitted++;
      send(event);
    },
    onLeave(value) {
      if (!this.capture || hook2.emitted >= limit)
        return;
      const event = { type: "method_leave", hook_id: id, invocation: this.invocation, timestamp_ms: Date.now(), thread_id: this.threadId };
      if (args.capture_return && method2.returnType !== "void")
        event.return_value = scalar(value, method2.returnType);
      hook2.emitted++;
      send(event);
    }
  });
  hook2.listener = listener;
  hooks.set(id, hook2);
  return { hook_id: id, implementation: method2.implementation.toString(), observed: true, capture_policy: "scalars and addresses only; never dereference object arguments" };
}
function unhook(args) {
  const hook2 = hooks.get(args.hook_id);
  if (!hook2)
    throw new Error("Unknown hook in this process session");
  hook2.listener.detach();
  hooks.delete(hook2.id);
  return { hook_id: hook2.id, removed: true, calls: hook2.calls };
}
function enable(args) {
  const hook2 = hooks.get(args.hook_id);
  if (!hook2)
    throw new Error("Unknown hook in this process session");
  hook2.enabled = !!args.enabled;
  return { hook_id: hook2.id, enabled: hook2.enabled };
}
function listHooks() {
  return { hooks: Array.from(hooks.values()).map((hook2) => ({
    hook_id: hook2.id,
    class_name: hook2.args.class_name,
    selector: hook2.args.selector,
    enabled: hook2.enabled,
    calls: hook2.calls,
    emitted: hook2.emitted,
    buffer_limit_reached: hook2.emitted >= (hook2.args.max_events || 1e3)
  })) };
}
function dispose2() {
  for (const hook2 of hooks.values())
    hook2.listener.detach();
  hooks.clear();
}

// agents/frida/automation.ts
function kind(value, name) {
  return !!value && !value.handle.isNull() && !!frida_objc_bridge_default.classes[name] && !!value.isKindOfClass_(frida_objc_bridge_default.classes[name]);
}
function present(value) {
  return !!value && !value.handle.isNull();
}
function windowFor(args) {
  const windows2 = windows().windows;
  const item = args.window_id ? windows2.find((w) => w.view_id === args.window_id) : windows2.find((w) => w.key_window);
  if (!item)
    throw new Error("Select an observed window; no key window is available");
  return objectFor(item.view_id);
}
function actionable(view, interaction = true) {
  if (!kind(view, "UIView") || !present(view.window()))
    throw new Error("Target is not an attached UIView");
  const box = view.convertRect_toView_(view.bounds(), view.window()), bounds = view.window().bounds();
  if (Number(box[1][0]) <= 0 || Number(box[1][1]) <= 0 || Number(box[0][0]) + Number(box[1][0]) <= Number(bounds[0][0]) || Number(box[0][1]) + Number(box[1][1]) <= Number(bounds[0][1]) || Number(box[0][0]) >= Number(bounds[0][0]) + Number(bounds[1][0]) || Number(box[0][1]) >= Number(bounds[0][1]) + Number(bounds[1][1]))
    throw new Error("Target is outside the window bounds");
  let current = view, alpha = 1;
  for (let i = 0; i < 128 && present(current); i++, current = current.superview()) {
    alpha *= Number(current.alpha());
    if (current.isHidden() || alpha <= 0.01 || interaction && !current.isUserInteractionEnabled())
      throw new Error("Target or an ancestor is hidden, transparent or disabled");
  }
  if (interaction && kind(view, "UIControl") && !view.isEnabled())
    throw new Error("Control is disabled");
}
function resolve(target, allowMissing = false, interaction = true) {
  if (target.view_id) {
    const view2 = objectFor(target.view_id);
    try {
      actionable(view2, interaction);
    } catch (error) {
      if (allowMissing)
        return null;
      throw error;
    }
    return view2;
  }
  if (target.x != null) {
    const view2 = windowFor(target).hitTest_withEvent_([target.x, target.y], NULL);
    if (!present(view2)) {
      if (allowMissing)
        return null;
      throw new Error("No view at the requested window point");
    }
    actionable(view2, interaction);
    return view2;
  }
  const found = snapshot({
    ...target,
    format: "summary",
    fields: ["view_id"],
    controls_only: false,
    visible_only: true,
    include_text: false,
    max_nodes: target.max_nodes || 1e3,
    depth: 30
  }).views;
  if (!found.length && allowMissing)
    return null;
  const index = target.match_index;
  if (!found.length)
    throw new Error("No visible view matches the target");
  if (index == null && found.length !== 1)
    throw new Error("Target is ambiguous; select view_id or match_index");
  if (!found[index ?? 0])
    throw new Error("match_index exceeds the observed matches");
  const view = objectFor(found[index ?? 0].view_id);
  actionable(view, interaction);
  return view;
}
function step(args) {
  if (state.disposing)
    throw new Error("Process session is disposing; remaining actions were cancelled");
  const action = args.action;
  if (action === "back") {
    const window = windowFor(args), seen = /* @__PURE__ */ new Set();
    let current = window.rootViewController();
    while (present(current) && seen.size < 64 && !seen.has(current.handle.toString())) {
      seen.add(current.handle.toString());
      const next = current.presentedViewController();
      if (present(next)) {
        current = next;
        continue;
      }
      if (kind(current, "UINavigationController")) {
        current = current.visibleViewController();
        continue;
      }
      if (kind(current, "UITabBarController")) {
        current = current.selectedViewController();
        continue;
      }
      break;
    }
    if (!present(current))
      throw new Error("No visible controller is available");
    const navigation = current.navigationController();
    if (args.mode !== "dismiss" && present(navigation) && Number(navigation.viewControllers().count()) > 1) {
      navigation.popViewControllerAnimated_(!!args.animated);
      window.layoutIfNeeded();
      return { action, method: "navigation_pop", performed: true };
    }
    const modal = present(current.presentingViewController()) ? current : navigation;
    if (args.mode !== "navigation" && present(modal) && present(modal.presentingViewController())) {
      modal.dismissViewControllerAnimated_completion_(!!args.animated, NULL);
      window.layoutIfNeeded();
      return { action, method: "dismiss", performed: true };
    }
    throw new Error("No navigation or modal transition can go back from this controller");
  }
  const target = args.target || {};
  let view = resolve(target, action === "wait_for", action !== "wait_for" && action !== "assert" && action !== "tap");
  if (!view)
    return { action, matched: false };
  const viewId = objectId(view);
  if (action === "assert" || action === "wait_for")
    return { action, matched: true, view_id: viewId };
  if (action === "tap") {
    for (let i = 0; i < 32 && present(view); i++, view = view.superview()) {
      if (kind(view, "UIWindow"))
        break;
      actionable(view, false);
      if (kind(view, "UISwitch")) {
        actionable(view);
        view.setOn_(!view.isOn());
        view.sendActionsForControlEvents_(4096);
        return { action, method: "switch_value_changed", view_id: objectId(view), performed: true };
      }
      if (kind(view, "UIControl")) {
        actionable(view);
        const events = Number(view.allControlEvents());
        const event = args.event === "primary_action" ? 8192 : args.event === "touch_up_inside" ? 64 : events & 64 ? 64 : events & 8192 ? 8192 : 0;
        if (event) {
          view.sendActionsForControlEvents_(event);
          return { action, method: "control_event", control_event: event, view_id: objectId(view), performed: true };
        }
      }
      if (view.isUserInteractionEnabled() && view.respondsToSelector_(frida_objc_bridge_default.selector("accessibilityActivate")) && view.accessibilityActivate()) {
        return { action, method: "accessibility_activate", view_id: objectId(view), performed: true };
      }
    }
    throw new Error("This view requires physical touch/gesture injection; no UIKit control action or accessibility activation is available");
  }
  if (action === "input_text") {
    if (!kind(view, "UITextField") && !kind(view, "UITextView"))
      throw new Error("Text input requires UITextField or UITextView");
    if (args.focus)
      view.becomeFirstResponder();
    view.setText_(args.text);
    if (kind(view, "UIControl"))
      view.sendActionsForControlEvents_(262144);
    else
      frida_objc_bridge_default.classes.NSNotificationCenter.defaultCenter().postNotificationName_object_("UITextViewTextDidChangeNotification", view);
    return { action, view_id: viewId, characters: args.text.length, performed: true };
  }
  if (action === "scroll") {
    while (present(view) && !kind(view, "UIScrollView"))
      view = view.superview();
    if (!present(view))
      throw new Error("Target has no UIScrollView ancestor");
    const offset = view.contentOffset(), size = view.contentSize(), bounds = view.bounds()[1];
    const inset = view.adjustedContentInset();
    const top = Number(inset[0]), left = Number(inset[1]), bottom = Number(inset[2]), right = Number(inset[3]);
    const dy = args.pages == null ? args.dy ?? 0 : Number(bounds[1]) * args.pages;
    const x = Math.max(-left, Math.min(Math.max(-left, Number(size[0]) - Number(bounds[0]) + right), Number(offset[0]) + (args.dx ?? 0)));
    const y = Math.max(-top, Math.min(Math.max(-top, Number(size[1]) - Number(bounds[1]) + bottom), Number(offset[1]) + dy));
    if (x === Number(offset[0]) && y === Number(offset[1])) {
      return {
        action,
        view_id: objectId(view),
        content_offset: { x, y },
        performed: false,
        at_boundary: dy !== 0 || (args.dx ?? 0) !== 0
      };
    }
    view.setContentOffset_animated_([x, y], !!args.animated);
    return { action, view_id: objectId(view), content_offset: { x, y }, performed: true };
  }
  throw new Error("Unsupported automation action");
}
async function run(args) {
  const lease = {
    ...args,
    _hold_lease: true,
    _input_handles: args.steps.flatMap((s) => [s.target?.view_id, s.target?.window_id, s.window_id]).filter(Boolean)
  };
  const results = [];
  const started = Date.now();
  await main(() => withObjectLease(lease, () => null));
  try {
    for (const item of args.steps) {
      const begin = Date.now();
      try {
        let result;
        do {
          result = await main(() => withObjectLease(lease, () => step(item)));
          if (item.action !== "wait_for" || result.matched || Date.now() - begin >= item.timeout_ms)
            break;
          await new Promise((resolve2) => setTimeout(resolve2, Math.min(item.poll_ms, item.timeout_ms - (Date.now() - begin))));
        } while (!state.disposing);
        if (state.disposing)
          throw new Error("Process session is disposing; remaining actions were cancelled");
        if (item.action === "wait_for" && !result.matched)
          throw new Error("Timed out waiting for a visible matching view");
        results.push({ ...result, elapsed_ms: Date.now() - begin });
        if (args.settle_ms)
          await new Promise((resolve2) => setTimeout(resolve2, args.settle_ms));
      } catch (error) {
        results.push({ action: item.action, performed: false, error: error instanceof Error ? error.message : String(error), elapsed_ms: Date.now() - begin });
        break;
      }
    }
    const capture2 = args.after_capture !== "none" && !state.disposing ? await main(() => withObjectLease(lease, () => capture({ ...args, mode: args.after_capture }))) : {};
    return {
      steps: results,
      completed: results.length === args.steps.length && !results.some((s) => s.error),
      elapsed_ms: Date.now() - started,
      ...capture2
    };
  } finally {
    await main(() => finishObjectLease(args._lease_id, args._lease_ttl));
  }
}

// agents/frida/logging.ts
var listeners = [];
var entries = [];
var sequence = 0;
var dropped = 0;
var characters = 0;
var capacity = 200;
var maxLength = 512;
var sources = [];
var unavailable = [];
var failures = [];
var reading = /* @__PURE__ */ new Set();
function cString(pointer, bytes = maxLength * 4) {
  let length = 0;
  while (length < bytes && pointer.add(length).readU8())
    length++;
  for (let end = length; end >= Math.max(0, length - 3); end--) {
    try {
      return pointer.readUtf8String(end) || "";
    } catch (_) {
    }
  }
  return "";
}
function nsString(object) {
  return String(object.substringToIndex_(Math.min(Number(object.length()), maxLength + 1)));
}
function append(source, level, text2, kind2) {
  const message = text2.slice(0, maxLength);
  if (!message)
    return;
  const entry = {
    sequence: ++sequence,
    timestamp_ms: Date.now(),
    source,
    level,
    message,
    message_kind: kind2,
    truncated: text2.length > maxLength
  };
  entries.push(entry);
  characters += message.length;
  while (entries.length > capacity || characters > 65536) {
    characters -= entries.shift().message.length;
    dropped++;
  }
}
function hook(name, source, read) {
  const address = Module.findGlobalExportByName(name);
  if (!address) {
    unavailable.push(name);
    return;
  }
  try {
    listeners.push(Interceptor.attach(address, { onEnter(args) {
      if (reading.has(this.threadId))
        return;
      reading.add(this.threadId);
      try {
        read(args);
      } catch (_) {
      } finally {
        reading.delete(this.threadId);
      }
    } }));
  } catch (error) {
    unavailable.push(name);
    failures.push({ name, reason: String(error).slice(0, 160) });
    return;
  }
  if (!sources.includes(source))
    sources.push(source);
}
function start(args) {
  if (listeners.length)
    return;
  capacity = args.capacity;
  maxLength = args.max_message_length;
  unavailable = [];
  sources = [];
  failures = [];
  if (args.sources.includes("os_log"))
    hook("_os_log_impl", "os_log", (values) => {
      const level = { 0: "default", 1: "info", 2: "debug", 16: "error", 17: "fault" }[values[2].toInt32()] || "default";
      append("os_log", level, cString(values[3]), "format");
    });
  if (args.sources.includes("nslog")) {
    hook("NSLog", "nslog", (values) => append("nslog", "default", nsString(new frida_objc_bridge_default.Object(values[0])), "format"));
    hook("NSLogv", "nslog", (values) => {
      const pool = frida_objc_bridge_default.classes.NSAutoreleasePool.alloc().init();
      let formatted = null;
      try {
        formatted = frida_objc_bridge_default.classes.NSString.alloc().initWithFormat_arguments_(new frida_objc_bridge_default.Object(values[0]), values[1]);
        append("nslog", "default", nsString(formatted), "rendered");
      } finally {
        if (formatted)
          formatted.release();
        pool.release();
      }
    });
  }
  if (args.sources.includes("stdio")) {
    const read = (values) => {
      const fd = values[0].toInt32();
      if (fd !== 1 && fd !== 2)
        return;
      const count = Math.min(Number(values[2].toString()), maxLength);
      if (count > 0)
        append(fd === 1 ? "stdout" : "stderr", fd === 1 ? "info" : "error", cString(values[1], count), "rendered");
    };
    hook("write", "stdio", read);
    hook("__write_nocancel", "stdio", read);
  }
}
async function run2(args) {
  if (args.action === "stop") {
    dispose3();
    return { active: false, stopped: true, next_cursor: sequence, dropped };
  }
  start(args);
  if (args.wait_ms)
    await new Promise((resolve2) => setTimeout(resolve2, args.wait_ms));
  const reset = args.after > sequence;
  const eligible = entries.filter((e) => e.sequence > (reset ? 0 : args.after));
  const matching = eligible.filter((e) => (!args.level || e.level === args.level) && (!args.contains || e.message.includes(args.contains)));
  const page = matching.slice(0, args.limit);
  const next = matching.length > page.length ? page[page.length - 1].sequence : sequence;
  return {
    active: listeners.length > 0,
    sources,
    unavailable,
    failures,
    entries: page,
    next_cursor: next,
    has_more: matching.length > page.length,
    cursor_reset: reset,
    dropped,
    buffered: entries.length,
    oldest_cursor: entries[0]?.sequence ?? sequence + 1,
    capacity,
    max_message_length: maxLength
  };
}
function dispose3() {
  for (const listener of listeners)
    listener.detach();
  listeners.length = 0;
  entries = [];
  characters = 0;
  reading.clear();
}

// agents/frida/debugger.ts
function inspect(args) {
  let threads = Process.enumerateThreads();
  if (args.thread_id != null)
    threads = threads.filter((t) => t.id === args.thread_id);
  else
    threads = threads.slice(0, args.max_threads);
  if (args.thread_id != null && !threads.length)
    throw new Error("Thread is no longer present in this process");
  const rows = threads.map((thread) => {
    const result = { thread_id: thread.id, state: thread.state };
    if (thread.name)
      result.name = thread.name;
    if (args.mode === "backtrace") {
      try {
        result.frames = Thread.backtrace(thread.context, Backtracer.ACCURATE).slice(0, args.max_frames).map((address, index) => {
          const frame = { index, address: address.toString() };
          if (args.symbols) {
            frame.symbol = DebugSymbol.fromAddress(address).toString();
            const image = Process.findModuleByAddress(address.strip());
            if (image)
              frame.image = image.name;
          }
          return frame;
        });
      } catch (_) {
        result.unavailable = "Thread context could not be unwound";
      }
    }
    if (args.mode === "registers") {
      const names = args.register_names.length ? args.register_names : ["pc", "sp", "fp", "lr"];
      result.registers = Object.fromEntries(names.filter((name) => name in thread.context).map((name) => [name, String(thread.context[name])]));
    }
    return result;
  });
  return { backend: "frida", pid: Process.id, threads: rows, observed: true, consistent_stop: false };
}

// agents/frida/decrypt.ts
function modules() {
  const bundle = String(frida_objc_bridge_default.classes.NSBundle.mainBundle().bundlePath());
  return { dump_directory: String(frida_objc_bridge_default.classes.NSFileManager.defaultManager().temporaryDirectory().path()), bundle_path: bundle, main_module: Process.mainModule.path, modules: Process.enumerateModules().filter((m2) => m2.path.startsWith(bundle + "/")).map((m2) => ({ name: m2.name, path: m2.path, size: m2.size })) };
}
function dump(args) {
  const pool = frida_objc_bridge_default.classes.NSAutoreleasePool.alloc().init();
  try {
    let allocStr2 = function(str) {
      return Memory.allocUtf8String(str);
    }, putStr2 = function(addr, str) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.writeUtf8String(str);
    }, getByteArr2 = function(addr, l) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readByteArray(l);
    }, getU82 = function(addr) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readU8();
    }, putU82 = function(addr, n) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.writeU8(n);
    }, getU162 = function(addr) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readU16();
    }, putU162 = function(addr, n) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.writeU16(n);
    }, getU322 = function(addr) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readU32();
    }, putU322 = function(addr, n) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.writeU32(n);
    }, getU642 = function(addr) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readU64();
    }, putU642 = function(addr, n) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.writeU64(n);
    }, getPt2 = function(addr) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      return addr.readPointer();
    }, putPt2 = function(addr, n) {
      if (typeof addr == "number") {
        addr = ptr(addr);
      }
      if (typeof n == "number") {
        n = ptr(n);
      }
      return addr.writePointer(n);
    }, malloc2 = function(size) {
      return Memory.alloc(size);
    }, getExportFunction2 = function(type, name, ret, args2) {
      var nptr;
      nptr = Module.findGlobalExportByName(name);
      if (nptr === null) {
        throw new Error("Cannot find native export: " + name);
      } else {
        if (type === "f") {
          var funclet = new NativeFunction(nptr, ret, args2);
          if (typeof funclet === "undefined") {
            console.log("parse error " + name);
            return null;
          }
          return funclet;
        } else if (type === "d") {
          var datalet = nptr.readPointer();
          if (typeof datalet === "undefined") {
            console.log("parse error " + name);
            return null;
          }
          return datalet;
        }
      }
    }, read2 = function(fd, buffer, size) {
      while (true) {
        var result = nativeRead(fd, buffer, size);
        result = typeof result === "number" ? result : result.toNumber();
        if (result >= 0)
          return result;
        var error = nativeErrno().readS32();
        if (error === 4)
          continue;
        throw new Error("read failed (fd=" + fd + ", errno=" + error + ")");
      }
    }, readExact2 = function(fd, buffer, size) {
      var offset = 0;
      while (offset < size) {
        var count = read2(fd, buffer.add(offset), size - offset);
        if (count === 0) {
          throw new Error("Unexpected EOF (fd=" + fd + ", read=" + offset + "/" + size + ")");
        }
        offset += count;
      }
    }, writeAll2 = function(fd, buffer, size) {
      var offset = 0;
      while (offset < size) {
        var result = nativeWrite(fd, buffer.add(offset), size - offset);
        var count = typeof result === "number" ? result : result.toNumber();
        if (count < 0) {
          var error = nativeErrno().readS32();
          if (error === 4)
            continue;
          throw new Error("write failed (fd=" + fd + ", errno=" + error + ")");
        }
        if (count === 0)
          throw new Error("write made no progress (fd=" + fd + ")");
        offset += count;
      }
    }, lseek2 = function(fd, offset, whence) {
      var result = nativeSeek(fd, offset, whence);
      var position = typeof result === "number" ? result : result.toNumber();
      if (position < 0) {
        throw new Error("lseek failed (fd=" + fd + ", errno=" + nativeErrno().readS32() + ")");
      }
      if (!Number.isSafeInteger(position))
        throw new Error("File offset exceeds safe integer range");
      return position;
    }, getDocumentDir2 = function() {
      var manager = frida_objc_bridge_default.classes.NSFileManager.defaultManager();
      function isWritableDirectory(directory2) {
        var isDirectory = Memory.alloc(Process.pointerSize);
        isDirectory.writeU8(0);
        return manager.fileExistsAtPath_isDirectory_(directory2, isDirectory) && isDirectory.readU8() !== 0 && manager.isWritableFileAtPath_(directory2);
      }
      var NSDocumentDirectory = 9;
      var NSUserDomainMask = 1;
      var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
      if (!npdirs.isNull()) {
        var directories = frida_objc_bridge_default.Object(npdirs);
        if (directories.count() > 0) {
          var documents = directories.objectAtIndex_(0);
          if (isWritableDirectory(documents))
            return documents.toString();
        }
      }
      var temporary = NSTemporaryDirectory();
      if (!temporary.isNull()) {
        var directory = frida_objc_bridge_default.Object(temporary);
        if (isWritableDirectory(directory))
          return directory.toString();
      }
      throw new Error("No writable directory for dump files: Documents and temporary directory are unavailable");
    }, open2 = function(pathname, flags, mode) {
      if (typeof pathname == "string") {
        pathname = allocStr2(pathname);
      }
      return wrapper_open(pathname, flags, mode);
    }, getAllAppModules2 = function() {
      modules2 = new Array();
      var tmpmods = Process.enumerateModules();
      for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.startsWith(args.bundle_path + "/")) {
          modules2.push(tmpmods[i]);
        }
      }
      return modules2;
    }, pad2 = function(str, n) {
      return Array(n - str.length + 1).join("0") + str;
    }, swap322 = function(value) {
      value = pad2(value.toString(16), 8);
      var result = "";
      for (var i = 0; i < value.length; i = i + 2) {
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
      }
      return parseInt(result, 16);
    }, dumpModule2 = function(name, dumpId) {
      if (modules2 == null) {
        modules2 = getAllAppModules2();
      }
      var targetmod = null;
      for (var i = 0; i < modules2.length; i++) {
        if (modules2[i].path === name) {
          targetmod = modules2[i];
          break;
        }
      }
      if (targetmod == null) {
        throw new Error("Cannot find module: " + name);
      }
      var modbase = modules2[i].base;
      var modsize = modules2[i].size;
      var newmodpath = args.output_directory + "/vesper-" + dumpId + ".fid";
      var oldmodpath = modules2[i].path;
      if (!access(allocStr2(newmodpath), 0)) {
        remove(allocStr2(newmodpath));
      }
      var fmodule = open2(newmodpath, O_CREAT | O_TRUNC | O_RDWR, 384);
      var foldmodule = open2(oldmodpath, O_RDONLY, 0);
      if (fmodule == -1 || foldmodule == -1) {
        if (fmodule !== -1)
          close(fmodule);
        if (foldmodule !== -1)
          close(foldmodule);
        throw new Error("Cannot open module files: " + oldmodpath + " -> " + newmodpath);
      }
      try {
        var is64bit = false;
        var size_of_mach_header = 0;
        var magic = getU322(modbase);
        var cur_cpu_type = getU322(modbase.add(4));
        var cur_cpu_subtype = getU322(modbase.add(8));
        if (magic == MH_MAGIC || magic == MH_CIGAM) {
          is64bit = false;
          size_of_mach_header = 28;
        } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
          is64bit = true;
          size_of_mach_header = 32;
        } else {
          throw new Error("Unsupported Mach-O header");
        }
        var BUFSIZE = 64 * 1024;
        var buffer = malloc2(BUFSIZE);
        readExact2(foldmodule, buffer, 8);
        var fileoffset = 0;
        var filesize = 0;
        magic = getU322(buffer);
        if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
          var off = 4;
          var archs = swap322(getU322(buffer.add(4)));
          if (archs > Math.floor((BUFSIZE - 8) / 20)) {
            throw new Error("FAT architecture table exceeds buffer size");
          }
          lseek2(foldmodule, 0, SEEK_SET);
          readExact2(foldmodule, buffer, 8 + archs * 20);
          for (var i = 0; i < archs; i++) {
            var cputype = swap322(getU322(buffer.add(off + 4)));
            var cpusubtype = swap322(getU322(buffer.add(off + 8)));
            if (cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype) {
              fileoffset = swap322(getU322(buffer.add(off + 12)));
              filesize = swap322(getU322(buffer.add(off + 16)));
              break;
            }
            off += 20;
          }
          if (fileoffset == 0 || filesize == 0) {
            throw new Error("Cannot find matching architecture in " + oldmodpath);
          }
        } else {
          filesize = lseek2(foldmodule, 0, SEEK_END);
        }
        if (filesize > args.max_bytes)
          throw new Error("Module exceeds max_decrypt_bytes");
        lseek2(foldmodule, fileoffset, SEEK_SET);
        lseek2(fmodule, 0, SEEK_SET);
        var remaining = filesize;
        while (remaining > 0) {
          var chunk = Math.min(remaining, BUFSIZE);
          readExact2(foldmodule, buffer, chunk);
          writeAll2(fmodule, buffer, chunk);
          remaining -= chunk;
        }
        var ncmds = getU322(modbase.add(16));
        var off = size_of_mach_header;
        var offset_cryptid = -1;
        var crypt_off = 0;
        var crypt_size = 0;
        var segments = [];
        for (var i = 0; i < ncmds; i++) {
          var cmd = getU322(modbase.add(off));
          var cmdsize = getU322(modbase.add(off + 4));
          if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            originalCryptid = getU322(modbase.add(off + 16));
            crypt_off = getU322(modbase.add(off + 8));
            crypt_size = getU322(modbase.add(off + 12));
          }
          off += cmdsize;
        }
        if (offset_cryptid != -1) {
          if (crypt_off > filesize || crypt_size > filesize - crypt_off) {
            throw new Error("Encrypted region exceeds module file size");
          }
          lseek2(fmodule, crypt_off, SEEK_SET);
          writeAll2(fmodule, modbase.add(crypt_off), crypt_size);
          var tpbuf = malloc2(8);
          putU642(tpbuf, 0);
          lseek2(fmodule, offset_cryptid, SEEK_SET);
          writeAll2(fmodule, tpbuf, 4);
        }
        return newmodpath;
      } catch (error) {
        throw new Error("Cannot dump " + oldmodpath + ": " + error.message);
      } finally {
        close(fmodule);
        close(foldmodule);
      }
    };
    var allocStr = allocStr2, putStr = putStr2, getByteArr = getByteArr2, getU8 = getU82, putU8 = putU82, getU16 = getU162, putU16 = putU162, getU32 = getU322, putU32 = putU322, getU64 = getU642, putU64 = putU642, getPt = getPt2, putPt = putPt2, malloc = malloc2, getExportFunction = getExportFunction2, read = read2, readExact = readExact2, writeAll = writeAll2, lseek = lseek2, getDocumentDir = getDocumentDir2, open = open2, getAllAppModules = getAllAppModules2, pad = pad2, swap32 = swap322, dumpModule = dumpModule2;
    const bundle = String(frida_objc_bridge_default.classes.NSBundle.mainBundle().bundlePath());
    const target = Process.enumerateModules().find((m2) => m2.path === args.module_path);
    if (!target || !target.path.startsWith(bundle + "/") || !/^[A-Za-z0-9_-]+$/.test(args.dump_id))
      throw new Error("Select a loaded module inside the verified app bundle");
    args = { ...args, bundle_path: bundle };
    var originalCryptid = null;
    var O_RDONLY = 0;
    var O_WRONLY = 1;
    var O_RDWR = 2;
    var O_CREAT = 512;
    var O_TRUNC = 1024;
    var SEEK_SET = 0;
    var SEEK_CUR = 1;
    var SEEK_END = 2;
    var NSSearchPathForDirectoriesInDomains = getExportFunction2("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
    var NSTemporaryDirectory = getExportFunction2("f", "NSTemporaryDirectory", "pointer", []);
    var wrapper_open = getExportFunction2("f", "open", "int", ["pointer", "int", "...", "int"]);
    var nativeRead = getExportFunction2("f", "read", "long", ["int", "pointer", "ulong"]);
    var nativeWrite = getExportFunction2("f", "write", "long", ["int", "pointer", "ulong"]);
    var nativeSeek = getExportFunction2("f", "lseek", "int64", ["int", "int64", "int"]);
    var nativeErrno = getExportFunction2("f", "__error", "pointer", []);
    var close = getExportFunction2("f", "close", "int", ["int"]);
    var remove = getExportFunction2("f", "remove", "int", ["pointer"]);
    var access = getExportFunction2("f", "access", "int", ["pointer", "int"]);
    var dlopen = getExportFunction2("f", "dlopen", "pointer", ["pointer", "int"]);
    var modules2 = null;
    var FAT_MAGIC = 3405691582;
    var FAT_CIGAM = 3199925962;
    var MH_MAGIC = 4277009102;
    var MH_CIGAM = 3472551422;
    var MH_MAGIC_64 = 4277009103;
    var MH_CIGAM_64 = 3489328638;
    var LC_SEGMENT = 1;
    var LC_SEGMENT_64 = 25;
    var LC_ENCRYPTION_INFO = 33;
    var LC_ENCRYPTION_INFO_64 = 44;
    const remote = dumpModule2(target.path, args.dump_id);
    return { original_cryptid: originalCryptid, remote_path: remote, module_path: target.path, image: imageFor(target.base), backend: "frida-ios-dump", upstream_commit: "8395374b3fc254c89e6b6ef67bb8247ac6d1c342" };
  } finally {
    pool.release();
  }
}

// agents/frida/index.ts
var methods2 = {
  hook_method: hookMethod,
  unhook,
  list_hooks: listHooks,
  enable_hook: enable,
  windows,
  snapshot,
  inspect_view: inspectView,
  constraints,
  responders,
  hit_test: hitTest,
  find_views: findViews,
  screenshot,
  capture,
  release_leases: objectStats,
  search_classes: searchClasses,
  dump_class: dumpClass,
  get_methods: methods,
  get_properties: properties,
  get_ivars: ivars,
  inspect_object: inspectObject,
  get_method_implementation: implementation2,
  find_instances: findInstances,
  inspect_objects: inspectObjects
};
var leaseTimer = null;
var sweepPending = false;
rpc.exports = {
  async dispatch(name, args) {
    try {
      requireRuntime();
      if (name === "initialize") {
        if (state.session)
          throw new Error("Agent already initialized");
        const identity = processIdentity();
        if (identity.bundle_id !== args.bundle_id)
          throw new Error("Application bundle identity mismatch");
        state.session = args.session_id;
        state.bundle = identity.bundle_id;
        leaseTimer = setInterval(() => {
          if (sweepPending || state.objects.size === 0)
            return;
          sweepPending = true;
          main(() => expireLeases()).catch(() => {
          }).finally(() => {
            sweepPending = false;
          });
        }, 1e3);
        return identity;
      }
      if (!state.session)
        throw new Error("Initialize the process session first");
      if (name === "app_logs")
        return await run2(args);
      if (name === "debug_inspect")
        return inspect(args);
      if (name === "decrypt_modules")
        return modules();
      if (name === "decrypt_module")
        return dump(args);
      if (name === "automate") {
        const result = await run(args);
        const metadata2 = { ...result, _expired_leases: takeExpiredLeases() };
        const png = metadata2.screenshot?._png;
        if (png) {
          delete metadata2.screenshot._png;
          return [metadata2, png];
        }
        return metadata2;
      }
      if (name === "identity")
        return { ...processIdentity(), main_image: imageFor(Process.mainModule.base) };
      if (name === "tweak_state") {
        const module = Process.findModuleByName(args.module_name);
        if (!module)
          return { loaded: false, observed: true };
        const marker = module.findExportByName("VesperBuildID");
        const count = module.findExportByName("VesperInvocationCount");
        let buildMarker = "";
        if (marker)
          for (let i = 0; i < 80; i++) {
            const byte = marker.add(i).readU8();
            if (!byte)
              break;
            if (byte > 127)
              throw new Error("Invalid build marker");
            buildMarker += String.fromCharCode(byte);
          }
        return {
          loaded: true,
          path: module.path,
          build_marker: marker ? buildMarker : null,
          invocation_count: count ? Number(count.readU64().toString()) : 0,
          observed: true
        };
      }
      if (name === "dispose") {
        state.disposing = true;
        if (leaseTimer !== null)
          clearInterval(leaseTimer);
        leaseTimer = null;
        dispose2();
        dispose3();
        if (state.objects.size)
          await main(() => releaseObjects());
        return { disposed: true };
      }
      if (!methods2[name])
        throw new Error(`Unknown inspection RPC: ${name}`);
      const queuedAt = Date.now();
      return await main(() => {
        const started = Date.now();
        try {
          const result = withObjectLease(args, () => methods2[name](args));
          const metadata2 = { ...result, _expired_leases: takeExpiredLeases() };
          if (name === "screenshot" || name === "capture")
            metadata2._agent_timings_ms = { main_queue: started - queuedAt, execution: Date.now() - started };
          const image = metadata2.screenshot || metadata2;
          const png = image._png;
          if (png) {
            delete image._png;
            return [metadata2, png];
          }
          return metadata2;
        } catch (error) {
          return { agent_error: error instanceof Error ? error.message : String(error), code: "AGENT_ERROR", _expired_leases: takeExpiredLeases() };
        }
      });
    } catch (error) {
      return { agent_error: error instanceof Error ? error.message : String(error), code: "AGENT_ERROR" };
    }
  }
};
