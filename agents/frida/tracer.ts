import ObjC from "frida-objc-bridge";
import { Args, imageFor, methodFor, state } from "./common.js";

type HookState = { id: string; args: Args; listener: InvocationListener; calls: number; emitted: number; enabled: boolean };
const hooks = new Map<string, HookState>();
let serial = 0;

function scalar(value: NativePointer, type: string): Args {
  if (["bool", "char", "uchar", "short", "ushort", "int", "uint"].includes(type)) return { type, value: value.toInt32(), observed: true };
  return { type, address: value.toString(), decoded: false };
}

export function hookMethod(args: Args): Args {
  if (hooks.size >= 128) throw new Error("Hook limit reached");
  const method = methodFor(args), id = `${state.session}:hook_${++serial}`;
  const hook: HookState = { id, args, listener: null as any, calls: 0, emitted: 0, enabled: true };
  const limit = args.max_events || 1000;
  const listener = Interceptor.attach(method.implementation, {
    onEnter(callArgs) {
      this.capture = false;
      if (!hook.enabled) return;
      // Inherited methods may share an IMP across many classes: filter the actual receiver/selector.
      try {
        const receiver = new ObjC.Object(callArgs[0]);
        const matches = args.class_method ? receiver.isSubclassOfClass_(ObjC.classes[args.class_name]) : receiver.isKindOfClass_(ObjC.classes[args.class_name]);
        if (!matches || ObjC.selectorAsString(callArgs[1]) !== args.selector) return;
      } catch (_) { return; }
      hook.calls++;
      if (hook.emitted >= limit) return;
      this.capture = true;
      this.invocation = hook.calls;
      const event: Args = { type: "method_enter", hook_id: id, invocation: hook.calls,
        timestamp_ms: Date.now(), thread_id: this.threadId, class_name: args.class_name, selector: args.selector };
      if (args.capture_arguments) event.arguments = method.argumentTypes.slice(2, 10).map((type, i) => scalar(callArgs[i + 2], type));
      if (args.backtrace) event.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 32).map(address => ({ address: address.toString(), symbol: DebugSymbol.fromAddress(address).toString(), image: imageFor(address) }));
      hook.emitted++; send(event);
    },
    onLeave(value) {
      if (!this.capture || hook.emitted >= limit) return;
      const event: Args = { type: "method_leave", hook_id: id, invocation: this.invocation, timestamp_ms: Date.now(), thread_id: this.threadId };
      if (args.capture_return && method.returnType !== "void") event.return_value = scalar(value, method.returnType);
      hook.emitted++; send(event);
    },
  });
  hook.listener = listener; hooks.set(id, hook);
  return { hook_id: id, implementation: method.implementation.toString(), observed: true, capture_policy: "scalars and addresses only; never dereference object arguments" };
}

export function unhook(args: Args): Args {
  const hook = hooks.get(args.hook_id);
  if (!hook) throw new Error("Unknown hook in this process session");
  hook.listener.detach(); hooks.delete(hook.id);
  return { hook_id: hook.id, removed: true, calls: hook.calls };
}

export function enable(args: Args): Args {
  const hook = hooks.get(args.hook_id);
  if (!hook) throw new Error("Unknown hook in this process session");
  hook.enabled = !!args.enabled;
  return { hook_id: hook.id, enabled: hook.enabled };
}

export function listHooks(): Args {
  return { hooks: Array.from(hooks.values()).map(hook => ({ hook_id: hook.id, class_name: hook.args.class_name,
    selector: hook.args.selector, enabled: hook.enabled, calls: hook.calls, emitted: hook.emitted,
    buffer_limit_reached: hook.emitted >= (hook.args.max_events || 1000) })) };
}

export function dispose(): void { for (const hook of hooks.values()) hook.listener.detach(); hooks.clear(); }
