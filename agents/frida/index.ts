import ObjC from "frida-objc-bridge";
import { Args, expireLeases, imageFor, main, objectStats, releaseObjects, requireRuntime, state, takeExpiredLeases, withObjectLease } from "./common.js";
import * as runtime from "./objc_runtime.js";
import * as ui from "./ui_inspector.js";
import * as tracer from "./tracer.js";
import * as automation from "./automation.js";
import * as logging from "./logging.js";
import * as debuggerTools from "./debugger.js";
import * as decrypt from "./decrypt.js";

const methods: { [name: string]: (args: Args) => any } = {
  hook_method: tracer.hookMethod,
  unhook: tracer.unhook,
  list_hooks: tracer.listHooks,
  enable_hook: tracer.enable,
  windows: ui.windows,
  snapshot: ui.snapshot,
  inspect_view: ui.inspectView,
  constraints: ui.constraints,
  responders: ui.responders,
  hit_test: ui.hitTest,
  find_views: ui.findViews,
  screenshot: ui.screenshot,
  capture: ui.capture,
  release_leases: objectStats,
  search_classes: runtime.searchClasses,
  dump_class: runtime.dumpClass,
  get_methods: runtime.methods,
  get_properties: runtime.properties,
  get_ivars: runtime.ivars,
  inspect_object: runtime.inspectObject,
  get_method_implementation: runtime.implementation,
  find_instances: runtime.findInstances,
  inspect_objects: runtime.inspectObjects,
};

let leaseTimer: ReturnType<typeof setInterval> | null = null;
let sweepPending = false;

rpc.exports = {
  async dispatch(name: string, args: Args) {
    try {
      requireRuntime();
      if (name === "initialize") {
        if (state.session) throw new Error("Agent already initialized");
        return await main(() => {
          const bundle = String(ObjC.classes.NSBundle.mainBundle().bundleIdentifier());
          if (bundle !== args.bundle_id) throw new Error("Application bundle identity mismatch");
          state.session = args.session_id; state.bundle = bundle;
          leaseTimer = setInterval(() => {
            if (sweepPending) return;
            sweepPending = true;
            main(() => expireLeases()).catch(() => {}).finally(() => { sweepPending = false; });
          }, 1000);
          return { bundle_id: bundle, pid: Process.id, architecture: Process.arch,
            executable: String(ObjC.classes.NSBundle.mainBundle().executablePath()), observed: true };
        });
      }
      if (!state.session) throw new Error("Initialize the process session first");
      if (name === "app_logs") return await logging.run(args);
      if (name === "debug_inspect") return debuggerTools.inspect(args);
      if (name === "decrypt_modules") return decrypt.modules();
      if (name === "decrypt_module") return decrypt.dump(args);
      if (name === "automate") {
        const result = await automation.run(args);
        const metadata: Args = { ...result, _expired_leases: takeExpiredLeases() };
        const png = metadata.screenshot?._png;
        if (png) { delete metadata.screenshot._png; return [metadata, png]; }
        return metadata;
      }
      if (name === "identity") return await main(() => ({ bundle_id: state.bundle, pid: Process.id, main_image: imageFor(Process.mainModule.base), executable: String(ObjC.classes.NSBundle.mainBundle().executablePath()), observed: true }));
      if (name === "tweak_state") {
        const module = Process.findModuleByName(args.module_name);
        if (!module) return { loaded: false, observed: true };
        const marker = module.findExportByName("VesperBuildID");
        const count = module.findExportByName("VesperInvocationCount");
        let buildMarker = "";
        if (marker) for (let i = 0; i < 80; i++) { const byte = marker.add(i).readU8(); if (!byte) break; if (byte > 127) throw new Error("Invalid build marker"); buildMarker += String.fromCharCode(byte); }
        return { loaded: true, path: module.path, build_marker: marker ? buildMarker : null,
          invocation_count: count ? Number(count.readU64().toString()) : 0, observed: true };
      }
      if (name === "dispose") {
        state.disposing = true;
          return await main(() => { if (leaseTimer !== null) clearInterval(leaseTimer); leaseTimer = null; tracer.dispose(); logging.dispose(); releaseObjects(); return { disposed: true }; });
      }
      if (!methods[name]) throw new Error(`Unknown inspection RPC: ${name}`);
      const queuedAt = Date.now();
      return await main(() => {
        const started = Date.now();
        try {
          const result = withObjectLease(args, () => methods[name](args));
          const metadata = { ...result, _expired_leases: takeExpiredLeases() };
          if (name === "screenshot" || name === "capture") metadata._agent_timings_ms = { main_queue: started - queuedAt, execution: Date.now() - started };
          const image = metadata.screenshot || metadata;
          const png = image._png;
          if (png) {
            delete image._png;
            // Frida >=17.5 transports [JSON metadata, ArrayBuffer] as a binary
            // RPC result. PNG bytes/scale are identical; no device-side base64.
            return [metadata, png];
          }
          return metadata;
        }
        catch (error) { return { agent_error: error instanceof Error ? error.message : String(error), code: "AGENT_ERROR", _expired_leases: takeExpiredLeases() }; }
      });
    } catch (error) {
      return { agent_error: error instanceof Error ? error.message : String(error), code: "AGENT_ERROR" };
    }
  },
};
