import ObjC from "frida-objc-bridge";
import { Args, imageFor, main, releaseObjects, requireRuntime, state } from "./common.js";
import * as runtime from "./objc_runtime.js";
import * as ui from "./ui_inspector.js";
import * as tracer from "./tracer.js";

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
  search_classes: runtime.searchClasses,
  dump_class: runtime.dumpClass,
  get_methods: runtime.methods,
  get_properties: runtime.properties,
  get_ivars: runtime.ivars,
  inspect_object: runtime.inspectObject,
  get_method_implementation: runtime.implementation,
  find_instances: runtime.findInstances,
};

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
          return { bundle_id: bundle, pid: Process.id, architecture: Process.arch,
            executable: String(ObjC.classes.NSBundle.mainBundle().executablePath()), observed: true };
        });
      }
      if (!state.session) throw new Error("Initialize the process session first");
      if (name === "identity") return await main(() => ({ bundle_id: state.bundle, pid: Process.id, main_image: imageFor(Process.mainModule.base), executable: String(ObjC.classes.NSBundle.mainBundle().executablePath()), observed: true }));
      if (name === "tweak_state") {
        const module = Process.findModuleByName(args.module_name);
        if (!module) return { loaded: false, observed: true };
        const marker = module.findExportByName("IOSDecompilerMCPBuildID");
        const count = module.findExportByName("IOSDecompilerMCPInvocationCount");
        let buildMarker = "";
        if (marker) for (let i = 0; i < 80; i++) { const byte = marker.add(i).readU8(); if (!byte) break; if (byte > 127) throw new Error("Invalid build marker"); buildMarker += String.fromCharCode(byte); }
        return { loaded: true, path: module.path, build_marker: marker ? buildMarker : null,
          invocation_count: count ? Number(count.readU64().toString()) : 0, observed: true };
      }
      if (name === "dispose") return await main(() => { tracer.dispose(); releaseObjects(); return { disposed: true }; });
      if (!methods[name]) throw new Error(`Unknown inspection RPC: ${name}`);
      return await main(() => methods[name](args));
    } catch (error) {
      return { agent_error: error instanceof Error ? error.message : String(error), code: "AGENT_ERROR" };
    }
  },
};
