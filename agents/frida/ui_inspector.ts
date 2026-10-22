import ObjC from "frida-objc-bridge";
import { Args, array, nullableString, objectFor, objectId } from "./common.js";

function rect(value: any): Args {
  if (Array.isArray(value)) return { x: Number(value[0][0]), y: Number(value[0][1]), width: Number(value[1][0]), height: Number(value[1][1]) };
  return { x: Number(value.origin.x), y: Number(value.origin.y), width: Number(value.size.width), height: Number(value.size.height) };
}

function isKind(object: ObjC.Object, name: string): boolean {
  return !!ObjC.classes[name] && !!object.isKindOfClass_(ObjC.classes[name]);
}

function viewFor(id: string): ObjC.Object {
  const object = objectFor(id);
  if (!isKind(object, "UIView")) throw new Error("Object is not a UIView");
  return object;
}

function controller(view: ObjC.Object): Args | null {
  let responder = view.nextResponder();
  for (let i = 0; i < 64 && responder && !responder.handle.isNull(); i++) {
    if (isKind(responder, "UIViewController")) return { object_id: objectId(responder), class_name: responder.$className, observed: true, basis: "nextResponder chain" };
    responder = responder.nextResponder();
  }
  return null;
}

function text(view: ObjC.Object): string | null {
  if (view.respondsToSelector_(ObjC.selector("isSecureTextEntry")) && view.isSecureTextEntry()) return "[REDACTED]";
  const identifier = nullableString(view.accessibilityIdentifier()) || "";
  if (/password|passwd|secret|token|credential|private.?key/i.test(identifier)) return "[REDACTED]";
  if (isKind(view, "UIButton")) return nullableString(view.currentTitle());
  if (isKind(view, "UILabel") || isKind(view, "UITextField") || isKind(view, "UITextView")) return nullableString(view.text());
  return null;
}

export function windows(): Args {
  const app = ObjC.classes.UIApplication?.sharedApplication();
  if (!app) throw new Error("UIKit is unavailable in this process");
  const found = new Map<string, ObjC.Object>(), scenes: Args[] = [];
  if (app.respondsToSelector_(ObjC.selector("connectedScenes"))) {
    for (const scene of array(app.connectedScenes().allObjects(), 100)) {
      const sceneId = nullableString(scene.session().persistentIdentifier());
      const sceneInfo: Args = { scene_id: sceneId, activation_state: Number(scene.activationState()), class_name: scene.$className, windows: [] };
      if (scene.respondsToSelector_(ObjC.selector("windows"))) {
        for (const window of array(scene.windows(), 100)) { found.set(window.handle.toString(), window); sceneInfo.windows.push(objectId(window)); }
      }
      scenes.push(sceneInfo);
    }
  }
  for (const window of array(app.windows(), 100)) found.set(window.handle.toString(), window);
  const values = Array.from(found.values()).map(window => ({ view_id: objectId(window), class_name: window.$className,
    key_window: !!window.isKeyWindow(), hidden: !!window.isHidden(), alpha: Number(window.alpha()),
    frame: rect(window.frame()), window_level: Number(window.windowLevel()),
    root_controller: window.rootViewController()?.$className || null, observed: true }));
  return { windows: values, scenes, observed: true };
}

export function targets(view: ObjC.Object): Args[] {
  if (!isKind(view, "UIControl")) return [];
  const result: Args[] = [];
  const events = [1, 2, 4, 8, 16, 32, 64, 128, 256, 4096, 8192, 65536, 131072, 262144, 524288];
  for (const target of array(view.allTargets().allObjects(), 32)) {
    for (const event of events) {
      for (const selector of array(view.actionsForTarget_forControlEvent_(target, event), 32)) {
        result.push({ target_id: objectId(target), target_class: target.$className, selector: String(selector), control_event: event, observed: true });
        if (result.length >= 128) return result;
      }
    }
  }
  return result;
}

function describe(view: ObjC.Object, includeText: boolean, detailed = false): Args {
  const owner = controller(view);
  const result: Args = { view_id: objectId(view), class_name: view.$className, frame: rect(view.frame()), bounds: rect(view.bounds()),
    is_button: isKind(view, "UIButton"),
    hidden: !!view.isHidden(), alpha: Number(view.alpha()), user_interaction_enabled: !!view.isUserInteractionEnabled(),
    accessibility_identifier: nullableString(view.accessibilityIdentifier()), controller: owner, observed: true };
  if (includeText) result.text = text(view);
  if (detailed) {
    const superview = view.superview();
    result.superview_id = objectId(superview);
    result.subviews = array(view.subviews(), 500).map(objectId);
    result.translates_autoresizing_mask = !!view.translatesAutoresizingMaskIntoConstraints();
    result.targets = targets(view);
  }
  return result;
}

export function snapshot(args: Args): Args {
  const windowInfo = windows();
  const roots: ObjC.Object[] = args.root_view_id ? [viewFor(args.root_view_id)] : windowInfo.windows.map((w: Args) => objectFor(w.view_id));
  const queue = roots.map(view => ({ view, depth: 0, parent_id: null as string | null }));
  const nodes: Args[] = [], visited = new Set<string>();
  const depthLimit = args.depth ?? 8, maximum = args.max_nodes ?? 1000;
  let depthTruncated = false;
  for (let index = 0; index < queue.length && nodes.length < maximum; index++) {
    const { view, depth, parent_id } = queue[index];
    if (visited.has(view.handle.toString())) continue;
    visited.add(view.handle.toString());
    const description = describe(view, !!args.include_text);
    nodes.push({ ...description, parent_id, depth });
    const children = array(view.subviews(), maximum);
    if (depth < depthLimit) for (const child of children) {
      if (queue.length >= maximum * 2) { depthTruncated = true; break; }
      queue.push({ view: child, depth: depth + 1, parent_id: description.view_id });
    } else if (children.length) depthTruncated = true;
  }
  const offset = args.offset || 0, limit = args.limit || 100;
  return { ...windowInfo, views: nodes.slice(offset, offset + limit), total_visited: nodes.length,
    next_offset: offset + limit < nodes.length ? offset + limit : null,
    truncated: depthTruncated || queue.length > nodes.length, session_scoped: true, observed: true };
}

export function inspectView(args: Args): Args { return describe(viewFor(args.view_id), !!args.include_text, true); }

export function constraints(args: Args): Args {
  const view = viewFor(args.view_id);
  const constraints = array(view.constraints(), 1000);
  const offset = args.offset || 0, limit = args.limit || 100;
  return { constraints: constraints.slice(offset, offset + limit).map(item => ({
    object_id: objectId(item), identifier: nullableString(item.identifier()),
    first_item: objectId(item.firstItem()), second_item: objectId(item.secondItem()),
    first_attribute: Number(item.firstAttribute()), second_attribute: Number(item.secondAttribute()),
    relation: Number(item.relation()), multiplier: Number(item.multiplier()), constant: Number(item.constant()),
    priority: Number(item.priority()), active: !!item.isActive(), observed: true,
  })), total: constraints.length, next_offset: offset + limit < constraints.length ? offset + limit : null };
}

export function responders(args: Args): Args {
  let current = viewFor(args.view_id);
  const result: Args[] = [], visited = new Set<string>();
  while (current && !current.handle.isNull() && result.length < 64 && !visited.has(current.handle.toString())) {
    visited.add(current.handle.toString());
    result.push({ object_id: objectId(current), class_name: current.$className, observed: true });
    current = current.nextResponder();
  }
  return { responders: result, truncated: result.length >= 64 };
}

export function hitTest(args: Args): Args {
  const available = windows().windows;
  const selected = args.window_id ? available.find((item: Args) => item.view_id === args.window_id) : available.find((item: Args) => item.key_window);
  if (!selected) throw new Error("Select an observed window; no unique key window is available");
  const window = viewFor(selected.view_id);
  const hit = window.hitTest_withEvent_([args.x, args.y], NULL);
  return { coordinate_space: "window bounds in UIKit points", window_id: selected.view_id,
    hit: hit == null ? null : describe(hit, !!args.include_text, true), observed: true };
}

export function findViews(args: Args): Args {
  const all = snapshot({ ...args, offset: 0, limit: args.max_nodes || 1000, include_text: !!args.include_text || args.text != null });
  const query = String(args.text || "").toLowerCase();
  const results = all.views.filter((view: Args) =>
    (!args.class_name || view.class_name === args.class_name) &&
    (!args.accessibility_identifier || view.accessibility_identifier === args.accessibility_identifier) &&
    (!query || String(view.text || "").toLowerCase().includes(query)) &&
    (args.hidden == null || view.hidden === args.hidden) &&
    (args.user_interaction_enabled == null || view.user_interaction_enabled === args.user_interaction_enabled));
  const offset = args.offset || 0, limit = args.limit || 100;
  return { views: results.slice(offset, offset + limit), total: results.length,
    next_offset: offset + limit < results.length ? offset + limit : null, truncated: all.truncated, observed: true };
}

export function screenshot(args: Args): Args {
  const available = windows().windows;
  const selected = args.window_id ? available.find((item: Args) => item.view_id === args.window_id) : available.find((item: Args) => item.key_window);
  if (!selected) throw new Error("A window must be selected for a screenshot");
  const window = viewFor(selected.view_id);
  const size = window.bounds()[1];
  if (Number(size[0]) * Number(size[1]) > 4000000) throw new Error("Window exceeds screenshot size limit");
  const renderer = ObjC.classes.UIGraphicsImageRenderer.alloc().initWithSize_(size);
  try {
    const block = new ObjC.Block({ retType: "void", argTypes: ["object"], implementation() { window.drawViewHierarchyInRect_afterScreenUpdates_(window.bounds(), true); } });
    const image = renderer.imageWithActions_(block);
    const png = new NativeFunction(Module.getGlobalExportByName("UIImagePNGRepresentation"), "pointer", ["pointer"])(image.handle);
    const data = new ObjC.Object(png);
    if (Number(data.length()) > 8388608) throw new Error("PNG exceeds screenshot size limit");
    return { mime_type: "image/png", base64: String(data.base64EncodedStringWithOptions_(0)), window_id: selected.view_id, observed: true };
  } finally { renderer.release(); }
}
