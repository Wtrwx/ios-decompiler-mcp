import ObjC from "frida-objc-bridge";
import { Args, array, nullableString, objectFor, objectId, ObjectLimitError } from "./common.js";

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

function controller(view: ObjC.Object, cache = new Map<string, Args | null>()): Args | null {
  const path: string[] = [view.handle.toString()];
  let responder = view.nextResponder();
  for (let i = 0; i < 64 && responder && !responder.handle.isNull(); i++) {
    const key = responder.handle.toString();
    let owner: Args | null | undefined = cache.get(key);
    if (owner === undefined && isKind(responder, "UIViewController")) owner = { object_id: objectId(responder), class_name: responder.$className, observed: true, basis: "nextResponder chain" };
    if (owner !== undefined) { for (const id of path) cache.set(id, owner); return owner; }
    path.push(key);
    responder = responder.nextResponder();
  }
  for (const id of path) cache.set(id, null);
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

function screenFrame(view: ObjC.Object): Args {
  return rect(view.convertRect_toView_(view.bounds(), view.window()));
}

function ancestry(view: ObjC.Object): Args {
  let current = view.superview(), hidden = false, alpha = 1, interaction = true;
  for (let i = 0; i < 128 && current && !current.handle.isNull(); i++) {
    hidden ||= !!current.isHidden(); alpha *= Number(current.alpha());
    interaction &&= !!current.isUserInteractionEnabled(); current = current.superview();
  }
  return { hidden, alpha, interaction };
}

function interactive(view: ObjC.Object): boolean {
  if (!view.isUserInteractionEnabled()) return false;
  if (isKind(view, "UIControl") || Number(view.gestureRecognizers()?.count() || 0) > 0 || !!view.isAccessibilityElement()) return true;
  // Custom UIView touch handlers need not inherit UIButton or UIControl.
  const klass = ObjC.classes[view.$className];
  return ["touchesBegan:withEvent:", "touchesEnded:withEvent:", "hitTest:withEvent:"].some(selector => {
    const method = klass["- " + selector], base = ObjC.classes.UIView["- " + selector];
    return method && base && !method.implementation.equals(base.implementation);
  });
}

const summaryFields = ["view_id", "class_name", "frame", "screen_frame", "parent_id", "depth", "interactive", "accessibility_identifier"];
const detailFields = [...summaryFields, "bounds", "is_button", "hidden", "alpha", "effective_alpha", "visible", "user_interaction_enabled", "controller", "observed"];

function describe(view: ObjC.Object, includeText: boolean, detailed = false, fields?: string[], owners = new Map<string, Args | null>(), visibility?: Args): Args {
  const selected = new Set(fields || (detailed ? [...detailFields, "superview_id", "subviews", "translates_autoresizing_mask", "targets"] : summaryFields));
  const result: Args = { view_id: objectId(view), class_name: view.$className };
  if (selected.has("frame")) result.frame = rect(view.frame());
  if (selected.has("screen_frame")) result.screen_frame = screenFrame(view);
  if (selected.has("bounds")) result.bounds = rect(view.bounds());
  if (selected.has("is_button")) result.is_button = isKind(view, "UIButton");
  if (selected.has("hidden")) result.hidden = !!view.isHidden();
  if (selected.has("alpha")) result.alpha = Number(view.alpha());
  if (selected.has("effective_alpha")) result.effective_alpha = visibility?.alpha ?? ancestry(view).alpha * Number(view.alpha());
  if (selected.has("visible")) {
    const ancestors = visibility || ancestry(view);
    result.visible = !(ancestors.hidden || view.isHidden()) && Number(view.alpha()) * (visibility ? 1 : ancestors.alpha) > .01 && (visibility ? visibility.visible : true);
  }
  if (selected.has("user_interaction_enabled")) result.user_interaction_enabled = !!view.isUserInteractionEnabled();
  if (selected.has("interactive")) result.interactive = interactive(view) && (visibility?.interaction ?? ancestry(view).interaction);
  if (selected.has("accessibility_identifier")) result.accessibility_identifier = nullableString(view.accessibilityIdentifier());
  if (selected.has("controller")) result.controller = controller(view, owners);
  if (selected.has("observed")) result.observed = true;
  if (includeText && (!fields || selected.has("text"))) result.text = text(view);
  if (selected.has("superview_id")) result.superview_id = objectId(view.superview());
  if (selected.has("subviews")) result.subviews = array(view.subviews(), 500).map(objectId);
  if (selected.has("translates_autoresizing_mask")) result.translates_autoresizing_mask = !!view.translatesAutoresizingMaskIntoConstraints();
  if (selected.has("targets")) result.targets = targets(view);
  return result;
}

export function snapshot(args: Args, windowInfo = windows()): Args {
  const started = Date.now();
  const roots: ObjC.Object[] = args.root_view_id ? [viewFor(args.root_view_id)] : windowInfo.windows.map((w: Args) => objectFor(w.view_id));
  const queue = roots.map(view => ({ view, depth: 0, parent_id: null as string | null, ancestors: ancestry(view) }));
  const nodes: Args[] = [], visited = new Set<string>(), owners = new Map<string, Args | null>();
  const depthLimit = args.depth ?? 8, maximum = args.max_nodes ?? 1000;
  const detail = args.format === "detail", visibleOnly = args.visible_only ?? true, controlsOnly = args.controls_only ?? true;
  const fields: string[] = args.fields || [...(detail ? detailFields : summaryFields), ...(args.include_text ? ["text"] : [])];
  let truncated = false, index = 0, objectLimit = false;
  for (; index < queue.length && visited.size < maximum; index++) {
    const { view, depth, parent_id, ancestors } = queue[index];
    if (visited.has(view.handle.toString())) continue;
    visited.add(view.handle.toString());
    const hidden = ancestors.hidden || !!view.isHidden(), alpha = ancestors.alpha * Number(view.alpha());
    const box = screenFrame(view), window = view.window();
    const windowBox = window && !window.handle.isNull() ? rect(window.bounds()) : null;
    const visible = !hidden && alpha > .01 && box.width > 0 && box.height > 0 && !!windowBox &&
      box.x < windowBox.x + windowBox.width && box.y < windowBox.y + windowBox.height && box.x + box.width > windowBox.x && box.y + box.height > windowBox.y;
    if (visibleOnly && (hidden || alpha <= .01)) continue; // The entire subtree is invisible.
    const isInteractive = ancestors.interaction && interactive(view);
    const isContent = isInteractive || isKind(view, "UILabel") || isKind(view, "UITextView") || !!view.isAccessibilityElement();
    const matches = (!args.class_name || view.$className === args.class_name) &&
      (!args.accessibility_identifier || nullableString(view.accessibilityIdentifier()) === args.accessibility_identifier) &&
      (args.hidden == null || !!view.isHidden() === args.hidden) &&
      (args.user_interaction_enabled == null || !!view.isUserInteractionEnabled() === args.user_interaction_enabled) &&
      (args.text == null || String(text(view) || "").toLowerCase().includes(String(args.text).toLowerCase()));
    let selectedParent = parent_id;
    if (matches && (!visibleOnly || visible) && (!controlsOnly || isContent)) {
      try {
        const description = describe(view, !!args.include_text, false, fields, owners, { hidden, alpha, interaction: ancestors.interaction, visible });
        if (fields.includes("parent_id")) description.parent_id = parent_id;
        if (fields.includes("depth")) description.depth = depth;
        nodes.push(description); selectedParent = description.view_id;
      } catch (error) {
        if (!(error instanceof ObjectLimitError)) throw error;
        objectLimit = true; break;
      }
    }
    const children = array(view.subviews(), maximum + 1);
    if (depth < depthLimit) for (const child of children) {
      if (queue.length >= maximum * 2) { truncated = true; break; }
      queue.push({ view: child, depth: depth + 1, parent_id: selectedParent,
        ancestors: { hidden, alpha, interaction: ancestors.interaction && !!view.isUserInteractionEnabled() } });
    } else if (children.length) truncated = true;
  }
  // Return the full bounded capture once. The host pages its immutable copy.
  return { ...(detail ? windowInfo : {}), views: nodes, total_visited: visited.size,
    captured_at: new Date(started).toISOString(), collection_ms: Date.now() - started,
    truncated: truncated || index < queue.length, object_limit_reached: objectLimit,
    coordinate_space: "screen_frame is in window UIKit points; frame is in superview points", session_scoped: true, observed: true };
}

export function inspectView(args: Args): Args { return describe(viewFor(args.view_id), !!args.include_text, true, args.fields); }

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
  return snapshot({ ...args, format: args.format || "detail", controls_only: args.controls_only ?? false,
    visible_only: args.visible_only ?? false, include_text: !!args.include_text });
}

export function screenshot(args: Args, available = windows().windows): Args {
  const started = Date.now();
  const selected = args.window_id ? available.find((item: Args) => item.view_id === args.window_id) : available.find((item: Args) => item.key_window);
  if (!selected) throw new Error("A window must be selected for a screenshot");
  const window = viewFor(selected.view_id);
  const size = window.bounds()[1];
  if (Number(size[0]) * Number(size[1]) > 4000000) throw new Error("Window exceeds screenshot size limit");
  const renderer = ObjC.classes.UIGraphicsImageRenderer.alloc().initWithSize_(size);
  try {
    const block = new ObjC.Block({ retType: "void", argTypes: ["object"], implementation() { window.drawViewHierarchyInRect_afterScreenUpdates_(window.bounds(), true); } });
    const image = renderer.imageWithActions_(block);
    const rendered = Date.now();
    const png = new NativeFunction(Module.getGlobalExportByName("UIImagePNGRepresentation"), "pointer", ["pointer"])(image.handle);
    const data = new ObjC.Object(png);
    if (Number(data.length()) > 8388608) throw new Error("PNG exceeds screenshot size limit");
    const encoded = Date.now();
    const binary = args._image_transport !== "base64";
    const payload = binary ? { _png: data.bytes().readByteArray(Number(data.length())) } : { base64: String(data.base64EncodedStringWithOptions_(0)) };
    return { mime_type: "image/png", ...payload, frida_transport: binary ? "binary" : "base64", window_id: selected.view_id, observed: true,
      width_points: Number(size[0]), height_points: Number(size[1]), scale: Number(image.scale()),
      timings_ms: { render: rendered - started, png_encode: encoded - rendered, payload_prepare: Date.now() - encoded } };
  } finally { renderer.release(); }
}

// One main-queue operation; screenshots are produced only for explicit modes.
export function capture(args: Args): Args {
  const result: Args = {}, windowInfo = windows();
  if (args.mode === "summary" || args.mode === "both") result.summary = snapshot(args, windowInfo);
  if (args.mode === "screenshot" || args.mode === "both") result.screenshot = screenshot(args, windowInfo.windows);
  return result;
}
