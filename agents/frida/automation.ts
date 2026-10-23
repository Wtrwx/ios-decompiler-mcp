import ObjC from "frida-objc-bridge";
import { Args, array, finishObjectLease, main, objectFor, objectId, state, withObjectLease } from "./common.js";
import * as ui from "./ui_inspector.js";

function kind(value: any, name: string): boolean {
  return !!value && !value.handle.isNull() && !!ObjC.classes[name] && !!value.isKindOfClass_(ObjC.classes[name]);
}
function present(value: any): boolean { return !!value && !value.handle.isNull(); }
function windowFor(args: Args): ObjC.Object {
  const windows = ui.windows().windows;
  const item = args.window_id ? windows.find((w: Args) => w.view_id === args.window_id) : windows.find((w: Args) => w.key_window);
  if (!item) throw new Error("Select an observed window; no key window is available");
  return objectFor(item.view_id);
}
function actionable(view: ObjC.Object, interaction = true): void {
  if (!kind(view, "UIView") || !present(view.window())) throw new Error("Target is not an attached UIView");
  const box = view.convertRect_toView_(view.bounds(), view.window()), bounds = view.window().bounds();
  if (Number(box[1][0]) <= 0 || Number(box[1][1]) <= 0 || Number(box[0][0]) + Number(box[1][0]) <= Number(bounds[0][0]) ||
      Number(box[0][1]) + Number(box[1][1]) <= Number(bounds[0][1]) || Number(box[0][0]) >= Number(bounds[0][0]) + Number(bounds[1][0]) ||
      Number(box[0][1]) >= Number(bounds[0][1]) + Number(bounds[1][1])) throw new Error("Target is outside the window bounds");
  let current: any = view, alpha = 1;
  for (let i = 0; i < 128 && present(current); i++, current = current.superview()) {
    alpha *= Number(current.alpha());
    if (current.isHidden() || alpha <= .01 || (interaction && !current.isUserInteractionEnabled())) throw new Error("Target or an ancestor is hidden, transparent or disabled");
  }
  if (interaction && kind(view, "UIControl") && !view.isEnabled()) throw new Error("Control is disabled");
}
function resolve(target: Args, allowMissing = false, interaction = true): ObjC.Object | null {
  if (target.view_id) {
    const view = objectFor(target.view_id);
    try { actionable(view, interaction); }
    catch (error) { if (allowMissing) return null; throw error; }
    return view;
  }
  if (target.x != null) {
    const view = windowFor(target).hitTest_withEvent_([target.x, target.y], NULL);
    if (!present(view)) { if (allowMissing) return null; throw new Error("No view at the requested window point"); }
    actionable(view, interaction); return view;
  }
  const found = ui.snapshot({ ...target, format: "summary", fields: ["view_id"], controls_only: false,
    visible_only: true, include_text: false, max_nodes: target.max_nodes || 1000, depth: 30 }).views;
  if (!found.length && allowMissing) return null;
  const index = target.match_index;
  if (!found.length) throw new Error("No visible view matches the target");
  if (index == null && found.length !== 1) throw new Error("Target is ambiguous; select view_id or match_index");
  if (!found[index ?? 0]) throw new Error("match_index exceeds the observed matches");
  const view = objectFor(found[index ?? 0].view_id); actionable(view, interaction); return view;
}

// These are UIKit semantic operations. They do not synthesize private UITouch/
// HID events, so arbitrary gesture recognizers are deliberately unsupported.
export function step(args: Args): Args {
  if (state.disposing) throw new Error("Process session is disposing; remaining actions were cancelled");
  const action = args.action;
  if (action === "back") {
    const window = windowFor(args), seen = new Set<string>();
    let current: any = window.rootViewController();
    while (present(current) && seen.size < 64 && !seen.has(current.handle.toString())) {
      seen.add(current.handle.toString());
      const next = current.presentedViewController();
      if (present(next)) { current = next; continue; }
      if (kind(current, "UINavigationController")) { current = current.visibleViewController(); continue; }
      if (kind(current, "UITabBarController")) { current = current.selectedViewController(); continue; }
      break;
    }
    if (!present(current)) throw new Error("No visible controller is available");
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
  if (!view) return { action, matched: false };
  const viewId = objectId(view);
  if (action === "assert" || action === "wait_for") return { action, matched: true, view_id: viewId };
  if (action === "tap") {
    for (let i = 0; i < 32 && present(view); i++, view = view!.superview()) {
      // A gesture-only control can reach its window without finding an action.
      // UIWindow.window may be nil; it is the traversal boundary, not a target.
      if (kind(view, "UIWindow")) break;
      actionable(view!, false);
      if (kind(view, "UISwitch")) {
        actionable(view!);
        view!.setOn_(!view!.isOn()); view!.sendActionsForControlEvents_(4096);
        return { action, method: "switch_value_changed", view_id: objectId(view), performed: true };
      }
      if (kind(view, "UIControl")) {
        actionable(view!);
        const events = Number(view!.allControlEvents());
        const event = args.event === "primary_action" ? 8192 : args.event === "touch_up_inside" ? 64 : (events & 64) ? 64 : (events & 8192) ? 8192 : 0;
        if (event) {
          view!.sendActionsForControlEvents_(event);
          return { action, method: "control_event", control_event: event, view_id: objectId(view), performed: true };
        }
      }
      if (view!.isUserInteractionEnabled() && view!.respondsToSelector_(ObjC.selector("accessibilityActivate")) && view!.accessibilityActivate()) {
        return { action, method: "accessibility_activate", view_id: objectId(view), performed: true };
      }
    }
    throw new Error("This view requires physical touch/gesture injection; no UIKit control action or accessibility activation is available");
  }
  if (action === "input_text") {
    if (!kind(view, "UITextField") && !kind(view, "UITextView")) throw new Error("Text input requires UITextField or UITextView");
    if (args.focus) view!.becomeFirstResponder();
    view!.setText_(args.text);
    if (kind(view, "UIControl")) view!.sendActionsForControlEvents_(262144);
    else ObjC.classes.NSNotificationCenter.defaultCenter().postNotificationName_object_("UITextViewTextDidChangeNotification", view);
    return { action, view_id: viewId, characters: args.text.length, performed: true };
  }
  if (action === "scroll") {
    while (present(view) && !kind(view, "UIScrollView")) view = view!.superview();
    if (!present(view)) throw new Error("Target has no UIScrollView ancestor");
    const offset = view!.contentOffset(), size = view!.contentSize(), bounds = view!.bounds()[1];
    const inset = view!.adjustedContentInset();
    const top = Number(inset[0]), left = Number(inset[1]), bottom = Number(inset[2]), right = Number(inset[3]);
    // Derive a feed page on-device so callers need neither a viewport query nor
    // device-specific pixel/Tab Bar assumptions. A page is the scroll viewport.
    const dy = args.pages == null ? (args.dy ?? 0) : Number(bounds[1]) * args.pages;
    const x = Math.max(-left, Math.min(Math.max(-left, Number(size[0]) - Number(bounds[0]) + right), Number(offset[0]) + (args.dx ?? 0)));
    const y = Math.max(-top, Math.min(Math.max(-top, Number(size[1]) - Number(bounds[1]) + bottom), Number(offset[1]) + dy));
    if (x === Number(offset[0]) && y === Number(offset[1])) {
      return { action, view_id: objectId(view), content_offset: { x, y }, performed: false,
        at_boundary: dy !== 0 || (args.dx ?? 0) !== 0 };
    }
    view!.setContentOffset_animated_([x, y], !!args.animated);
    return { action, view_id: objectId(view), content_offset: { x, y }, performed: true };
  }
  throw new Error("Unsupported automation action");
}

export async function run(args: Args): Promise<Args> {
  const lease = { ...args, _hold_lease: true,
    _input_handles: args.steps.flatMap((s: Args) => [s.target?.view_id, s.target?.window_id, s.window_id]).filter(Boolean) };
  const results: Args[] = [];
  const started = Date.now();
  await main(() => withObjectLease(lease, () => null));
  try {
    for (const item of args.steps) {
      const begin = Date.now();
      try {
        let result: Args;
        do {
          result = await main(() => withObjectLease(lease, () => step(item)));
          if (item.action !== "wait_for" || result.matched || Date.now() - begin >= item.timeout_ms) break;
          await new Promise(resolve => setTimeout(resolve, Math.min(item.poll_ms, item.timeout_ms - (Date.now() - begin))));
        } while (!state.disposing);
        if (state.disposing) throw new Error("Process session is disposing; remaining actions were cancelled");
        if (item.action === "wait_for" && !result.matched) throw new Error("Timed out waiting for a visible matching view");
        results.push({ ...result, elapsed_ms: Date.now() - begin });
        if (args.settle_ms) await new Promise(resolve => setTimeout(resolve, args.settle_ms));
      } catch (error) {
        results.push({ action: item.action, performed: false, error: error instanceof Error ? error.message : String(error), elapsed_ms: Date.now() - begin });
        break; // Never retry a mutation whose outcome may be uncertain.
      }
    }
    const capture = args.after_capture !== "none" && !state.disposing ?
      await main(() => withObjectLease(lease, () => ui.capture({ ...args, mode: args.after_capture }))) : {};
    return { steps: results, completed: results.length === args.steps.length && !results.some(s => s.error),
      elapsed_ms: Date.now() - started, ...capture };
  } finally {
    await main(() => finishObjectLease(args._lease_id, args._lease_ttl));
  }
}
