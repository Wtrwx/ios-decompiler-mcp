/* Execute production TypeScript with a small ObjC boundary; no copied algorithms. */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const ts = require('typescript');

function runtime() {
  let serial = 0, responderReads = 0, textReads = 0, windowsReads = 0;
  const address = (value) => ({ toString: () => String(value), isNull: () => false, equals: other => other.toString() === String(value) });
  const collection = values => ({ count: () => values.length, objectAtIndex_: index => values[index] });
  const classes = {};
  for (const name of ['UIView', 'UIWindow', 'UIViewController', 'UIControl', 'UIButton', 'UILabel', 'UITextView', 'UITextField', 'CustomTouchView', 'NSObject', 'UISwitch', 'UIScrollView', 'UINavigationController', 'UITabBarController', 'NSString', 'NSNumber', 'NSArray', 'NSDictionary', 'NSData', 'NSNull']) {
    classes[name] = { name };
    for (const selector of ['touchesBegan:withEvent:', 'touchesEnded:withEvent:', 'hitTest:withEvent:']) {
      classes[name]['- ' + selector] = { implementation: address(name === 'CustomTouchView' ? 9 : 1) };
    }
  }
  const controller = { handle: address(++serial), $className: 'FixtureController', retain() { this.retains++; }, release() { this.releases++; }, retains: 0, releases: 0,
    isKindOfClass_: cls => cls.name === 'UIViewController', nextResponder: () => null,
    presentedViewController: () => null, navigationController: () => null, presentingViewController: () => null };
  function view(name, opts = {}) {
    const object = { handle: address(++serial), $className: name, children: [], parent: null, retains: 0, releases: 0,
      retain() { this.retains++; }, release() { this.releases++; },
      isKindOfClass_: cls => cls.name === name || cls.name === 'NSObject' || (cls.name === 'UIView' && name !== 'NSObject') || (cls.name === 'UIControl' && ['UIButton', 'UITextField', 'UISwitch'].includes(name)),
      $ivars: opts.ivars || {}, events: [], enteredText: null,
      frame: () => [[opts.x || 0, 0], [100, 30]], bounds: () => [[0, 0], [100, 30]],
      isHidden: () => !!opts.hidden, alpha: () => opts.alpha ?? 1,
      isUserInteractionEnabled: () => opts.interaction ?? name !== 'UILabel',
      isAccessibilityElement: () => !!opts.accessible,
      accessibilityIdentifier: () => opts.identifier || null,
      respondsToSelector_: selector => selector === 'accessibilityActivate' && !!opts.activate,
      accessibilityActivate: () => !!opts.activate,
      isEnabled: () => opts.enabled ?? true,
      allControlEvents: () => opts.events ?? 64,
      sendActionsForControlEvents_(event) { this.events.push(event); if (opts.onAction) opts.onAction(event); },
      setText_(value) { this.enteredText = value; },
      becomeFirstResponder: () => true,
      currentTitle: () => { textReads++; return opts.text || 'button'; },
      text: () => { textReads++; return opts.text || 'label'; },
      gestureRecognizers: () => collection(opts.gestures ? [1] : []),
      superview() { return this.parent; }, subviews() { return collection(this.children); },
      nextResponder() { responderReads++; return this.parent || controller; },
      window() { let current = this; while (current.parent) current = current.parent; return current.$className === 'UIWindow' ? current : null; },
      convertRect_toView_() { return this.frame(); },
      isKeyWindow: () => true, windowLevel: () => 0, rootViewController: () => controller,
      layoutIfNeeded: () => {},
    };
    return object;
  }
  const root = view('UIWindow');
  root.bounds = () => [[0, 0], [400, 800]];
  const add = (parent, child) => { child.parent = parent; parent.children.push(child); return child; };
  classes.UIApplication = { sharedApplication: () => ({ respondsToSelector_: () => false, windows: () => { windowsReads++; return collection([root]); } }) };
  const heap = [], chooseCalls = [];
  const objc = { available: true, classes, selector: s => s, mainQueue: 'main', schedule: (queue, fn) => { assert.equal(queue, 'main'); fn(); },
    choose(spec, callbacks) { chooseCalls.push(spec); for (const object of heap) { if (object.$className === spec.class.name && callbacks.onMatch(object) === 'stop') break; } callbacks.onComplete(); } };
  function load(file, mocks) {
    const source = fs.readFileSync(path.join(__dirname, '../agents/frida', file), 'utf8');
    const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
    const module = { exports: {} };
    new Function('require', 'module', 'exports', compiled)(name => {
      if (name === 'frida-objc-bridge') return { default: objc };
      if (mocks[name]) return mocks[name];
      throw Error('Unexpected import: ' + name);
    }, module, module.exports);
    return module.exports;
  }
  const common = load('common.ts', {});
  common.state.session = 'process_test';
  const ui = load('ui_inspector.ts', { './common.js': common });
  const automation = load('automation.ts', { './common.js': common, './ui_inspector.js': ui });
  const objcRuntime = load('objc_runtime.ts', { './common.js': common });
  global.NULL = null;
  return { common, ui, automation, objcRuntime, heap, chooseCalls, view, add, root, controller, reads: () => ({ responderReads, textReads, windowsReads }) };
}

function scope(r, id, fn, args = {}) { return r.common.withObjectLease({ _lease_id: id, _lease_ttl: 60, ...args }, fn); }

test('snapshot and operation references release once, with inputs protected before expiry', () => {
  const r = runtime(), obj = r.view('NSObject');
  const id = scope(r, 'snapshot_a', () => r.common.objectId(obj));
  scope(r, 'snapshot_b', () => assert.equal(r.common.objectId(obj), id));
  assert.equal(obj.retains, 1);
  r.common.releaseLease('snapshot_a');
  assert.equal(obj.releases, 0);
  scope(r, 'operation', () => {
    assert.equal(r.common.objectFor(id), obj);
    assert.equal(obj.releases, 0);
    // The currently executing operation cannot be evicted.
    r.common.releaseLease('operation');
    assert.equal(obj.releases, 0);
  }, { view_id: id, _release_leases: ['snapshot_b'] });
  assert.equal(obj.releases, 0);
  r.common.expireLeases(Date.now() + 61000);
  assert.equal(obj.releases, 1);
  assert.equal(r.common.objectStats().objects, 0);
  assert.throws(() => scope(r, 'stale', () => r.common.objectFor(id)), /Unknown/);
});

test('registry pressure evicts old snapshots while preserving the current operation and 2048 bound', () => {
  const r = runtime(), objects = Array.from({ length: 2048 }, () => r.view('NSObject'));
  scope(r, 'old_snapshot', () => objects.forEach(obj => r.common.objectId(obj)));
  assert.equal(r.common.objectStats().objects, 2048);
  const active = objects[0], id = r.common.state.byPointer.get(active.handle.toString());
  const fresh = r.view('NSObject');
  scope(r, 'new_snapshot', () => { r.common.objectId(fresh); assert.equal(active.releases, 0); }, { object_id: id });
  assert.equal(r.common.objectStats().objects, 2);
  assert.ok(r.common.takeExpiredLeases().includes('old_snapshot'));
  r.common.releaseLease('new_snapshot');
  assert.equal(fresh.releases, 1);
  assert.ok(objects.every(obj => obj.releases === 1));
  assert.equal(r.common.objectStats().objects, 0);
});

test('failed operations release their own retains and leave shared handles usable', () => {
  const r = runtime(), shared = r.view('NSObject'), fresh = r.view('NSObject');
  const id = scope(r, 'snapshot', () => r.common.objectId(shared));
  assert.throws(() => scope(r, 'failed', () => { r.common.objectFor(id); r.common.objectId(fresh); throw Error('failed'); }));
  assert.equal(fresh.releases, 1);
  assert.equal(shared.releases, 0);
  r.common.releaseObjects();
  assert.equal(shared.releases, 1);
});

test('visible summary excludes hidden/transparent ancestors and includes custom UIView interactions', () => {
  const r = runtime();
  const hidden = r.add(r.root, r.view('UIView', { hidden: true }));
  r.add(hidden, r.view('UIButton'));
  const alpha = r.add(r.root, r.view('UIView', { alpha: .005 }));
  r.add(alpha, r.view('UIButton'));
  const custom = r.add(r.root, r.view('CustomTouchView'));
  r.add(custom, r.view('UILabel'));
  r.add(r.root, r.view('UIView', { gestures: true }));
  r.add(r.root, r.view('UIButton', { x: 900 }));
  const result = scope(r, 'summary', () => r.ui.capture({ mode: 'summary' })).summary;
  assert.deepEqual(result.views.map(v => v.class_name), ['CustomTouchView', 'UIView', 'UILabel']);
  assert.equal(result.views[2].parent_id, result.views[0].view_id);
  assert.ok(!result.views.some(v => 'text' in v || 'controller' in v || 'targets' in v));
  assert.deepEqual(r.reads(), { textReads: 0, responderReads: 0, windowsReads: 1 });
});

test('detail controller lookup reuses ancestor ownership; fields keep expensive metadata opt-in', () => {
  const r = runtime();
  let parent = r.root;
  for (let i = 0; i < 20; i++) parent = r.add(parent, r.view('UIView'));
  const result = scope(r, 'detail', () => r.ui.snapshot({ format: 'detail', controls_only: false, depth: 30, max_nodes: 100, fields: ['controller'] }));
  assert.equal(result.views.length, 21);
  assert.ok(result.views.every(v => v.controller.class_name === 'FixtureController'));
  assert.ok(r.reads().responderReads < 45);
  assert.equal(r.reads().textReads, 0);
});

test('filters run before metadata/retains and opt-in text redacts sensitive controls', () => {
  const r = runtime();
  r.add(r.root, r.view('UIButton', { identifier: 'password', text: 'never-return-this' }));
  r.add(r.root, r.view('UILabel', { identifier: 'public', text: 'hello' }));
  const before = scope(r, 'find', () => r.ui.findViews({ format: 'summary', accessibility_identifier: 'public', include_text: true }));
  assert.equal(before.views.length, 1);
  assert.equal(before.views[0].text, 'hello');
  assert.equal(r.reads().responderReads, 0);
  const secret = scope(r, 'secret', () => r.ui.findViews({ accessibility_identifier: 'password', include_text: true }));
  assert.equal(secret.views[0].text, '[REDACTED]');
});

test('one live capture reports truncation at the object bound and new operations can recover', () => {
  const r = runtime();
  // Retaining 2049 objects in a single operation fails and rolls back its references.
  assert.throws(() => scope(r, 'too-many', () => {
    for (let i = 0; i < 2049; i++) r.common.objectId(r.view('NSObject'));
  }), r.common.ObjectLimitError);
  assert.equal(r.common.objectStats().objects, 0);
  const obj = r.view('NSObject');
  scope(r, 'fresh', () => r.common.objectId(obj));
  assert.equal(r.common.objectStats().objects, 1);
  r.common.releaseObjects();
  assert.equal(obj.releases, 1);
});

test('automation semantics batch taps/input/back without echoing text and stop on unsupported gesture', async () => {
  const r = runtime(), button = r.add(r.root, r.view('UIButton', { identifier: 'continue' }));
  const input = r.add(r.root, r.view('UITextField', { identifier: 'input' }));
  const custom = r.add(r.root, r.view('CustomTouchView', { identifier: 'gesture' }));
  let pops = 0;
  r.controller.navigationController = () => ({ handle: { isNull: () => false }, viewControllers: () => ({ count: () => 2 }), popViewControllerAnimated_: animated => { assert.equal(animated, false); pops++; } });
  const result = await r.automation.run({ _lease_id: 'batch', _lease_ttl: 60, after_capture: 'summary', steps: [
    { action: 'tap', target: { accessibility_identifier: 'continue' } },
    { action: 'input_text', target: { accessibility_identifier: 'input' }, text: 'do-not-echo' },
    { action: 'back', mode: 'auto' },
  ] });
  assert.equal(result.completed, true);
  assert.deepEqual(button.events, [64]); assert.deepEqual(input.events, [262144]);
  assert.equal(input.enteredText, 'do-not-echo'); assert.equal(pops, 1);
  assert.ok(!JSON.stringify(result).includes('do-not-echo'));
  assert.ok(result.summary.views.length > 0);
  const failed = await r.automation.run({ _lease_id: 'failure', _lease_ttl: 60, after_capture: 'none', steps: [
    { action: 'tap', target: { accessibility_identifier: 'gesture' } },
    { action: 'tap', target: { accessibility_identifier: 'continue' } },
  ] });
  assert.equal(failed.completed, false); assert.equal(failed.steps.length, 1);
  assert.match(failed.steps[0].error, /physical touch/);
  assert.deepEqual(button.events, [64]);
  assert.ok(custom.retains > 0);
});

test('gesture-only UIButton reports unsupported action when UIWindow.window is nil', async () => {
  const r = runtime();
  r.root.window = () => null;
  r.add(r.root, r.view('UIButton', { identifier: 'gesture-only', events: 0, gestures: true }));
  const result = await r.automation.run({ _lease_id: 'gesture-window-boundary', _lease_ttl: 60,
    after_capture: 'none', steps: [{ action: 'tap', target: { accessibility_identifier: 'gesture-only' } }] });
  assert.equal(result.completed, false);
  assert.match(result.steps[0].error, /physical touch\/gesture injection/);
  assert.equal(result.steps[0].performed, false);
});

test('automation rejects ambiguous/hidden/disabled targets and supports noninteractive assertions', async () => {
  const r = runtime();
  r.add(r.root, r.view('UIButton', { identifier: 'duplicate' }));
  r.add(r.root, r.view('UIButton', { identifier: 'duplicate' }));
  const disabled = r.add(r.root, r.view('UIButton', { enabled: false }));
  const hidden = r.add(r.root, r.view('UIView', { hidden: true }));
  const child = r.add(hidden, r.view('UIButton'));
  const ids = scope(r, 'inputs', () => [r.common.objectId(disabled), r.common.objectId(child)]);
  for (const target of [{ accessibility_identifier: 'duplicate' }, ...ids.map(view_id => ({ view_id }))]) {
    const result = await r.automation.run({ _lease_id: 'run_' + Math.random(), _lease_ttl: 60, after_capture: 'none', steps: [{ action: 'tap', target }] });
    assert.equal(result.completed, false); assert.equal(result.steps[0].performed, false);
  }
  r.add(r.root, r.view('UILabel', { identifier: 'status' }));
  const result = await r.automation.run({ _lease_id: 'assertion', _lease_ttl: 60, after_capture: 'none', steps: [{ action: 'assert', target: { accessibility_identifier: 'status' } }] });
  assert.equal(result.completed, true);
});

test('held workflow leases survive timer/pressure and bounded waits stop after cancellation', async () => {
  const r = runtime(), obj = r.add(r.root, r.view('UIButton'));
  const id = scope(r, 'snapshot', () => r.common.objectId(obj));
  r.common.withObjectLease({ _lease_id: 'held', _hold_lease: true, _input_handles: [id] }, () => null);
  r.common.releaseLease('snapshot'); r.common.expireLeases(Date.now() + 100000);
  r.common.releaseLease('held'); assert.equal(obj.releases, 0);
  r.common.finishObjectLease('held', 1); r.common.expireLeases(Date.now() + 2000); assert.equal(obj.releases, 1);
  const button = r.add(r.root, r.view('UIButton', { identifier: 'later' }));
  const pending = r.automation.run({ _lease_id: 'waiting', _lease_ttl: 1, after_capture: 'none', steps: [
    { action: 'wait_for', target: { accessibility_identifier: 'missing' }, timeout_ms: 500, poll_ms: 50 },
    { action: 'tap', target: { accessibility_identifier: 'later' } },
  ] });
  setTimeout(() => { r.common.state.disposing = true; }, 20);
  const result = await pending;
  assert.equal(result.completed, false); assert.deepEqual(button.events, []);
  assert.match(result.steps[0].error, /cancelled/);
});

test('instance discovery is synchronous/bounded and reads selected ivars without getters/descriptions', () => {
  const r = runtime();
  let secretReads = 0, arbitraryReads = 0;
  for (let i = 0; i < 8; i++) {
    const ivars = { _count: i, _enabled: true, _name: 'a'.repeat(100), _peer: r.view('NSObject') };
    Object.defineProperty(ivars, '_password', { enumerable: true, get() { secretReads++; throw Error('must not read'); } });
    const object = r.view('NSObject', { ivars });
    object.description = () => { arbitraryReads++; throw Error('no arbitrary description'); };
    r.heap.push(object);
  }
  const result = scope(r, 'instances', () => r.objcRuntime.findInstances({ class_name: 'NSObject', limit: 2, offset: 1,
    include_values: true, include_subclasses: false, field_names: ['_count', '_name', '_password', '_peer'], max_string_length: 8 }));
  assert.equal(result instanceof Promise, false); assert.equal(result.instances.length, 2);
  assert.equal(result.instances[0].values._count, 1); assert.equal(result.instances[0].values._name, 'aaaaaaaa');
  assert.equal(result.instances[0].values._password, '[REDACTED]');
  assert.equal(result.instances[0].values._peer.class_name, 'NSObject');
  assert.equal(secretReads, 0); assert.equal(arbitraryReads, 0);
  assert.equal(r.chooseCalls.length, 1); assert.equal(r.chooseCalls[0].subclasses, false);
  const ids = result.instances.map(row => row.object_id);
  const direct = scope(r, 'direct', () => r.objcRuntime.inspectObjects({ object_ids: ids, field_names: ['_count', 'missing'] }), { _input_handles: ids, _release_leases: ['instances'] });
  assert.deepEqual(direct.instances.map(row => row.values._count), [1, 2]);
  assert.equal(direct.instances[0].values.missing.unavailable, 'ivar_not_found');
  assert.equal(r.chooseCalls.length, 1);
  r.common.releaseObjects(); assert.equal(r.common.objectStats().objects, 0);
});

test('automation scroll clamps UIKit points and switch/accessibility activation use explicit semantics', async () => {
  const r = runtime(), scroll = r.add(r.root, r.view('UIScrollView', { identifier: 'list' }));
  scroll.contentOffset = () => [0, 0]; scroll.contentSize = () => [200, 900];
  scroll.bounds = () => [[0, 0], [200, 400]]; scroll.adjustedContentInset = () => [10, 0, 20, 0];
  let moved;
  scroll.setContentOffset_animated_ = (offset, animated) => { moved = offset; assert.equal(animated, false); };
  const toggle = r.add(r.root, r.view('UISwitch', { identifier: 'toggle' }));
  toggle.isOn = () => false; toggle.setOn_ = value => assert.equal(value, true);
  r.add(r.root, r.view('CustomTouchView', { identifier: 'accessible', activate: true }));
  const result = await r.automation.run({ _lease_id: 'scrolling', _lease_ttl: 60, after_capture: 'none', steps: [
    { action: 'scroll', target: { accessibility_identifier: 'list' }, dx: -100, dy: 10000 },
    { action: 'tap', target: { accessibility_identifier: 'toggle' } },
    { action: 'tap', target: { accessibility_identifier: 'accessible' } },
  ] });
  assert.equal(result.completed, true); assert.ok(moved[0] === 0); assert.equal(moved[1], 520);
  assert.deepEqual(toggle.events, [4096]); assert.equal(result.steps[2].method, 'accessibility_activate');
});

test('instance Foundation values are bounded and dictionary secrets are never read', () => {
  const r = runtime();
  const string = value => Object.assign(r.view('NSString'), { length: () => value.length, substringToIndex_: n => string(value.slice(0, n)), toString: () => value });
  const list = Object.assign(r.view('NSArray'), { count: () => 10000, objectAtIndex_: index => string('item' + index) });
  const keys = [string('public'), string('access_token')]; let index = 0, secretReads = 0;
  const dictionary = Object.assign(r.view('NSDictionary'), { count: () => 2, keyEnumerator: () => ({ nextObject: () => keys[index++] || null }),
    objectForKey_(key) { if (String(key) === 'access_token') { secretReads++; throw Error('must not read'); } return string('hello'); } });
  const obj = r.view('NSObject', { ivars: { _list: list, _dictionary: dictionary, _long: 'x'.repeat(40000) } });
  const result = scope(r, 'values', () => r.objcRuntime.readObject(obj, { max_items: 2, max_string_length: 4 }));
  assert.equal(result.values._list.total, 10000); assert.deepEqual(result.values._list.items, ['item', 'item']);
  assert.equal(result.values._dictionary.entries[0].value, 'hell');
  // Redaction checks the full key before truncating display names.
  assert.equal(secretReads, 0);
});

test('wait_for retries a leased hidden target and value budgets cap nested expansion', async () => {
  const r = runtime(), obj = r.add(r.root, r.view('UILabel'));
  let hidden = true;
  obj.isHidden = () => hidden;
  const id = scope(r, 'hidden_source', () => r.common.objectId(obj));
  setTimeout(() => { hidden = false; }, 20);
  const result = await r.automation.run({ _lease_id: 'becoming_visible', _lease_ttl: 1, after_capture: 'none', steps: [
    { action: 'wait_for', target: { view_id: id }, timeout_ms: 300, poll_ms: 50 },
  ] });
  assert.equal(result.completed, true); assert.equal(result.steps[0].view_id, id);
  const array = depth => Object.assign(r.view('NSArray'), { count: () => 20,
    objectAtIndex_: () => depth ? array(depth - 1) : 'x'.repeat(4096) });
  const object = r.view('NSObject', { ivars: { _tree: array(2), _struct: [[1, 2], [3, 4]] } });
  const values = scope(r, 'bounded_values', () => r.objcRuntime.readObject(object, { max_items: 20, max_depth: 3, max_string_length: 4096 }));
  assert.equal(values.values_truncated, true); assert.ok(JSON.stringify(values).length < 100000);
  const shallow = scope(r, 'depth_zero', () => r.objcRuntime.readObject(object, { field_names: ['_struct'], max_depth: 0 }));
  assert.deepEqual(shallow.values._struct, { array_length: 2 });
});
