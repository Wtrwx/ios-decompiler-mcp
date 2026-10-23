const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');

function runtime() {
  const queued = [], timers = new Map(), rpc = {};
  let drains = 0, stopped = 0;
  const classes = {
    NSAutoreleasePool: { alloc: () => ({ init: () => ({ drain: () => drains++ }) }) },
    NSBundle: { mainBundle: () => ({ bundleIdentifier: () => 'dev.fixture', executablePath: () => '/Fixture.app/Fixture' }) },
  };
  Object.defineProperty(classes, 'UIApplication', { get() { throw Error('Unexpected UIKit identity access'); } });
  const objc = { available: true, classes, mainQueue: 'main', schedule(queue, fn) {
    assert.equal(queue, 'main'); queued.push(fn); // Model an unresponsive main queue.
  } };
  const process = { id: 42, arch: 'arm64', mainModule: { base: 'main' }, enumerateThreads: () => [{ id: 7, state: 'running' }] };
  function load(file, mocks = {}) {
    const source = fs.readFileSync(path.join(__dirname, '../agents/frida', file), 'utf8');
    const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
    const module = { exports: {} };
    new Function('require', 'module', 'exports', 'rpc', 'Process', 'setInterval', 'clearInterval', js)(name => {
      if (name === 'frida-objc-bridge') return { default: objc };
      if (mocks[name]) return mocks[name];
      throw Error('Unexpected import: ' + name);
    }, module, module.exports, rpc, process, fn => { timers.set(1, fn); return 1; }, id => timers.delete(id));
    return module.exports;
  }
  const common = load('common.ts');
  common.imageFor = () => ({ uuid: 'fixture' });
  const debuggerTools = load('debugger.ts', { './common.js': common });
  const disposal = { dispose: () => stopped++ };
  load('index.ts', { './common.js': common, './objc_runtime.js': {}, './ui_inspector.js': {},
    './tracer.js': disposal, './automation.js': {}, './logging.js': disposal,
    './debugger.js': debuggerTools, './decrypt.js': {} });
  return { common, queued, timers, dispatch: rpc.exports.dispatch, counts: () => ({ drains, stopped }) };
}

test('cold debugger identity, timer and empty cleanup work while UIKit main queue is unresponsive', async () => {
  const r = runtime();
  const mismatch = await r.dispatch('initialize', { session_id: 'bad', bundle_id: 'another.app' });
  assert.match(mismatch.agent_error, /identity mismatch/);
  assert.equal(r.common.state.session, ''); assert.equal(r.timers.size, 0);
  const identity = await r.dispatch('initialize', { session_id: 'verified', bundle_id: 'dev.fixture' });
  assert.equal(identity.bundle_id, 'dev.fixture'); assert.equal(identity.pid, 42);
  const fresh = await r.dispatch('identity', {});
  assert.equal(fresh.executable, '/Fixture.app/Fixture'); assert.equal(fresh.main_image.uuid, 'fixture');
  const trace = await r.dispatch('debug_inspect', { mode: 'threads', max_threads: 1 });
  assert.deepEqual(trace.threads, [{ thread_id: 7, state: 'running' }]);
  r.timers.get(1)();
  assert.equal(r.queued.length, 0);
  assert.deepEqual(await r.dispatch('dispose', {}), { disposed: true });
  assert.equal(r.timers.size, 0); assert.equal(r.queued.length, 0);
  assert.deepEqual(r.counts(), { drains: 3, stopped: 2 });
});

test('cleanup of retained UI handles still waits for the main queue and releases once', async () => {
  const r = runtime();
  await r.dispatch('initialize', { session_id: 'verified', bundle_id: 'dev.fixture' });
  let retains = 0, releases = 0;
  const object = { handle: { isNull: () => false, toString: () => '0x1' }, retain: () => retains++, release: () => releases++ };
  r.common.withObjectLease({ _lease_id: 'snapshot' }, () => r.common.objectId(object));
  const disposing = r.dispatch('dispose', {});
  assert.equal(r.queued.length, 1); assert.equal(retains, 1); assert.equal(releases, 0);
  r.queued.shift()();
  assert.deepEqual(await disposing, { disposed: true });
  assert.equal(releases, 1); assert.equal(r.common.state.objects.size, 0);
});
