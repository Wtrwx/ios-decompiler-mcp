const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');

function load(file, mocks = {}) {
  const source = fs.readFileSync(path.join(__dirname, '../agents/frida', file), 'utf8');
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
  const module = { exports: {} };
  new Function('require', 'module', 'exports', js)(name => {
    if (name === 'frida-objc-bridge') return { default: {} };
    if (mocks[name]) return mocks[name];
    throw Error(name);
  }, module, module.exports);
  return module.exports;
}

function logging() {
  const hooks = new Map(), detached = [];
  global.Module = { findGlobalExportByName: name => name === 'NSLogv' ? null : name };
  global.Interceptor = { attach(name, callbacks) {
    if (name === 'NSLog') throw Error('Cannot intercept');
    hooks.set(name, callbacks);
    return { detach: () => detached.push(name) };
  } };
  const api = load('logging.ts');
  const string = text => {
    const data = Buffer.from(text + '\0');
    return { add: i => ({ readU8: () => data[i] }), readUtf8String: size => new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, size)) };
  };
  function emit(message, level = 0) {
    hooks.get('_os_log_impl').onEnter.call({ threadId: 1 }, [null, null, { toInt32: () => level }, string(message)]);
  }
  const defaults = { action: 'read', sources: ['os_log', 'nslog'], capacity: 3, max_message_length: 32, after: 0, limit: 2, wait_ms: 0 };
  return { api, emit, hooks, detached, defaults };
}

test('log ring wraps, filter pages advance, partial hooks work and stop detaches', async () => {
  const r = logging();
  let result = await r.api.run(r.defaults);
  assert.equal(result.active, true); assert.deepEqual(result.unavailable.sort(), ['NSLog', 'NSLogv']);
  for (let i = 0; i < 6; i++) r.emit('event ' + i);
  result = await r.api.run(r.defaults);
  assert.equal(result.buffered, 3); assert.equal(result.dropped, 3);
  assert.deepEqual(result.entries.map(e => e.message), ['event 3', 'event 4']);
  assert.equal(result.next_cursor, 5); assert.equal(result.has_more, true);
  const next = await r.api.run({ ...r.defaults, after: result.next_cursor });
  assert.equal(next.entries[0].message, 'event 5'); assert.equal(next.next_cursor, 6);
  const empty = await r.api.run({ ...r.defaults, contains: 'absent' });
  assert.equal(empty.entries.length, 0); assert.equal(empty.next_cursor, 6);
  const reset = await r.api.run({ ...r.defaults, after: 999 });
  assert.equal(reset.cursor_reset, true);
  result = await r.api.run({ ...r.defaults, action: 'stop' });
  assert.equal(result.active, false); assert.deepEqual(r.detached, ['_os_log_impl']);
});

test('message and character budgets bound memory without per-event sends', async () => {
  const r = logging();
  const args = { ...r.defaults, capacity: 1000, max_message_length: 2048, sources: ['os_log'], limit: 100 };
  await r.api.run(args);
  for (let i = 0; i < 1000; i++) r.emit('界'.repeat(3000));
  const result = await r.api.run(args);
  assert.ok(result.buffered <= 32); assert.ok(result.dropped >= 968);
  assert.ok(result.entries.every(e => e.message.length <= 2048 && e.message_kind === 'format'));
  await r.api.run({ ...args, action: 'stop' });
});

test('running-thread inspection bounds frames and avoids symbol work unless selected', () => {
  const pointer = value => ({ toString: () => '0x' + value, strip() { return this; } });
  global.Process = { id: 42, enumerateThreads: () => Array.from({ length: 10 }, (_, id) => ({ id: id + 1, state: 'running', context: { pc: pointer(1), sp: pointer(2) } })), findModuleByAddress: () => ({ name: 'Fixture' }) };
  global.Thread = { backtrace: () => Array.from({ length: 30 }, (_, i) => pointer(i)) };
  global.Backtracer = { ACCURATE: 1 };
  let symbols = 0;
  global.DebugSymbol = { fromAddress: () => { symbols++; return 'symbol'; } };
  const api = load('debugger.ts');
  const args = { mode: 'backtrace', max_threads: 2, max_frames: 3, symbols: false, register_names: [] };
  const result = api.inspect(args);
  assert.equal(result.consistent_stop, false); assert.equal(result.threads.length, 2);
  assert.ok(result.threads.every(t => t.frames.length === 3)); assert.equal(symbols, 0);
  const regs = api.inspect({ ...args, mode: 'registers', thread_id: 4, register_names: ['pc', 'missing'] });
  assert.deepEqual(regs.threads[0].registers, { pc: '0x1' });
  assert.throws(() => api.inspect({ ...args, thread_id: 100 }), /no longer present/);
});
