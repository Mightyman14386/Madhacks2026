const test = require('node:test');
const assert = require('node:assert/strict');
const { boot } = require('./harness.cjs');

test('person aliases are readable and consistent within and between pastes', async () => {
  const b = boot();
  const first = await b.sanitize('Alice Smith met Bob Jones. Alice Smith left.');
  assert.equal(first.ok, true);
  assert.equal(first.sanitized, 'Alex Morgan met Jamie Parker. Alex Morgan left.');
  assert.equal((await b.sanitize('Alice Smith')).sanitized, 'Alex Morgan');
});

test('first paste waits for storage and legacy watchlist migration', async () => {
  const state = { local: {}, session: {}, sync: { watchlist: ['xyzzy', 42] } };
  const b = boot({ state, controls: { delay: 5 } });
  assert.equal((await b.sanitize('xyzzy')).sanitized, '[WATCH_1]');
  assert.deepEqual(state.local.watchlist, [{ text: 'xyzzy', type: 'WATCH', caseSensitive: false }]);
  assert.equal(state.sync.watchlist, undefined);
  assert.ok(b.access.every(a => a.accessLevel === 'TRUSTED_CONTEXTS'));
});

test('concurrent tabs receive distinct stable aliases', async () => {
  const b = boot({ controls: { delay: 2 } });
  const [a, c, again] = await Promise.all([
    b.sanitize('alice@example.com'), b.sanitize('bob@example.com'), b.sanitize('alice@example.com'),
  ]);
  assert.equal(a.sanitized, '[EMAIL_1]');
  assert.equal(c.sanitized, '[EMAIL_2]');
  assert.equal(again.sanitized, '[EMAIL_1]');
  assert.deepEqual(Object.values(b.state.session.pgVaultV2.entries).map(e => e.value), ['alice@example.com', 'bob@example.com']);
});

test('worker restart reloads persisted aliases before allocation', async () => {
  const first = boot();
  await first.sanitize('alice@example.com');
  const restarted = boot({ state: first.state });
  assert.equal((await restarted.sanitize('bob@example.com')).sanitized, '[EMAIL_2]');
  assert.equal((await restarted.sanitize('alice@example.com')).sanitized, '[EMAIL_1]');
});

test('watchlist updates take effect on the next request without reload', async () => {
  const b = boot();
  assert.equal((await b.watchlist([{ text: 'xyzzy', type: 'ORG' }])).ok, true);
  assert.equal((await b.sanitize('xyzzy')).sanitized, 'Example Company 1');
  await b.watchlist([]);
  assert.equal((await b.sanitize('xyzzy')).sanitized, 'xyzzy');
});

test('literal placeholders and names are skipped during new allocation', async () => {
  const b = boot();
  assert.equal((await b.sanitize('[EMAIL_1] alice@example.com')).sanitized, '[EMAIL_1] [EMAIL_2]');
  const names = await b.sanitize('Alice Smith met Alex Morgan.');
  assert.equal(names.ok, true);
  assert.ok(!names.found.some(m => m.label === 'Alex Morgan'));
  assert.equal(new Set(names.found.map(m => m.label)).size, 2);
});

test('existing alias collision is reported instead of creating ambiguous mappings', async () => {
  const b = boot();
  await b.sanitize('alice@example.com');
  const result = await b.sanitize('[EMAIL_1] alice@example.com');
  assert.equal(result.ok, false);
  assert.match(result.error, /existing replacement alias/);
  assert.equal(result.sanitized, undefined);
});

test('failed vault writes return no sanitized text and do not consume aliases', async () => {
  const b = boot();
  await b.sanitize('plain text');
  b.controls.failWrite = true;
  const failed = await b.sanitize('alice@example.com');
  assert.equal(failed.ok, false);
  assert.equal(failed.sanitized, undefined);
  b.controls.failWrite = false;
  assert.equal((await b.sanitize('alice@example.com')).sanitized, '[EMAIL_1]');
});

test('failed initialization retries and preserves legacy synced data', async () => {
  const state = { local: {}, session: {}, sync: { watchlist: ['xyzzy'] } };
  const b = boot({ state, controls: { failWrite: true } });
  assert.equal((await b.sanitize('xyzzy')).ok, false);
  assert.deepEqual(state.sync.watchlist, ['xyzzy']);
  b.controls.failWrite = false;
  assert.equal((await b.sanitize('xyzzy')).sanitized, '[WATCH_1]');
});

test('corrupt vault fails closed instead of remapping existing aliases', async () => {
  const b = boot({ state: { local: {}, sync: {}, session: { pgVaultV2: { broken: true } } } });
  assert.equal((await b.sanitize('alice@example.com')).ok, false);
});

test('unsupported senders and settings writes from chat tabs are denied', async () => {
  const b = boot();
  assert.equal((await b.send({ type: 'PG_SANITIZE', text: 'secret' }, { id: 'test-extension', url: 'chrome://settings' })).ok, false);
  assert.equal((await b.send({ type: 'PG_SET_WATCHLIST', watchlist: [] })).ok, false);
  assert.equal((await b.send({ type: 'PG_GET_WATCHLIST' }, true)).ok, true);
});

test('invalid watchlist saves leave previous configuration intact', async () => {
  const b = boot();
  await b.watchlist(['xyzzy']);
  assert.equal((await b.watchlist([42])).ok, false);
  assert.equal((await b.sanitize('xyzzy')).sanitized, '[WATCH_1]');
});
