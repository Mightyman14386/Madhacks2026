const test = require('node:test');
const assert = require('node:assert/strict');
const { boot, plain } = require('./harness.cjs');
const { detector } = boot();
const collect = (text, watchlist = []) => plain(detector.collect(text, watchlist));

test('local NLP identifies full person names and preserves punctuation/offsets', () => {
  const text = '😀 "Alice Smith" met Bob Jones.\nAlice Smith left.';
  const matches = collect(text);
  assert.deepEqual(matches.map(m => m.value), ['Alice Smith', 'Bob Jones', 'Alice Smith']);
  matches.forEach(m => assert.equal(text.slice(m.start, m.end), m.value));
  assert.equal(detector.render(text, matches, ['Alex Morgan', 'Jamie Parker', 'Alex Morgan']), '😀 "Alex Morgan" met Jamie Parker.\nAlex Morgan left.');
});

test('complete email wins over watched or inferred names inside it', () => {
  const matches = collect('alice@example.com', [{ text: 'Alice', type: 'PERSON' }]);
  assert.deepEqual(matches.map(m => [m.type, m.value]), [['EMAIL', 'alice@example.com']]);
});

test('longest watched name wins regardless of watchlist order', () => {
  const entries = [{ text: 'Alice', type: 'PERSON' }, { text: 'Alice Smith', type: 'PERSON' }];
  for (const list of [entries, entries.toReversed()]) {
    assert.deepEqual(collect('Alice Smith', list).map(m => m.value), ['Alice Smith']);
  }
});

test('inferred full name wins over a short watched name', () => {
  assert.deepEqual(collect('Alice Smith', ['Alice']).map(m => m.value), ['Alice Smith']);
});

test('explicit type wins for the same full phrase', () => {
  assert.equal(collect('Alice Smith', [{ text: 'Alice Smith', type: 'ORG' }])[0].type, 'ORG');
});

test('generated aliases are never scanned as watchlist terms', () => {
  const text = 'xyzzy';
  const matches = collect(text, ['xyzzy', 'WATCH_1']);
  assert.equal(detector.render(text, matches, ['[WATCH_1]']), '[WATCH_1]');
});

test('Unicode boundaries and literal regex characters are respected', () => {
  const matches = collect('éxyzzy xyzzy xyzzyé a.b axb', ['xyzzy', 'a.b']);
  assert.deepEqual(matches.filter(m => m.source === 'watchlist').map(m => m.value), ['xyzzy', 'a.b']);
});

test('watchlist case sensitivity is explicit', () => {
  assert.deepEqual(collect('xyzzy XYZZY', [{ text: 'XYZZY', type: 'WATCH', caseSensitive: true }]).map(m => m.value), ['XYZZY']);
});

test('malformed legacy watchlist entries do not crash detection', () => {
  assert.doesNotThrow(() => collect('xyzzy', [42, null, {}, 'xyzzy']));
  assert.equal(collect('xyzzy', [42, null, {}, 'xyzzy'])[0].type, 'WATCH');
  assert.throws(() => detector.normalizeWatchlist([42], true), /valid category/);
  assert.throws(() => detector.normalizeWatchlist(['xyzzy', 'XYZZY'], true), /duplicate/);
});

test('ordinary long mixed-case identifiers are not secrets', () => {
  assert.deepEqual(collect('QuarterlyReportForEngineeringTeam2026'), []);
});

test('contextual tokens and known API key prefixes are detected', () => {
  const matches = collect('api_key=abcdef0123456789 sk-abcdefghijklmnopqrstuvwxyz');
  assert.deepEqual(matches.map(m => [m.type, m.value]), [['KEY', 'abcdef0123456789'], ['KEY', 'sk-abcdefghijklmnopqrstuvwxyz']]);
});

test('complete contextual key wins over a phone-like substring', () => {
  assert.deepEqual(collect('api_key=abcdefghijklmnop-6085551234-more').map(m => [m.type, m.value]), [['KEY', 'abcdefghijklmnop-6085551234-more']]);
});

test('checksum validation rejects all-zero and invalid card candidates', () => {
  assert.deepEqual(collect('0000000000000000 4111111111111112'), []);
  assert.equal(collect('4111 1111 1111 1111')[0].type, 'CARD');
});

test('SSN validation and full IPv4 boundaries reduce false positives', () => {
  assert.deepEqual(collect('000-12-3456 666-12-3456 123-00-3456 123-45-0000 999.192.168.1.1'), []);
  assert.deepEqual(collect('123-45-6789 192.168.1.1 +1 (608) 555-1234').map(m => m.type), ['SSN', 'IP', 'PHONE']);
});

test('JWT is preserved as one match', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefgh1234567890';
  assert.deepEqual(collect(jwt).map(m => [m.type, m.value]), [['JWT', jwt]]);
});

test('missing NLP and oversized input fail closed', () => {
  const b = boot();
  b.context.nlp = undefined;
  assert.throws(() => b.detector.collect('Alice Smith'), /unavailable/);
  assert.throws(() => detector.collect('x'.repeat(100001)), /100,000/);
});
