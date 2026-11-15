const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const plain = value => JSON.parse(JSON.stringify(value));

function boot(options = {}) {
  const state = options.state || { session: {}, local: { sites: ['chatgpt.com'] }, sync: {} };
  if (state.local.sites === undefined) state.local.sites = ['chatgpt.com'];
  const controls = { failWrite: false, failRead: false, delay: 0, ...options.controls };
  const writes = [], access = [];
  let listener;
  const wait = async () => { if (controls.delay) await new Promise(resolve => setTimeout(resolve, controls.delay)); };
  const storage = Object.fromEntries(['session', 'local', 'sync'].map(area => [area, {
    async get(key) {
      await wait();
      if (controls.failRead) throw new Error('Storage read failed');
      return state[area][key] === undefined ? {} : { [key]: plain(state[area][key]) };
    },
    async set(data) {
      await wait();
      if (controls.failWrite) throw new Error('Storage write failed');
      Object.assign(state[area], plain(data));
      writes.push({ area, data: plain(data) });
    },
    async remove(key) { delete state[area][key]; },
    async setAccessLevel(value) { access.push({ area, ...value }); },
  }]));
  const chrome = { storage, runtime: {
    id: 'test-extension',
    getURL: file => `chrome-extension://test-extension/${file}`,
    onMessage: { addListener(fn) { listener = fn; } },
  } };
  const context = vm.createContext({ chrome, URL, console, setTimeout, clearTimeout });
  context.importScripts = (...files) => files.forEach(file => vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context, { filename: file }));
  context.importScripts('background.js');
  const detector = vm.runInContext('PasteGuard', context);
  function send(message, settings = false) {
    const sender = typeof settings === 'object' ? settings : {
      id: chrome.runtime.id,
      url: settings ? chrome.runtime.getURL('options.html') : 'https://chatgpt.com/c/test',
    };
    return new Promise(resolve => listener(message, sender, result => resolve(plain(result))));
  }
  return {
    state, controls, writes, access, detector, context, send,
    sanitize: text => send({ type: 'PG_SANITIZE', text }),
    watchlist: watchlist => send({ type: 'PG_SET_WATCHLIST', watchlist }, true),
  };
}
module.exports = { boot, plain, root };
