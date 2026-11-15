// Actual MV3 extension in Chromium, using local fixtures served at the supported
// origin. No ChatGPT account, live chat, or third-party network calls are used.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const bundledBrowser = path.join(root, 'node_modules/.cache/ms-playwright');
if (!process.env.PLAYWRIGHT_BROWSERS_PATH && fs.existsSync(bundledBrowser)) process.env.PLAYWRIGHT_BROWSERS_PATH = bundledBrowser;
const { chromium } = require('playwright');
const fixture = rich => `<!doctype html><html><head><style>[contenteditable] { white-space: pre-wrap; }</style></head><body>
${rich ? '<div id="prompt-textarea" contenteditable="true"><p>before selected after</p></div>' : '<textarea id="prompt-textarea">before selected after</textarea>'}
<textarea id="unrelated"></textarea><button id="send">Send</button>
<script>
window.sitePastes = 0; window.inputEvents = [];
window.addEventListener('paste', () => window.sitePastes++, true);
document.addEventListener('input', e => window.inputEvents.push(e.data));
</script></body></html>`;

async function run() {
  const testRoot = path.join(root, 'test-results');
  fs.mkdirSync(testRoot, { recursive: true });
  const profile = fs.mkdtempSync(path.join(testRoot, 'browser-'));
  let context;
  let count = 0;
  const passed = label => { count++; console.log(`PASS ${label}`); };
  try {
    context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`],
    });
    await context.route('https://chatgpt.com/**', route => route.fulfill({ contentType: 'text/html', body: fixture(route.request().url().includes('/rich')) }));
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://chatgpt.com' });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const extensionId = new URL(worker.url()).host;
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('https://chatgpt.com/text');

    async function paste(targetPage, text) {
      await targetPage.evaluate(value => navigator.clipboard.writeText(value), text);
      await targetPage.keyboard.press('Control+V');
    }
    async function selectText(targetPage, start, end) {
      await targetPage.locator('#prompt-textarea').evaluate((input, [start, end]) => {
        input.focus(); input.setSelectionRange(start, end);
      }, [start, end]);
    }

    await selectText(page, 7, 15);
    await paste(page, 'Alice Smith: alice@example.com');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'before Alex Morgan: [EMAIL_1] after');
    assert.equal(await page.evaluate(() => window.sitePastes), 0);
    assert.ok((await page.evaluate(() => window.inputEvents)).includes('Alex Morgan: [EMAIL_1]'));
    passed('real textarea paste replaces selection and suppresses raw site paste');

    await page.keyboard.press('Control+Z');
    assert.equal(await page.locator('#prompt-textarea').inputValue(), 'before selected after');
    passed('textarea paste preserves undo');

    const second = await context.newPage();
    await second.goto('https://chatgpt.com/text');
    await selectText(second, 0, 21);
    await paste(second, 'Alice Smith alice@example.com bob@example.com');
    await second.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'Alex Morgan [EMAIL_1] [EMAIL_2]');
    passed('real tabs share stable name and email mappings');

    await page.goto('https://chatgpt.com/rich');
    await page.locator('#prompt-textarea').evaluate(input => {
      input.focus();
      const range = document.createRange();
      range.setStart(input.firstChild.firstChild, 7);
      range.setEnd(input.firstChild.firstChild, 15);
      window.getSelection().removeAllRanges(); window.getSelection().addRange(range);
    });
    await paste(page, 'alice@example.com\n<em>literal</em>');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').innerText.includes('[EMAIL_1]'));
    const rich = await page.locator('#prompt-textarea').innerText();
    assert.equal(rich, 'before [EMAIL_1]\n<em>literal</em> after');
    assert.equal(await page.locator('#prompt-textarea em').count(), 0);
    assert.equal(await page.evaluate(() => window.sitePastes), 0);
    passed('rich editor supports multiline plain text without HTML injection');
    await page.keyboard.press('Control+Z');
    assert.equal(await page.locator('#prompt-textarea').innerText(), 'before selected after');
    passed('rich editor paste preserves undo');

    await page.locator('#prompt-textarea').fill('');
    await paste(page, 'first\n\nlast\n');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').innerText.startsWith('first'));
    assert.equal(await page.locator('#prompt-textarea').innerText(), 'first\n\nlast\n');
    passed('empty rich editor preserves blank lines and trailing newline');

    await page.goto('https://chatgpt.com/text');
    await page.locator('#unrelated').focus();
    await paste(page, 'alice@example.com');
    await page.waitForFunction(() => document.querySelector('#unrelated').value === 'alice@example.com');
    assert.equal(await page.evaluate(() => window.sitePastes), 1);
    passed('unrelated textareas keep native paste behavior');

    // Delay real worker reads, then edit before the response returns.
    await worker.evaluate(() => {
      globalThis.originalLocalGet = chrome.storage.local.get.bind(chrome.storage.local);
      chrome.storage.local.get = async (...args) => {
        await new Promise(resolve => { globalThis.releaseRead = resolve; });
        return globalThis.originalLocalGet(...args);
      };
    });
    await selectText(page, 0, 21);
    await paste(page, 'alice@example.com');
    await page.locator('#prompt-textarea').fill('new draft');
    for (let i = 0; i < 100; i++) {
      if (await worker.evaluate(() => typeof globalThis.releaseRead === 'function')) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    await worker.evaluate(() => { chrome.storage.local.get = globalThis.originalLocalGet; globalThis.releaseRead(); });
    await page.waitForSelector('#paste-guard-notice');
    assert.equal(await page.locator('#prompt-textarea').inputValue(), 'new draft');
    passed('editor changes while detection is pending cancel insertion');

    await page.goto('https://chatgpt.com/text');
    await selectText(page, 0, 21);
    await paste(page, 'x'.repeat(100001));
    await page.waitForSelector('#paste-guard-notice');
    assert.equal(await page.locator('#prompt-textarea').inputValue(), 'before selected after');
    passed('detector errors block the original paste and show a notice');

    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await options.waitForFunction(() => !document.querySelector('#fields').disabled);
    await options.locator('#add').click();
    await options.locator('input[type=text]').fill('xyzzy');
    await options.locator('select').selectOption('ORG');
    await options.locator('button[type=submit]').click();
    await options.waitForFunction(() => document.querySelector('#status').textContent.startsWith('Saved'));
    await page.goto('https://chatgpt.com/text');
    await selectText(page, 0, 21);
    await paste(page, 'xyzzy');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'Example Company 1');
    passed('options page saves typed watchlist used by subsequent pastes');

    const vaultAccess = await page.evaluate(async () => {
      // The page itself has no extension storage API.
      return typeof chrome?.storage;
    });
    assert.equal(vaultAccess, 'undefined');
    assert.deepEqual(errors, []);
    console.log(`${count} browser scenarios passed with the actual unpacked extension.`);
  } finally {
    await context?.close();
    const relative = path.relative(testRoot, path.resolve(profile));
    if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) fs.rmSync(profile, { recursive: true, force: true });
  }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
