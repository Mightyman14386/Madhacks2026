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
    options.on('pageerror', error => errors.push(error.message));
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await options.waitForFunction(() => !document.querySelector('#fields').disabled);
    await options.locator('#add').click();
    await options.locator('#entries input[type=text]').fill('xyzzy');
    await options.locator('select').selectOption('ORG');
    await options.locator('#save').click();
    await options.waitForFunction(() => document.querySelector('#status').textContent.startsWith('Saved'));
    await page.goto('https://chatgpt.com/text');
    await selectText(page, 0, 21);
    await paste(page, 'xyzzy');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'Example Company 1');
    passed('options page saves typed watchlist used by subsequent pastes');


    await options.locator('#add-never').click();
    await options.locator('#exceptions input[type=text]').fill('alice@example.com');
    await options.locator('#save').click();
    await options.waitForFunction(() => document.querySelector('#status').textContent.startsWith('Saved'));
    await page.goto('https://chatgpt.com/text');
    await selectText(page, 0, 21);
    await paste(page, 'alice@example.com bob@example.com');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'alice@example.com [EMAIL_2]');
    passed('never-redact phrase overrides email detection');
    await options.locator('#never-input').fill('chatgpt.com');
    await options.locator('#never-add').click();
    await options.waitForFunction(() => document.querySelector('#never-sites').textContent.includes('chatgpt.com'));
    await page.goto('https://chatgpt.com/text');
    await selectText(page, 0, 21);
    await paste(page, 'Bob Jones bob@example.com');
    await page.waitForFunction(() => document.querySelector('#prompt-textarea').value === 'Bob Jones bob@example.com');
    passed('never-redact site bypasses paste processing');
    await options.reload();
    await options.waitForFunction(() => !document.querySelector('#fields').disabled);
    assert.equal(await options.locator('#exceptions input[type=text]').inputValue(), 'alice@example.com');
    assert.ok((await options.locator('#never-sites').innerText()).includes('chatgpt.com'));
    await options.evaluate(() => scrollTo(0,0));
    await options.screenshot({path:path.join(testRoot,'settings-desktop.png'),fullPage:true});
    await options.setViewportSize({width:390,height:844});
    assert.ok(await options.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await options.screenshot({path:path.join(testRoot,'settings-mobile.png'),fullPage:true});
    passed('rules persist and settings fit mobile layout');


    const lab=await context.newPage();
    lab.on('pageerror', error => errors.push(error.message));
    await lab.goto('chrome-extension://'+extensionId+'/lab.html');
    await lab.waitForURL('**/options.html#preview');
    assert.equal(await lab.locator('#websites').count(),1);
    assert.equal(await lab.locator('#phrases').count(),1);
    assert.equal(await lab.locator('#checks').count(),1);
    assert.ok(!(await lab.locator('body').innerText()).includes('Privacy Lab'));
    await lab.locator('#sample').click();
    await lab.locator('#analyze').click();
    await lab.waitForSelector('#results:not([hidden])');
    assert.ok((await lab.locator('#output').innerText()).includes('alice@example.com'));
    assert.ok(!(await lab.locator('#output').innerText()).includes('Alice Smith'));
    assert.ok((await lab.locator('#findings').innerText()).includes('never-redact'));
    const downloadEvent=lab.waitForEvent('download');
    await lab.locator('#export').click();
    const download=await downloadEvent;
    const report=JSON.parse(fs.readFileSync(await download.path(),'utf8'));
    assert.ok(report.redacted>0);
    assert.ok(!JSON.stringify(report).includes('example.com'));
    assert.ok(!JSON.stringify(report).includes('Alice'));
    passed('Privacy Lab explains exceptions and exports only counts');
    await lab.locator('#run-checks').click();
    await lab.waitForFunction(()=>document.querySelector('#check-summary').textContent.startsWith('10 / 10'));
    assert.equal(await lab.locator('.check').count(),10);
    passed('bundled diagnostic runs the actual detector');
    await lab.locator('#destination').fill('chatgpt.com');
    assert.equal(await lab.locator('#results').isVisible(),false);
    await lab.locator('#analyze').click();
    await lab.waitForSelector('#results:not([hidden])');
    assert.equal(await lab.locator('#output').innerText(),await lab.locator('#source').inputValue());
    assert.ok((await lab.locator('#site-reason').innerText()).includes('Never redact'));
    passed('destination simulator honors website exceptions');
    await lab.evaluate(()=>scrollTo(0,0));
    await lab.screenshot({path:path.join(testRoot,'lab-desktop.png'),fullPage:true});
    await lab.setViewportSize({width:390,height:844});
    assert.ok(await lab.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await lab.screenshot({path:path.join(testRoot,'lab-mobile.png'),fullPage:true});
    await lab.locator('#clear').click();
    assert.equal(await lab.locator('#source').inputValue(),'');
    assert.equal(await lab.locator('#results').isVisible(),false);
    assert.equal(await lab.locator('#output').innerText(),'');
    passed('lab fits mobile and clears sensitive previews');

    await lab.locator('#exceptions input[type=text]').fill('Bob Jones');
    await lab.locator('#save').click();
    await lab.waitForFunction(()=>document.querySelector('#status').textContent.startsWith('Saved'));
    await lab.locator('#sample').click();
    await lab.locator('#analyze').click();
    await lab.waitForSelector('#results:not([hidden])');
    assert.ok((await lab.locator('#output').innerText()).includes('Bob Jones'));
    assert.ok(!(await lab.locator('#output').innerText()).includes('alice@example.com'));
    passed('preferences and preview work together in one page');
    await lab.close();
    const popup=await context.newPage();
    await popup.setViewportSize({width:400,height:650});
    popup.on('pageerror', error=>errors.push(error.message));
    await popup.goto('chrome-extension://'+extensionId+'/popup.html');
    await popup.waitForFunction(()=>!document.querySelector('#enabled').disabled);
    assert.equal(await popup.locator('#open-lab').count(),0);
    assert.equal(await popup.locator('#open-settings').count(),1);
    assert.ok(!(await popup.locator('body').innerText()).includes('Privacy Lab'));
    const cards=await popup.locator('.card').evaluateAll(elements=>elements.map(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom})));
    assert.ok(cards[1].top-cards[0].bottom>=18);
    await popup.screenshot({path:path.join(testRoot,'popup-spacing.png'),fullPage:true});
    await popup.evaluate(()=>{const original=chrome.runtime.openOptionsPage.bind(chrome.runtime);chrome.runtime.openOptionsPage=()=>{window.settingsOpened=true;return original();};});
    await popup.locator('#open-settings').click();
    await popup.waitForFunction(()=>window.settingsOpened===true);
    assert.ok(context.pages().some(p=>p.url().includes('/options.html')));
    passed('popup has spaced cards and a single settings destination');
    await popup.close();


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
