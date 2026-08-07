#!/usr/bin/env node
//
// Recapture docs/router-ui.png -- the MCP Server page in GL.iNet's admin panel.
//
// Usage:
//
//   npm install puppeteer-core           # or use a Chrome you already have
//   ROUTER=192.168.8.1 \
//   SID=$(ssh root@192.168.8.1 'ls /tmp/gl_token_* | head -1 | sed "s|.*/gl_token_||"') \
//   CHROME_BIN=/usr/bin/google-chrome \
//   node docs/screenshot.js docs/router-ui.png
//
// You must be logged into the router's web UI in a browser first. This script does not
// authenticate: it reuses the session id you already created, read from /tmp/gl_token_* on
// the router. Sessions are short-lived, so log in immediately before running this. If SID is
// stale or empty the SPA renders the login page and the run aborts rather than saving a
// misleading image.
//
// Why not automate the login: entering a password is not something this script should do,
// and putting one in an env var to be captured by shell history is worse than the manual
// step it saves.

const ROUTER = process.env.ROUTER || '192.168.8.1';
const SID = process.env.SID || '';
const CHROME = process.env.CHROME_BIN;
const OUT = process.argv[2] || 'docs/router-ui.png';
const BASE = `http://${ROUTER}`;

// The page is captured at 2x and downscaled afterwards, which is the only way to get text
// that is not soft on a HiDPI README:
//   magick shot.png -resize 1440x -strip docs/router-ui.png
const WIDTH = 1440, HEIGHT = 1000;

const sleep = ms => new Promise(r => setTimeout(r, ms));

if (!CHROME) { console.error('set CHROME_BIN to a Chrome/Chromium binary'); process.exit(2); }
if (!SID) { console.error('set SID -- see the header comment; log into the router UI first'); process.exit(2); }

// Required after the argument checks so a missing dependency cannot mask a plain mistake,
// and resolved explicitly because this file lives in docs/ where there is no node_modules.
let puppeteer;
try {
  puppeteer = require('puppeteer-core');
} catch {
  console.error('puppeteer-core not found. Install it somewhere node can see, e.g.\n' +
    '  npm install puppeteer-core          (creates ./node_modules, gitignored)\n' +
    'or point at an existing install:\n' +
    '  NODE_PATH=/path/to/node_modules node docs/screenshot.js');
  process.exit(2);
}

// Click the first childless element whose text matches, then its enclosing <li>. The GL.iNet
// nav puts the handler on varying ancestors depending on menu depth, so try both.
async function clickByText(page, source) {
  return page.evaluate((src) => {
    const rx = new RegExp(src, 'i');
    const n = [...document.querySelectorAll('span,a,li,div,p')]
      .find(el => el.children.length === 0 && rx.test((el.textContent || '').trim()));
    if (!n) return null;
    (n.closest('li') || n.parentElement || n).click();
    n.click();
    return (n.textContent || '').trim();
  }, source);
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--force-device-scale-factor=2']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: WIDTH, height: HEIGHT, deviceScaleFactor: 2 });

  // The SPA is flaky to bootstrap headless -- it paints nothing on roughly half of attempts,
  // on its own pages as well as ours. Retry until the nav actually exists rather than
  // screenshotting a blank page and calling it a result.
  let ready = false;
  for (let attempt = 1; attempt <= 6 && !ready; attempt++) {
    await page.goto(BASE, { waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    await page.setCookie({ name: 'Admin-Token', value: SID, domain: ROUTER, path: '/' });
    await page.goto(`${BASE}/#/internet`, { waitUntil: 'networkidle2', timeout: 30000 }).catch(() => {});
    await sleep(4000);
    ready = /APPLICATIONS/i.test(await page.evaluate(() => document.body.innerText || ''));
    console.error(`attempt ${attempt}: ${ready ? 'rendered' : 'blank, retrying'}`);
  }
  if (!ready) {
    console.error('the SPA never painted -- is SID current? sessions expire quickly');
    await browser.close();
    process.exit(1);
  }

  await clickByText(page, '^APPLICATIONS$');
  await sleep(1500);
  await clickByText(page, '^MCP Server$');
  await sleep(4000);

  const text = await page.evaluate(() => (document.body.innerText || '').replace(/\s+/g, ' '));
  if (!/Standing policies/i.test(text)) {
    console.error('reached ' + page.url() + ' but the MCP page did not render; not saving');
    await browser.close();
    process.exit(1);
  }

  await page.screenshot({ path: OUT });
  console.error(`saved ${OUT} at ${WIDTH * 2}x${HEIGHT * 2}; downscale to ${WIDTH}px wide before committing`);
  await browser.close();
})();
