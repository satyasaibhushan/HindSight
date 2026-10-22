// Renders docs/screenshots/after/*.png: boots the real app on the seeded in-memory demo harness
// (scripts/demo-app.js) and captures it with Playwright.
// Dev-only; never touches a database. Needs Playwright plus a Chromium (PLAYWRIGHT_BROWSERS_PATH); Playwright
// is not a project dependency, so set PLAYWRIGHT_MODULE to its entry point if `playwright` is not resolvable.
//   node scripts/screenshots.js [--only <name-substring>]
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { LAPTOP, TOKENS, filler, seed, start } from './demo-app.js';

const OUT = fileURLToPath(new URL('../docs/screenshots/after/', import.meta.url));
const only = process.argv.includes('--only') ? process.argv[process.argv.indexOf('--only') + 1] : '';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright')
  .catch(() => import('/opt/node-tools/node_modules/playwright/index.js')).then((m) => m.default ?? m);
mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch();
const DESKTOP = { viewport: { width: 1280, height: 860 } };
const MOBILE = { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true };

async function shot(name, base, path, { device = DESKTOP, colorScheme = 'light', prepare, selector, fullPage = true } = {}) {
  if (only && !name.includes(only)) return;
  const ctx = await browser.newContext({ ...device, colorScheme });
  const page = await ctx.newPage();
  await page.goto(base + path);
  if (prepare) await prepare(page);
  await page.waitForTimeout(150);
  const file = `${OUT}${name}.png`;
  if (selector) {
    await page.addStyleTag({ content: '.topbar{position:static!important}' });
    await page.locator(selector).screenshot({ path: file });
  } else await page.screenshot({ path: file, fullPage });
  await ctx.close();
  console.log('wrote', `docs/screenshots/after/${name}.png`);
}
// First item expanded and the fourth row's overflow menu open, as in the design mockup.
const expand = async (page) => {
  await page.locator('details.body').first().evaluate((d) => { d.open = true; });
  await page.locator('details.menu').nth(3).evaluate((d) => { d.open = true; });
};

const main = await start();
const anon = await start({ signedIn: false });
const setup = await start({ configured: false });
// Shots that create a key get their own server, so one shot's new key does not show up in another.
const servers = [];
const fresh = async () => { servers.push(await start()); return servers.at(-1); };
const long = await start({ rows: [...seed(), ...filler()] });
// Click "Show more" once: the script appends the next batch in place, into the same Earlier group.
const showMore = async (page) => {
  await page.click('[data-more]');
  await page.waitForSelector('#more-25');
  await page.evaluate(() => { document.activeElement.blur(); scrollTo(0, 0); });
  await page.mouse.move(0, 0);
};
const showMoreEnd = async (page) => { await showMore(page); await page.locator('.more').scrollIntoViewIfNeeded(); };
const allClear = await start({ rows: seed().map((r) => ({ ...r, review_state: r.review_state === 'dismissed' ? 'dismissed' : 'actioned' })) });
try {
  await shot('01-setup-required', setup.base, '/review');
  await shot('02-sign-in', anon.base, '/auth/signin');
  await shot('02b-sign-in-denied', anon.base, '/auth/signin?error=AccessDenied');
  await shot('03-inbox', main.base, '/review?state=all', { prepare: expand });
  await shot('04-inbox-filtered', main.base, `/review?state=all&client=${encodeURIComponent(LAPTOP)}&group=category`);
  await shot('05-inbox-empty', allClear.base, '/review');
  await shot('06-api-keys', main.base, '/tokens');
  await shot('07-api-key-created', (await fresh()).base, '/tokens', { prepare: async (page) => {
    await page.fill('input[name=name]', 'Build box — OpenCode');
    await Promise.all([page.waitForNavigation(), page.click('.btn-create')]);
  } });
  await shot('08-connect', main.base, '/connect');
  await shot('09-sign-out', main.base, '/auth/signout');
  await shot('10-inbox-mobile', main.base, '/review?state=all', { device: MOBILE, prepare: expand });
  await shot('11-api-keys-mobile', (await fresh()).base, '/tokens', { device: MOBILE, prepare: async (page) => {
    await page.fill('input[name=name]', 'Triage bot');
    await page.check('#sc-admin');
    await Promise.all([page.waitForNavigation(), page.click('.btn-create')]);
  } });
  await shot('12-sign-in-mobile', anon.base, '/auth/signin', { device: MOBILE });
  await shot('13-inbox-dark', main.base, '/review?state=all', { colorScheme: 'dark', prepare: expand });
  await shot('14-inbox-bulk-select', main.base, '/review?select=1', { prepare: async (page) => {
    for (const box of (await page.locator('.sel input').all()).slice(0, 2)) await box.check();
  } });
  await shot('15-api-key-admin-created', (await fresh()).base, '/tokens', { prepare: async (page) => {
    await page.fill('input[name=name]', 'Triage bot');
    await page.check('#sc-admin');
    await Promise.all([page.waitForNavigation(), page.click('.btn-create')]);
    await page.fill('input[name=name]', 'Nightly triage');
    await page.check('#sc-admin');
  } });
  await shot('16-connect-admin', main.base, '/connect', { selector: '#admin' });
  await shot('17-inbox-mobile-dark', main.base, '/review?state=all', { device: MOBILE, colorScheme: 'dark', prepare: expand });
  await shot('18-api-keys-dark', main.base, '/tokens', { colorScheme: 'dark', prepare: async (page) => { await page.check('#sc-admin'); } });
  await shot('19-inbox-mobile-bulk', main.base, '/review?select=1', { device: MOBILE, prepare: async (page) => {
    for (const box of (await page.locator('.sel input').all()).slice(0, 2)) await box.check();
  } });
  await shot('20-inbox-show-more', long.base, '/review?state=all', { prepare: showMore });
  await shot('21-inbox-show-more-mobile', long.base, '/review?state=all', { device: MOBILE, prepare: showMoreEnd, fullPage: false });
} finally {
  await browser.close();
  for (const s of [main, anon, setup, allClear, long, ...servers]) s.close();
}
