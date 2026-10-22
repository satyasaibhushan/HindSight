// Records the product demo in docs/demo/: boots the real app on the seeded in-memory demo harness
// (scripts/demo-app.js), drives one reviewer session with Playwright while recording video, then writes
//   docs/demo/poster.png  readable still of the Inbox
//   docs/demo/demo.webm   the recorded session (VP8, straight from Playwright)
//   docs/demo/demo.mp4    H.264 copy for players without WebM
//   docs/demo/demo.gif    looping copy for the README (GitHub does not play repo videos inline)
// Dev-only; never touches a database. Needs Playwright plus a Chromium (PLAYWRIGHT_MODULE, PLAYWRIGHT_BROWSERS_PATH)
// and an `ffmpeg` on PATH for the mp4 and gif copies (skipped, with a note, when ffmpeg is missing).
//   node scripts/demo.js
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { start } from './demo-app.js';

const OUT = fileURLToPath(new URL('../docs/demo/', import.meta.url));
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright')
  .catch(() => import('/opt/node-tools/node_modules/playwright/index.js')).then((m) => m.default ?? m);

const SIZE = { width: 1280, height: 800 };
const pause = (page, ms) => page.waitForTimeout(ms);
// Submits a form and waits for the full-page reload the app answers with.
const submit = (page, locator) => Promise.all([page.waitForNavigation(), locator.click()]);

mkdirSync(OUT, { recursive: true });
rmSync(`${OUT}frames`, { recursive: true, force: true });
const server = await start();
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: SIZE, recordVideo: { dir: `${OUT}frames`, size: SIZE } });
const page = await ctx.newPage();
try {
  // Inbox: the open checklist, one item expanded.
  await page.goto(`${server.base}/review`);
  await pause(page, 1400);
  await page.locator('details.body summary').first().click();
  await pause(page, 1800);
  await page.screenshot({ path: `${OUT}poster.png` });
  await pause(page, 600);
  // Tick the second item done: it leaves the Open view.
  await submit(page, page.locator('li.task .chk').nth(1));
  await pause(page, 1400);
  // Done view shows it struck through.
  await submit(page, page.locator('nav.views a', { hasText: 'Done' }));
  await pause(page, 1600);
  // API keys: create an ingest key and see the one-time reveal.
  await submit(page, page.locator('nav.tabsnav a', { hasText: 'API keys' }));
  await pause(page, 1000);
  await page.locator('input[name=name]').pressSequentially('Build box — OpenCode', { delay: 35 });
  await pause(page, 500);
  await submit(page, page.locator('.btn-create'));
  await pause(page, 2200);
  // Connect: copyable MCP setup per client.
  await submit(page, page.locator('nav.tabsnav a', { hasText: 'Connect' }));
  await pause(page, 1800);
} finally {
  await ctx.close();
  await browser.close();
  server.close();
}

const [webm] = readdirSync(`${OUT}frames`).filter((f) => f.endsWith('.webm'));
renameSync(`${OUT}frames/${webm}`, `${OUT}demo.webm`);
rmSync(`${OUT}frames`, { recursive: true, force: true });
console.log('wrote docs/demo/poster.png docs/demo/demo.webm');

const ffmpeg = (args) => spawnSync('ffmpeg', ['-y', '-hide_banner', '-loglevel', 'error', ...args], { stdio: 'inherit' });
if (spawnSync('ffmpeg', ['-version'], { stdio: 'ignore' }).error) {
  console.log('ffmpeg not found: skipped docs/demo/demo.mp4 and docs/demo/demo.gif');
} else {
  ffmpeg(['-i', `${OUT}demo.webm`, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '23', '-movflags', '+faststart', `${OUT}demo.mp4`]);
  ffmpeg(['-i', `${OUT}demo.webm`, '-vf', 'fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=5',
    '-loop', '0', `${OUT}demo.gif`]);
  console.log('wrote docs/demo/demo.mp4 docs/demo/demo.gif');
}
