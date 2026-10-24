// Serves the bundled SDK page and runs the suite in headless Chrome against a
// Kor server, once over streaming WebChannel and once with forced long
// polling. Usage: KOR_HOST=127.0.0.1 KOR_PORT=5002 node run.mjs
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import puppeteer from 'puppeteer';

const host = process.env.KOR_HOST || '127.0.0.1';
const port = Number(process.env.KOR_PORT || 5002);
const modes = (process.env.KOR_MODES || 'streaming,long-polling').split(',');

const page = `<!doctype html><meta charset="utf-8"><title>kor sdk</title>
<script type="module" src="/sdk-page.js"></script>`;
const bundle = readFileSync(new URL('./dist/sdk-page.js', import.meta.url));
const server = createServer((req, res) => {
  if (req.url === '/sdk-page.js') {
    res.writeHead(200, { 'content-type': 'text/javascript' });
    res.end(bundle);
  } else {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(page);
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await puppeteer.launch({ headless: true });
let failed = 0;
try {
  for (const mode of modes) {
    const tab = await browser.newPage();
    tab.on('pageerror', (e) => console.error(`  [${mode}] page error: ${e.message}`));
    await tab.goto(origin, { waitUntil: 'load' });
    await tab.waitForFunction(() => typeof window.runSuite === 'function', { timeout: 30000 });
    const results = await tab.evaluate(
      (args) => window.runSuite(args),
      { host, port, forceLongPolling: mode === 'long-polling' },
    );
    console.log(`browser SDK over ${mode}:`);
    for (const r of results) {
      if (!r.ok) failed++;
      console.log(`  ${r.ok ? 'PASS' : 'FAIL'} ${r.name} (${r.ms} ms)${r.ok ? '' : ` — ${r.detail}`}`);
    }
    await tab.close();
  }
} finally {
  await browser.close();
  server.close();
}
console.log(failed ? `${failed} browser check(s) failed` : 'all browser checks passed');
process.exit(failed ? 1 : 0);
