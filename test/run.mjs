// Runs PhishProof's analyzer and UI in headless Chromium.
// Usage: npm install && npx playwright install chromium && npm test
import { chromium } from 'playwright';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let failed = 0;
const ok = (c, n) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`); if (!c) failed++; };
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
await page.goto(pathToFileURL(path.join(root, 'index.html')).href);

const A = (t) => page.evaluate((x) => globalThis.PhishProof.analyze(x), t);
const ids = async (t) => (await A(t)).flags.map((f) => f.id);

// Every practice sample is classified correctly.
const samples = await page.evaluate(() => globalThis.PHISHPROOF_SAMPLES);
for (const [n, s] of samples.entries()) {
  const r = await A(s.text);
  ok(s.phish ? r.verdict === 'likely-phishing' : r.verdict === 'no-red-flags', `sample ${n + 1} (${s.phish ? 'phish' : 'legit'}) → ${r.verdict}, risk ${r.risk}, flags: ${r.flags.map((f) => f.id).join(',') || 'none'}`);
}

ok((await ids('From: PayPal <a@paypa1.com>\nhello')).includes('sender-lookalike'), 'paypa1 (digit 1) detected as lookalike');
ok((await ids('From: MS <a@rnicrosoft.com>\nhi')).includes('sender-lookalike'), 'rnicrosoft (r+n) detected as lookalike');
ok((await ids('From: Netflix <a@netflx.com>\nhi')).includes('sender-lookalike'), 'one-letter typo domain detected');
ok(!(await ids('From: PayPal <service@paypal.com>\nYour receipt')).includes('sender-lookalike'), 'real paypal.com not flagged');
ok(!(await ids('From: News <a@mail.google.com>\nhi')).some((x) => x.includes('lookalike')), 'real subdomain of google.com not flagged');
ok((await ids('Visit https://paypal.com.secure-login.net/x')).includes('link-lookalike'), 'brand inside another domain detected');
ok((await ids('From: Amazon Support <amzn.help@gmail.com>\nhi')).some((x) => ['sender-mismatch', 'free-mail-official'].includes(x)), 'brand display name from Gmail detected');
ok((await ids('<a href="https://evil.example/x">https://www.chase.com</a>')).includes('link-mismatch'), 'link text vs real destination mismatch');
ok(!(await ids('<a href="https://www.chase.com/login">https://chase.com</a>')).includes('link-mismatch'), 'same-site link text not flagged');
ok((await ids('go to http://192.168.4.20/login')).includes('ip-link'), 'bare IP link detected');
ok((await ids('see https://xn--pypal-4ve.com')).includes('punycode'), 'punycode link detected');
ok((await ids('click https://bit.ly/abc')).includes('shortener'), 'shortened link detected');
ok((await ids('click https://prize-center.top/claim')).includes('risky-tld'), 'risky TLD detected');
ok((await ids('login https://www.google.com@evil.example/x')).includes('at-in-url'), '@ trick in URL detected');
ok((await ids('Your account will be suspended. Act now!')).includes('urgency'), 'urgency language detected');
ok((await ids('Please verify your account by replying')).includes('credentials'), 'credential request detected');
ok((await ids('Buy gift cards and send the codes')).includes('money'), 'gift card request detected');
ok((await ids('Dear Customer,\nhello')).includes('generic-greeting'), 'generic greeting detected');
ok((await ids('Open the attached invoice.pdf.exe')).includes('double-ext'), 'double extension attachment detected');
ok((await ids('From: Apple <id@apple.com>\nReply-To: x@helpdesk.ru\nhi')).includes('reply-to'), 'reply-to mismatch detected');
const plain = await A('Hey, are we still meeting at the library at 4? Bring your notes.');
ok(plain.verdict === 'no-red-flags' && plain.flags.length === 0, 'normal message has no flags');

// Links are never opened, and pasted HTML never runs.
const requests = [];
page.on('request', (r) => { if (!r.url().startsWith('file:')) requests.push(r.url()); });
await page.evaluate(() => { window.__pwned = false; });
await page.fill('#msg', '<img src=x onerror="window.__pwned=true"> https://evil.example/steal <a href="http://1.2.3.4">x</a>');
await page.click('#check');
await page.waitForTimeout(300);
ok(!(await page.evaluate(() => window.__pwned)), 'pasted HTML never executes');
ok(requests.length === 0, `no network requests (${requests.length})`);

// UI: check mode
await page.click('#example');
ok((await page.textContent('#verdict-text')) === 'Likely phishing', 'example shows Likely phishing');
ok((await page.locator('#flags li').count()) >= 5, `example lists flags (${await page.locator('#flags li').count()})`);
ok((await page.evaluate(() => document.activeElement.id)) === 'result-h', 'focus moves to result heading');

// UI: tabs with keyboard + practice quiz
await page.focus('#tab-check');
await page.keyboard.press('ArrowRight');
ok(await page.isVisible('#panel-practice') && !(await page.isVisible('#panel-check')), 'arrow key switches to Practice tab');
let right = 0;
for (const s of samples) {
  await page.click(s.phish ? '#ans-phish' : '#ans-safe');
  if (await page.locator('#feedback .good').count()) right++;
  if (await page.isVisible('#next')) await page.click('#next');
}
ok(right === samples.length && /6\/6/.test(await page.textContent('#feedback')), `quiz scores 6/6 with all correct answers`);

ok(errors.length === 0, `no console/page errors (${errors.join(' | ')})`);
await browser.close();
console.log(failed ? `\n${failed} test(s) failed` : '\nAll tests passed');
process.exit(failed ? 1 : 0);
