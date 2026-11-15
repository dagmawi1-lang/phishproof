(function () {
// PhishProof analyzer: spots common phishing red flags in an email or message.
// Runs entirely in the browser. Nothing is sent anywhere, and links are never opened.

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc'];
const RISKY_TLDS = ['zip', 'mov', 'xyz', 'top', 'click', 'link', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'rest', 'support', 'live', 'icu'];
// Brands that phishers often impersonate, with their real domains.
const BRANDS = {
  paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
  google: ['google.com', 'gmail.com'], amazon: ['amazon.com'], netflix: ['netflix.com'], instagram: ['instagram.com'],
  facebook: ['facebook.com'], chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], bankofamerica: ['bankofamerica.com'],
  usps: ['usps.com'], fedex: ['fedex.com'], ups: ['ups.com'], dhl: ['dhl.com'], irs: ['irs.gov'], steam: ['steampowered.com', 'steamcommunity.com'],
  roblox: ['roblox.com'], discord: ['discord.com'], venmo: ['venmo.com'], coinbase: ['coinbase.com'],
};
const URGENCY = [/\burgent(ly)?\b/i, /\bimmediately\b/i, /\bwithin (24|48|12) hours\b/i, /\bact now\b/i, /\bfinal (notice|warning)\b/i, /\b(account|access) (will be|has been) (suspended|locked|disabled|terminated|closed)\b/i, /\bexpires? (today|soon)\b/i, /\blast chance\b/i, /\bunusual (sign-in|activity|login)\b/i];
const CREDENTIALS = [/\b(verify|confirm|update|validate)(ing)? (your )?(account|identity|password|login|details|information|payment)\b/i, /\b(enter|provide|send) (your )?(password|ssn|social security|pin|card number|cvv|bank details|login)\b/i, /\bsign in to (restore|unlock|verify)\b/i, /\bone[- ]time (code|passcode)\b/i];
const MONEY = [/\bgift ?cards?\b/i, /\bwire (transfer|the money)\b/i, /\b(bitcoin|crypto|btc|usdt)\b/i, /\byou('ve| have) won\b/i, /\bclaim (your )?(prize|reward|refund)\b/i, /\brefund of \$?\d/i, /\bunpaid (invoice|toll|fee)\b/i, /\bfree \$?\d+/i];
const GENERIC_GREETING = /^\s*(dear (customer|user|client|member|valued customer|account holder|sir\/madam|sir or madam)|hello (customer|user)|attention)[,!:]/im;
const DOUBLE_EXT = /\b[\w-]+\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|zip|html?|iso|lnk)\b/i;
const RISKY_ATTACH = /\b[\w-]+\.(exe|scr|js|vbs|bat|cmd|iso|lnk|html?)\b/i;

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

// Registrable domain (simple version: last two labels, or last three for co.uk-style).
function baseDomain(host) {
  const parts = host.split('.');
  if (parts.length >= 3 && /^(co|com|org|net|gov|ac|edu)$/.test(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

// Normalise lookalike characters so "paypa1" and "rnicrosoft" compare like the real names.
function skeleton(s) {
  return s.toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[0o]/g, 'o').replace(/[1il|]/g, 'l').replace(/5/g, 's').replace(/\$/g, 's').replace(/3/g, 'e').replace(/@/g, 'a').replace(/[-_.]/g, '');
}

function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

// Is this host pretending to be a known brand?
function impersonation(host) {
  const base = baseDomain(host);
  const all = Object.values(BRANDS).flat();
  if (all.includes(base)) return null;
  const label = base.split('.')[0];
  for (const [brand, domains] of Object.entries(BRANDS)) {
    const sk = skeleton(label);
    if (sk === skeleton(brand) && label !== brand) return { brand, domains, how: `"${base}" uses lookalike characters to imitate ${domains[0]}` };
    if (brand.length >= 5 && label !== brand && editDistance(label, brand) === 1) return { brand, domains, how: `"${base}" is one letter away from ${domains[0]}` };
    // Brand name buried in another domain or subdomain: paypal.com-secure.net, paypal-login.xyz
    if (host.includes(brand) && !domains.includes(base)) return { brand, domains, how: `"${host}" contains "${brand}" but the real site is ${domains[0]}. The actual domain is ${base}` };
    // Lookalike brand inside a longer name: paypa1-security.com, rnicrosoft-support.co
    if (brand.length >= 5 && skeleton(host).includes(skeleton(brand)) && !host.includes(brand)) return { brand, domains, how: `"${base}" uses lookalike characters to imitate ${domains[0]}` };
  }
  return null;
}

function extractLinks(text) {
  const links = [];
  // HTML anchors: compare visible text with the real destination.
  const anchor = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = anchor.exec(text))) links.push({ href: m[1].trim(), text: m[2].replace(/<[^>]+>/g, '').trim() });
  // Markdown links [text](url)
  const md = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;
  while ((m = md.exec(text))) links.push({ href: m[2], text: m[1] });
  // Bare URLs
  const stripped = text.replace(anchor, ' ').replace(md, ' ');
  const bare = /\b((?:https?:\/\/|www\.)[^\s<>"')\]]+)/gi;
  while ((m = bare.exec(stripped))) links.push({ href: m[1].startsWith('www.') ? 'http://' + m[1] : m[1].replace(/[.,;:!?]+$/, ''), text: '' });
  return links;
}

function parseSender(text) {
  const m = text.match(/^\s*from:\s*(.+)$/im);
  if (!m) return null;
  const line = m[1].trim();
  const email = (line.match(/<([^>]+@[^>]+)>/) || line.match(/([\w.+-]+@[\w.-]+\.\w+)/) || [])[1];
  const name = line.replace(/<[^>]*>/, '').replace(email || '', '').replace(/["']/g, '').trim();
  return { line, email: email && email.toLowerCase(), name, domain: email ? email.split('@')[1] : null };
}

function analyze(text) {
  const flags = [];
  const add = (id, severity, title, detail, tip) => flags.push({ id, severity, title, detail, tip });
  const body = text || '';

  // ---- sender ----
  const sender = parseSender(body);
  if (sender && sender.domain) {
    const imp = impersonation(sender.domain);
    if (imp) add('sender-lookalike', 'high', 'Sender domain imitates a real company', imp.how + '.', `Real ${imp.brand} emails come from ${imp.domains.join(' or ')}.`);
    const nameBrand = Object.keys(BRANDS).find((b) => skeleton(sender.name).includes(b));
    if (nameBrand && !BRANDS[nameBrand].includes(baseDomain(sender.domain)) && !imp)
      add('sender-mismatch', 'high', 'Display name doesn\'t match the email address', `It says "${sender.name}" but was sent from ${sender.email}.`, 'Anyone can type any display name. Always check the actual address.');
    if (/^(gmail|outlook|hotmail|yahoo|icloud|aol|proton(mail)?)\.(com|me)$/.test(baseDomain(sender.domain)) && /(support|security|billing|team|service|admin|help|account|office|principal|ceo|president|director|payroll|hr\b|teacher|dean|it dept)/i.test(sender.name + sender.email))
      add('free-mail-official', /(principal|ceo|president|director|dean|payroll|hr\b)/i.test(sender.name + sender.email) ? 'high' : 'medium', 'Official-sounding sender using a free email account', `"${sender.name || sender.email}" is writing from a free ${sender.domain} address.`, 'Real companies and schools send from their own domain.');
  }
  const replyTo = body.match(/^\s*reply-to:\s*.*?([\w.+-]+@[\w.-]+\.\w+)/im);
  if (replyTo && sender && sender.domain && baseDomain(replyTo[1].split('@')[1].toLowerCase()) !== baseDomain(sender.domain))
    add('reply-to', 'medium', 'Replies go to a different address', `Replies will go to ${replyTo[1]}, not ${sender.email}.`, 'Scammers do this so your reply reaches them instead of the real company.');

  // ---- links ----
  const links = extractLinks(body);
  const seen = new Set();
  for (const l of links) {
    const host = hostOf(l.href);
    if (!host || seen.has(l.href)) continue;
    seen.add(l.href);
    const shownHost = hostOf(/^https?:\/\//i.test(l.text) ? l.text : (/^[\w-]+(\.[\w-]+)+(\/|$)/.test(l.text) ? 'http://' + l.text : ''));
    if (shownHost && baseDomain(shownHost) !== baseDomain(host))
      add('link-mismatch', 'high', 'Link text hides a different destination', `The link shows "${l.text}" but actually goes to ${host}.`, 'Hover over (or long-press) links to see where they really go.');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('ip-link', 'high', 'Link goes to a bare IP address', `${l.href} uses a number instead of a website name.`, 'Legitimate companies almost never link to raw IP addresses.');
    if (host.startsWith('xn--') || host.includes('.xn--')) add('punycode', 'high', 'Link uses disguised international characters', `${host} is "punycode", which can make a fake site look like a real one.`, 'Type the company\'s address yourself instead of clicking.');
    const imp = impersonation(host);
    if (imp) add('link-lookalike', 'high', 'Link imitates a real website', imp.how + '.', `Go to ${imp.domains[0]} directly by typing it.`);
    if (SHORTENERS.includes(baseDomain(host))) add('shortener', 'medium', 'Shortened link hides where it goes', `${host} is a link shortener, so you can't see the real destination.`, 'Be careful with shortened links in unexpected messages.');
    const tld = host.split('.').pop();
    if (RISKY_TLDS.includes(tld)) add('risky-tld', 'medium', `Unusual web address ending ".${tld}"`, `${host} uses a domain ending that is common in scams.`, 'Check the address carefully before trusting it.');
    if (/^http:\/\//i.test(l.href) && CREDENTIALS.some((r) => r.test(body))) add('no-https', 'medium', 'Login link isn\'t secure (no HTTPS)', `${l.href} is not encrypted.`, 'Never enter a password on a page that isn\'t https://.');
    if (/@/.test(l.href.split('//')[1]?.split('/')[0] || '')) add('at-in-url', 'high', 'Link uses an "@" trick', `In ${l.href}, everything before "@" is ignored, so the real site is ${host}.`, 'This trick makes a link look like it goes somewhere it doesn\'t.');
  }

  // ---- language ----
  const hit = (list) => list.map((r) => (body.match(r) || [])[0]).filter(Boolean);
  const urg = hit(URGENCY);
  if (urg.length) add('urgency', urg.length > 1 ? 'high' : 'medium', 'Pressure to act fast', `It says: "${urg.slice(0, 3).join('", "')}".`, 'Scammers rush you so you don\'t stop to think. Real companies give you time.');
  const cred = hit(CREDENTIALS);
  if (cred.length) add('credentials', 'high', 'Asks for your login or personal details', `It asks you to "${cred[0]}".`, 'Real companies never ask for your password, PIN or codes by email or text.');
  const money = hit(MONEY);
  if (money.length) add('money', 'high', 'Money, prizes or gift cards', `It mentions "${money.slice(0, 3).join('", "')}".`, 'Requests for gift cards, crypto or wire transfers are almost always scams.');
  if (GENERIC_GREETING.test(body)) add('generic-greeting', 'low', 'Generic greeting', `It starts with "${body.match(GENERIC_GREETING)[1]}" instead of your name.`, 'Companies you have an account with usually use your name.');
  const dbl = body.match(DOUBLE_EXT);
  if (dbl) add('double-ext', 'high', 'Attachment with a hidden file type', `"${dbl[0]}" looks like a document but is really a .${dbl[2]} file.`, 'Don\'t open it. It could install malware.');
  else { const ra = body.match(RISKY_ATTACH); if (ra && /attach|download|open|file/i.test(body)) add('risky-attach', 'medium', 'Risky attachment type', `"${ra[0]}" can run code on your computer.`, 'Only open files you were expecting, from people you know.'); }
  const letters = body.replace(/[^A-Za-z]/g, '');
  const caps = (body.match(/\b[A-Z]{4,}\b/g) || []).filter((w) => !['HTTPS', 'HTTP', 'HTML', 'USPS', 'FEDEX'].includes(w));
  if (letters.length > 40 && caps.length >= 3) add('shouting', 'low', 'Lots of ALL-CAPS words', `Words like ${caps.slice(0, 3).join(', ')} are used to alarm you.`, 'Alarming formatting is a common pressure tactic.');

  const W = { high: 25, medium: 12, low: 5 };
  const risk = Math.min(100, flags.reduce((s, f) => s + W[f.severity], 0));
  const verdict = risk >= 50 ? 'likely-phishing' : risk >= 20 ? 'suspicious' : 'no-red-flags';
  return { risk, verdict, flags, links: [...seen], sender };
}

globalThis.PhishProof = { analyze, extractLinks, impersonation, baseDomain, skeleton, editDistance };
})();
