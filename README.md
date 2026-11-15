# PhishProof 🎣

**Spot phishing before you click.** Paste a suspicious email or text and PhishProof highlights the red flags and explains each one in plain language. Practice mode trains you to spot scams yourself.

Built for **IceHacks 2026**. Everything runs in your browser: links are never opened, and nothing is sent anywhere.

**Live demo:** https://dagmawi1-lang.github.io/phishproof/

## The problem

Phishing is the most common way people get hacked, and students are a big target: fake "unpaid fee" texts, gift-card requests from a "principal", and lookalike login pages. Most people are told "be careful" but never shown *what* to look for.

## What it does

**Check a message.** Paste an email or text. PhishProof checks it for **19 warning signs**:

| Area | What it catches |
|---|---|
| Sender | lookalike domains (`paypa1`, `rnicrosoft`, one-letter typos), brand names from Gmail/Outlook, "principal" on a free email account, Reply-To going somewhere else |
| Links | link text that hides a different destination, bare IP links, punycode, URL shorteners, risky domain endings, the `@` trick, login links without HTTPS, brand names buried in other domains (`paypal.com.secure-login.net`) |
| Language | urgent pressure, requests for passwords/codes, gift cards, crypto, prizes, generic greetings, ALL-CAPS alarm |
| Attachments | disguised files like `invoice.pdf.exe` and other risky file types |

You get a **risk score**, a verdict (*Likely phishing / Suspicious / No red flags*), and for each flag **what it means and what to do**.

**Practice.** Six realistic messages, a mix of phishing and legitimate ones. Decide which is which, then see the explanation and the red flags PhishProof found. Spotting phishing is a skill, and practice builds it.

## Privacy and safety

- No server, account or tracking. A Content-Security-Policy with `connect-src 'none'` blocks all network requests.
- Links in pasted messages are **never opened or fetched**.
- Pasted HTML is never run.

## Run it

Open `index.html` in a browser, or use the live demo.

## Tests

35 automated Playwright tests run in headless Chromium. They cover every rule, real domains that must *not* be flagged, all six practice messages, keyboard navigation, the quiz, and checks that no network requests are made and pasted HTML never runs.

```bash
npm install
npx playwright install chromium
npm test
```

Accessibility: PhishProof scores 100/100 in [AccessLens](https://github.com/dagmawi1-lang/accesslens).

## How it's built

Plain HTML, CSS and JavaScript, with no framework or build step.
- `src/analyzer.js`: the detection engine. It includes lookalike-character normalisation (`rn`→`m`, `1`→`l`, `0`→`o`), edit distance for typo domains, link-text vs destination comparison, and sender/Reply-To parsing.
- `src/samples.js`: practice messages, all made up.
- `src/app.js`: the UI, accessible tabs and quiz.

## Challenges

Catching lookalikes without false alarms. `mail.google.com` and `paypal.com` must pass, while `paypa1-security.com` and `rnicrosoft-support.co` must not. Normalising lookalike characters before comparing, together with checking the registrable domain rather than the whole hostname, solved it.

## What's next

- A browser extension that checks emails right inside Gmail or Outlook
- More practice messages, including SMS and social-media DMs
- A teacher mode for running phishing-awareness lessons

## AI disclosure

Built with AI coding assistance (Claude), which helped write and test the code and docs.

## License

MIT
