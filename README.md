# FakeLink Detector

Simple web app to quickly check if a URL looks **safe** or **suspicious** using client-side heuristics.

## Features

- Paste any URL and get an instant verdict
- Highlights whether the link looks safe or suspicious
- Shows short reasons explaining the decision
- Clean, responsive UI in pure HTML/CSS/JavaScript
- No backend — everything runs in the browser

## How it works

FakeLink Detector uses simple heuristics to flag risky patterns in URLs, such as:

- Suspicious domains and subdomains
- Very long or obfuscated URLs
- Mismatched brand names vs. domain
- Other common phishing-style patterns

> ⚠️ **Note:** This is a helper tool, not a security guarantee. Always double‑check suspicious emails and links manually.

## Getting started

1. Clone the repository:

```bash
git clone https://github.com/madiha-404/fakelinks-detector.git
cd fakelinks-detector
