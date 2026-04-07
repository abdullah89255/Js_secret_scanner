# Js_secret_scanner

---

## How to use it

**1. Populate `js_files.txt`** — one JS URL per line:
```
https://target.com/static/js/app.js
https://target.com/assets/bundle.js
```

**2. Run the scanner:**
```bash
# Basic usage
python3 js_secret_scanner.py

# Custom options
python3 js_secret_scanner.py -i js_files.txt -o report.html -t 5
```

**3. View the report** — open `scan_report.html` in any browser.

---

## What it detects (60+ patterns across 7 categories)

| Category | Examples |
|---|---|
| **Cloud API Keys** | AWS, GCP, Azure, Firebase, Heroku |
| **Payment** | Stripe live/test, Square, PayPal |
| **Messaging/Auth** | Slack, Twilio, SendGrid, Mailgun |
| **Dev Tokens** | GitHub, GitLab, NPM, Hugging Face, OpenAI |
| **Private Keys** | RSA, EC, SSH, PGP |
| **DB Connections** | MongoDB, MySQL, PostgreSQL, Redis |
| **Code Patterns** | Hardcoded passwords, JWT, Bearer tokens, Basic Auth URLs |

## Flags

| Flag | Description |
|---|---|
| `-i` | Input file (default: `js_files.txt`) |
| `-o` | HTML output report (default: `scan_report.html`) |
| `-j` | JSON output report (default: `scan_report.json`) |
| `-t` | Threads (default: `3` — be polite to Wayback) |
| `-q` | Quiet mode |

The tool uses the **Wayback CDX API** to find historical snapshots of each JS file, scans each snapshot, and generates a clickable HTML report with severity badges (Critical / High / Medium / Low). All matched values are **redacted** in the output for safety.
