# Js_secret_scanner

## Installation

```bash
pip install requests colorama
```

## Usage

**Basic usage:**
```bash
python js_secret_scanner.py js_files.txt
```

**Custom output directory and more workers:**
```bash
python js_secret_scanner.py js_files.txt -o ./js_downloads -w 20
```

**Download only (no analysis):**
```bash
python js_secret_scanner.py js_files.txt --urls-only
```

**Analyze already-downloaded files:**
```bash
python js_secret_scanner.py js_files.txt --analyze-only ./js_downloads
```

## Features

### Downloader
- **Concurrent downloads** with configurable worker count (default 10)
- **Retry logic** for transient failures (429, 5xx errors)
- **Safe filenames** derived from URLs with SHA1 hash suffix to prevent collisions
- **Caching** — already-downloaded files are skipped on re-runs
- **No size limits** for downloads

### Secret Detection (60+ patterns)
- **Cloud providers:** AWS, GCP, Azure, DigitalOcean, Heroku, Firebase
- **Code hosting:** GitHub (all token types), GitLab
- **Payments:** Stripe (live/test), PayPal/Braintree, Square, Shopify
- **Comms:** Slack (tokens + webhooks), Discord, Telegram, Twilio, SendGrid, Mailgun
- **Crypto:** RSA, DSA, EC, OpenSSH, PGP private keys
- **Databases:** MongoDB, PostgreSQL, MySQL, Redis connection strings
- **Others:** JWTs, OAuth tokens, generic API keys/secrets, basic auth in URLs, high-entropy strings

### Analysis Features
- **Severity levels:** CRITICAL, HIGH, MEDIUM, LOW
- **Deduplication** within each file
- **False positive filtering** for common placeholders (`your_api_key`, `xxxxxxxx`, etc.)
- **Context snippets** around each finding
- **Line numbers** for easy location

### Reporting
- **Color-coded** terminal output (via colorama)
- **JSON report** for automation/tooling
- **Text report** for easy reading

## Notes

1. **Only scan what you're authorized to scan.** Downloading and analyzing JS files from sites you don't own may violate terms of service or laws.
2. The **high-entropy string** detector can produce false positives — it's flagged as LOW severity for a reason.
3. Files are saved even if the content-type isn't exactly JS, since many CDNs serve JS as `text/plain` or `application/octet-stream`.
4. You can easily **extend the patterns list** at the top of the script — just add `(name, regex, severity)` tuples.
