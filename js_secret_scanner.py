#!/usr/bin/env python3
"""
JS Secret Scanner - Checks JavaScript files (via Wayback Machine) for sensitive data
Usage: python3 js_secret_scanner.py [--input js_files.txt] [--output report.html] [--threads 5]
"""

import re
import sys
import time
import json
import argparse
import threading
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
#  SENSITIVE DATA PATTERNS
# ─────────────────────────────────────────────
PATTERNS = {
    # API Keys & Tokens
    "AWS Access Key":           r'(?<![A-Z0-9])(AKIA|AIPA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
    "AWS Secret Key":           r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":           r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth Token":       r'ya29\.[0-9A-Za-z\-_]+',
    "GitHub Token":             r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
    "GitHub Classic Token":     r'[gG][iI][tT][hH][uU][bB].{0,30}["\']([0-9a-zA-Z]{40})["\']',
    "Slack Token":              r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9]{10,12}-[a-z0-9]{32}',
    "Slack Webhook":            r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
    "Stripe Live Key":          r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Public Key":        r'pk_live_[0-9a-zA-Z]{24,}',
    "Stripe Test Key":          r'sk_test_[0-9a-zA-Z]{24,}',
    "Twilio Account SID":       r'AC[a-fA-F0-9]{32}',
    "Twilio Auth Token":        r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']',
    "SendGrid API Key":         r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    "Firebase URL":             r'https://[a-z0-9\-]+\.firebaseio\.com',
    "Firebase API Key":         r'(?i)firebase.{0,20}["\']([A-Za-z0-9\-_]{35,})["\']',
    "Mailgun API Key":          r'key-[0-9a-zA-Z]{32}',
    "Mailchimp API Key":        r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Heroku API Key":           r'[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    "Cloudinary URL":           r'cloudinary://[0-9]{9,}:[A-Za-z0-9_\-]+@[a-zA-Z0-9]+',
    "Algolia API Key":          r'(?i)algolia.{0,30}["\']([A-Za-z0-9]{32})["\']',
    "Square Access Token":      r'sq0atp-[0-9A-Za-z\-_]{22}',
    "Square OAuth Secret":      r'sq0csp-[0-9A-Za-z\-_]{43}',
    "PayPal Client ID":         r'(?i)paypal.{0,30}client.{0,10}["\']([A-Za-z0-9]{60,})["\']',
    "Shopify Token":            r'shpat_[a-fA-F0-9]{32}',
    "Shopify Secret":           r'shpss_[a-fA-F0-9]{32}',
    "Azure Storage Key":        r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
    "Okta API Token":           r'(?i)okta.{0,30}["\']([0-9a-zA-Z_\-]{42})["\']',
    "Mapbox Token":             r'pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}',
    "NPM Token":                r'npm_[A-Za-z0-9]{36}',
    "Gitlab Token":             r'glpat-[A-Za-z0-9\-_]{20}',
    "Vault Token":              r's\.[A-Za-z0-9]{24}',
    "Telegram Bot Token":       r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}',
    "OpenAI API Key":           r'sk-[A-Za-z0-9]{48}',
    "Anthropic API Key":        r'sk-ant-[A-Za-z0-9\-_]{93,}',
    "Hugging Face Token":       r'hf_[A-Za-z0-9]{39}',

    # Private Keys & Certs
    "RSA Private Key":          r'-----BEGIN RSA PRIVATE KEY-----',
    "DSA Private Key":          r'-----BEGIN DSA PRIVATE KEY-----',
    "EC Private Key":           r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":          r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key":      r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":          r'-----BEGIN OPENSSH PRIVATE KEY-----',

    # Passwords & Secrets
    "Password in Code":         r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
    "Secret in Code":           r'(?i)(secret|secretkey|secret_key)\s*[=:]\s*["\'][^"\']{6,}["\']',
    "Auth Token in Code":       r'(?i)(auth.?token|authtoken)\s*[=:]\s*["\'][^"\']{8,}["\']',
    "Bearer Token":             r'[Bb]earer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',
    "Basic Auth in URL":        r'https?://[^:]+:[^@]+@[^/\s]+',
    "API Key in Code":          r'(?i)(api.?key|apikey|access.?key)\s*[=:]\s*["\'][A-Za-z0-9\-_./+=]{10,}["\']',
    "JWT Token":                r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+',

    # Connection Strings
    "MongoDB URI":              r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+',
    "MySQL Connection":         r'mysql://[^:]+:[^@]+@[^\s"\']+',
    "PostgreSQL Connection":    r'postgres(ql)?://[^:]+:[^@]+@[^\s"\']+',
    "Redis Connection":         r'redis://[^:]+:[^@]+@[^\s"\']+',
    "JDBC Connection":          r'jdbc:[a-z]+://[^\s"\']+password=[^&\s"\']+',
    "FTP Credentials":          r'ftp://[^:]+:[^@]+@[^\s"\']+',

    # Internal Infra
    "Internal IP":              r'(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
    "Localhost Reference":      r'http://localhost(:\d+)?[/\w\-\.?=&%]*',
    "Debug/Dev Endpoint":       r'(?i)(staging|dev|internal|test|debug|admin)\.(api|backend|server)\.[a-z]{2,}',
    "S3 Bucket (private)":      r'https?://[a-z0-9\-]+\.s3\.amazonaws\.com/[^\s"\']+',

    # Misc Sensitive
    "Credit Card Number":       r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    "Social Security Number":   r'\b\d{3}-\d{2}-\d{4}\b',
    "Hardcoded Email+Pass":     r'(?i)email\s*[=:]\s*["\'][^"\']+@[^"\']+["\'].{0,80}(password|passwd)\s*[=:]\s*["\'][^"\']+["\']',
}

SEVERITY = {
    "CRITICAL": ["RSA Private Key","DSA Private Key","EC Private Key","PGP Private Key",
                 "Generic Private Key","SSH Private Key","AWS Secret Key","Password in Code",
                 "Secret in Code","MongoDB URI","MySQL Connection","PostgreSQL Connection",
                 "Redis Connection","JDBC Connection","Stripe Live Key","Basic Auth in URL",
                 "Hardcoded Email+Pass","Credit Card Number","Social Security Number","Bearer Token"],
    "HIGH":     ["AWS Access Key","GitHub Token","GitHub Classic Token","Slack Token",
                 "Slack Webhook","Stripe Test Key","SendGrid API Key","Firebase API Key",
                 "Mailgun API Key","Azure Storage Key","OpenAI API Key","Anthropic API Key",
                 "Heroku API Key","Shopify Token","Shopify Secret","NPM Token","Gitlab Token",
                 "Telegram Bot Token","Hugging Face Token","Okta API Token","JWT Token",
                 "FTP Credentials","Auth Token in Code","API Key in Code"],
    "MEDIUM":   ["Google API Key","Google OAuth Token","Firebase URL","Mailchimp API Key",
                 "Stripe Public Key","Twilio Account SID","Twilio Auth Token","Algolia API Key",
                 "Square Access Token","Square OAuth Secret","PayPal Client ID","Cloudinary URL",
                 "Mapbox Token","Vault Token","Okta API Token","S3 Bucket (private)",
                 "Debug/Dev Endpoint"],
    "LOW":      ["Internal IP","Localhost Reference","Shopify Secret","JDBC Connection"],
}

def get_severity(pattern_name):
    for sev, names in SEVERITY.items():
        if pattern_name in names:
            return sev
    return "MEDIUM"

# ─────────────────────────────────────────────
#  WAYBACK MACHINE FETCHER
# ─────────────────────────────────────────────
WAYBACK_CDX  = "http://web.archive.org/cdx/search/cdx"
WAYBACK_BASE = "http://web.archive.org/web"

def get_wayback_snapshots(url, limit=3):
    """Get available Wayback Machine snapshots for a URL."""
    params = urllib.parse.urlencode({
        "url":    url,
        "output": "json",
        "limit":  limit,
        "fl":     "timestamp,statuscode,digest",
        "filter": "statuscode:200",
        "collapse":"digest",
    })
    api_url = f"{WAYBACK_CDX}?{params}"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "JS-SecretScanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        if len(data) <= 1:
            return []
        return [row[0] for row in data[1:]]   # list of timestamps
    except Exception as e:
        return []

def fetch_wayback_content(url, timestamp):
    """Fetch JS file content from Wayback Machine."""
    wb_url = f"{WAYBACK_BASE}/{timestamp}if_/{url}"
    try:
        req = urllib.request.Request(wb_url, headers={"User-Agent": "JS-SecretScanner/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace"), wb_url
    except Exception as e:
        return None, wb_url

def fetch_direct(url):
    """Try fetching URL directly as fallback."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "JS-SecretScanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None

# ─────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────
def scan_content(content, source_url):
    """Scan JS content for all sensitive patterns. Returns list of findings."""
    findings = []
    lines = content.splitlines()
    compiled = {name: re.compile(pat) for name, pat in PATTERNS.items()}

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        for name, regex in compiled.items():
            for match in regex.finditer(line):
                matched_val = match.group(0)
                # Redact middle of value for safety
                if len(matched_val) > 20:
                    display = matched_val[:8] + "..." + matched_val[-4:]
                else:
                    display = matched_val[:6] + "***"
                findings.append({
                    "pattern":  name,
                    "severity": get_severity(name),
                    "line_no":  line_no,
                    "matched":  display,
                    "context":  stripped[:120],
                    "source":   source_url,
                })
    return findings

def process_js_url(url, results_store, lock, verbose=True):
    """Full pipeline: Wayback snapshots → fetch → scan."""
    url = url.strip()
    if not url or url.startswith("#"):
        return

    entry = {
        "url":       url,
        "snapshots": [],
        "findings":  [],
        "errors":    [],
        "status":    "pending",
    }

    if verbose:
        print(f"  [→] {url}")

    # 1. Get snapshots
    timestamps = get_wayback_snapshots(url, limit=3)
    time.sleep(0.5)   # polite delay

    if not timestamps:
        entry["errors"].append("No Wayback snapshots found — trying direct fetch")
        content = fetch_direct(url)
        if content:
            entry["snapshots"].append({"timestamp": "live", "wb_url": url})
            findings = scan_content(content, url)
            entry["findings"].extend(findings)
            entry["status"] = "scanned_direct"
        else:
            entry["status"] = "no_snapshot"
            entry["errors"].append("Direct fetch also failed")
    else:
        # 2. Scan each snapshot (deduplicate by digest is already done by CDX)
        for ts in timestamps:
            content, wb_url = fetch_wayback_content(url, ts)
            time.sleep(0.3)
            snap = {"timestamp": ts, "wb_url": wb_url}
            if content:
                findings = scan_content(content, wb_url)
                snap["finding_count"] = len(findings)
                entry["findings"].extend(findings)
                entry["status"] = "scanned"
            else:
                snap["finding_count"] = 0
                entry["errors"].append(f"Failed to fetch snapshot {ts}")
            entry["snapshots"].append(snap)

    # Deduplicate findings by (pattern, line_no, matched)
    seen = set()
    deduped = []
    for f in entry["findings"]:
        key = (f["pattern"], f["line_no"], f["matched"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    entry["findings"] = deduped

    if verbose:
        cnt = len(entry["findings"])
        tag = f"⚠ {cnt} findings" if cnt else "✓ clean"
        print(f"      {tag}  [{entry['status']}]")

    with lock:
        results_store.append(entry)

# ─────────────────────────────────────────────
#  HTML REPORT
# ─────────────────────────────────────────────
SEV_COLOR = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#3498db"}

def build_html_report(results, output_path):
    total_urls    = len(results)
    total_findings= sum(len(r["findings"]) for r in results)
    clean_urls    = sum(1 for r in results if not r["findings"])
    vuln_urls     = total_urls - clean_urls
    sev_counts    = defaultdict(int)
    for r in results:
        for f in r["findings"]:
            sev_counts[f["severity"]] += 1

    rows = ""
    for r in sorted(results, key=lambda x: -len(x["findings"])):
        url        = r["url"]
        snaps      = len(r["snapshots"])
        snap_ts    = ", ".join(s["timestamp"] for s in r["snapshots"][:2]) or "—"
        status     = r["status"]
        findings   = r["findings"]
        f_count    = len(findings)
        badge_color= "#e74c3c" if f_count else "#27ae60"
        badge_txt  = f"{f_count} finding(s)" if f_count else "Clean"

        finding_rows = ""
        for f in findings:
            sc = SEV_COLOR.get(f["severity"], "#888")
            finding_rows += f"""
            <tr>
              <td><span style="background:{sc};color:#fff;padding:2px 7px;border-radius:4px;font-size:12px">{f['severity']}</span></td>
              <td>{f['pattern']}</td>
              <td style="font-family:monospace;font-size:12px">{f['matched']}</td>
              <td style="text-align:center">{f['line_no']}</td>
              <td style="font-family:monospace;font-size:11px;max-width:400px;word-break:break-all">{f['context'][:100]}</td>
            </tr>"""

        snap_links = " | ".join(
            f'<a href="{s["wb_url"]}" target="_blank">{s["timestamp"]}</a>'
            for s in r["snapshots"]
        ) or "—"

        rows += f"""
        <tr class="url-row" onclick="toggle('{url}')">
          <td style="font-family:monospace;font-size:13px;word-break:break-all">{url}</td>
          <td style="text-align:center">{snaps}</td>
          <td>{snap_links}</td>
          <td style="text-align:center">{status}</td>
          <td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:12px;font-size:12px">{badge_txt}</span></td>
        </tr>
        <tr id="details-{url}" style="display:none">
          <td colspan="5" style="background:#f8f9fa;padding:0">
            {'<table style="width:100%;border-collapse:collapse"><thead><tr style="background:#dee2e6"><th>Severity</th><th>Pattern</th><th>Match (redacted)</th><th>Line</th><th>Context</th></tr></thead><tbody>' + finding_rows + '</tbody></table>' if findings else '<div style="padding:10px;color:green">✓ No sensitive data found in this file.</div>'}
            {'<div style="padding:6px 10px;font-size:12px;color:#666">Errors: ' + '; '.join(r['errors']) + '</div>' if r['errors'] else ''}
          </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Secret Scanner Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#f0f2f5;color:#333}}
  header{{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:28px 40px}}
  header h1{{font-size:26px;font-weight:700;margin-bottom:4px}}
  header p{{color:#adb5bd;font-size:14px}}
  .container{{max-width:1300px;margin:24px auto;padding:0 20px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:24px}}
  .stat{{background:#fff;border-radius:10px;padding:18px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .stat .val{{font-size:32px;font-weight:700;margin-bottom:4px}}
  .stat .lbl{{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden;margin-bottom:24px}}
  .card-header{{padding:16px 20px;background:#343a40;color:#fff;font-weight:600;display:flex;justify-content:space-between;align-items:center}}
  table{{width:100%;border-collapse:collapse}}
  thead tr{{background:#e9ecef}}
  thead th{{padding:10px 12px;text-align:left;font-size:13px;color:#495057;font-weight:600;white-space:nowrap}}
  tbody tr{{border-bottom:1px solid #f0f0f0}}
  tbody tr:hover{{background:#f8f9fa}}
  tbody td{{padding:10px 12px;font-size:13px;vertical-align:middle}}
  .url-row{{cursor:pointer}}
  .url-row:hover td:first-child{{color:#0066cc;text-decoration:underline}}
  .badge-sev{{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}}
  .badge-sev span{{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;color:#fff}}
  footer{{text-align:center;color:#999;font-size:12px;padding:20px}}
</style>
</head>
<body>
<header>
  <h1>🔍 JS Secret Scanner — Wayback Machine Edition</h1>
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; {total_urls} URLs scanned</p>
</header>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="val" style="color:#e74c3c">{total_findings}</div><div class="lbl">Total Findings</div></div>
    <div class="stat"><div class="val" style="color:#e67e22">{vuln_urls}</div><div class="lbl">Vulnerable Files</div></div>
    <div class="stat"><div class="val" style="color:#27ae60">{clean_urls}</div><div class="lbl">Clean Files</div></div>
    <div class="stat"><div class="val" style="color:#e74c3c">{sev_counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="val" style="color:#e67e22">{sev_counts['HIGH']}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="val" style="color:#f1c40f">{sev_counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="val" style="color:#3498db">{sev_counts['LOW']}</div><div class="lbl">Low</div></div>
  </div>
  <div class="card">
    <div class="card-header">
      <span>Scan Results — Click a row to expand findings</span>
      <span style="font-size:13px;font-weight:400">{total_urls} files</span>
    </div>
    <table>
      <thead><tr>
        <th>JS File URL</th><th>Snapshots</th><th>Wayback Links</th><th>Status</th><th>Result</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
<footer>JS Secret Scanner &nbsp;•&nbsp; Wayback Machine &nbsp;•&nbsp; For authorized security research only</footer>
<script>
function toggle(url){{
  var el=document.getElementById('details-'+url);
  el.style.display=(el.style.display==='none'?'':'none');
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

def build_json_report(results, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="JS Secret Scanner — checks JS files via Wayback Machine for sensitive data"
    )
    parser.add_argument("-i", "--input",   default="js_files.txt", help="Input file with JS URLs (one per line)")
    parser.add_argument("-o", "--output",  default="scan_report.html", help="Output HTML report filename")
    parser.add_argument("-j", "--json",    default="scan_report.json", help="Output JSON report filename")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Concurrent threads (default: 3)")
    parser.add_argument("-q", "--quiet",   action="store_true", help="Suppress per-URL output")
    args = parser.parse_args()

    # Read URLs
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[ERROR] Input file '{args.input}' not found.")
        print("Create a file with one JS URL per line, e.g.:")
        print("  https://example.com/assets/app.js")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  JS Secret Scanner — Wayback Machine Edition")
    print(f"{'='*60}")
    print(f"  Input:    {args.input} ({len(urls)} URLs)")
    print(f"  Threads:  {args.threads}")
    print(f"  Patterns: {len(PATTERNS)}")
    print(f"{'='*60}\n")

    results = []
    lock    = threading.Lock()
    sem     = threading.Semaphore(args.threads)

    def worker(url):
        with sem:
            process_js_url(url, results, lock, verbose=not args.quiet)

    threads = []
    for url in urls:
        t = threading.Thread(target=worker, args=(url,))
        t.start()
        threads.append(t)
        time.sleep(0.2)   # stagger starts

    for t in threads:
        t.join()

    # Reports
    build_html_report(results, args.output)
    build_json_report(results, args.json)

    # Summary
    total_findings = sum(len(r["findings"]) for r in results)
    sev = defaultdict(int)
    for r in results:
        for f in r["findings"]:
            sev[f["severity"]] += 1

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  URLs scanned : {len(results)}")
    print(f"  Total findings: {total_findings}")
    print(f"  CRITICAL : {sev['CRITICAL']}")
    print(f"  HIGH     : {sev['HIGH']}")
    print(f"  MEDIUM   : {sev['MEDIUM']}")
    print(f"  LOW      : {sev['LOW']}")
    print(f"\n  HTML Report : {args.output}")
    print(f"  JSON Report : {args.json}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
