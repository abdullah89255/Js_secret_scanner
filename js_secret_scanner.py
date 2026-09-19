#!/usr/bin/env python3
"""
JS Secret Scanner - Download and analyze JavaScript files for secrets
"""

import os
import re
import sys
import json
import hashlib
import argparse
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ============================================================
# SECRET DETECTION PATTERNS
# ============================================================
# Each pattern: (name, regex, severity)
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "HIGH"),
    ("AWS Secret Key", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "HIGH"),
    ("AWS MWS Key", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "HIGH"),
    
    # Google
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    ("Google OAuth ID", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "MEDIUM"),
    ("Google OAuth Access Token", r"ya29\.[0-9A-Za-z\-_]+", "HIGH"),
    
    # GitHub
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "HIGH"),
    ("GitHub Personal Access Token (old)", r"ghp_[A-Za-z0-9]{36}", "HIGH"),
    ("GitHub OAuth", r"gho_[A-Za-z0-9]{36}", "HIGH"),
    ("GitHub App Token", r"(ghu|ghs)_[A-Za-z0-9]{36}", "HIGH"),
    
    # GitLab
    ("GitLab Personal Access Token", r"glpat-[A-Za-z0-9\-_]{20}", "HIGH"),
    
    # Slack
    ("Slack Token", r"xox[baprs]-([0-9a-zA-Z]{10,48})", "HIGH"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", "HIGH"),
    
    # Stripe
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24}", "MEDIUM"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24}", "HIGH"),
    
    # Twilio
    ("Twilio Account SID", r"AC[a-z0-9]{32}", "MEDIUM"),
    ("Twilio Auth Token", r"(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]", "HIGH"),
    
    # SendGrid
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "HIGH"),
    
    # Mailgun
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "HIGH"),
    
    # Heroku
    ("Heroku API Key", r"(?i)heroku(.{0,20})?['\"][0-9a-f]{32}['\"]", "HIGH"),
    
    # Facebook
    ("Facebook Access Token", r"EAACEdEose0cBA[0-9A-Za-z]+", "HIGH"),
    
    # Twitter
    ("Twitter Access Token", r"[1-9][0-9]+-[0-9a-zA-Z]{40}", "MEDIUM"),
    
    # Private Keys
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "CRITICAL"),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "CRITICAL"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "CRITICAL"),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "CRITICAL"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL"),
    ("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", "CRITICAL"),
    
    # JWT
    ("JSON Web Token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM"),
    
    # Basic Auth in URL
    ("Basic Auth in URL", r"https?://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@]+@[a-zA-Z0-9_\-\.]+", "HIGH"),
    
    # Generic API keys
    ("Generic API Key", r"(?i)(api[_\-]?key|apikey)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?", "MEDIUM"),
    ("Generic Secret", r"(?i)(secret|passwd|password|pwd|token)['\"\s:=]+['\"]([a-zA-Z0-9_\-!@#$%^&*]{8,64})['\"]", "MEDIUM"),
    
    # Database URLs
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s'\"]+", "HIGH"),
    ("PostgreSQL Connection String", r"postgres(?:ql)?://[^\s'\"]+", "HIGH"),
    ("MySQL Connection String", r"mysql://[^\s'\"]+", "HIGH"),
    ("Redis Connection String", r"redis://[^\s'\"]+", "HIGH"),
    
    # Firebase
    ("Firebase URL", r"https://[a-z0-9-]+\.firebaseio\.com", "MEDIUM"),
    ("Firebase Cloud Messaging", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "HIGH"),
    
    # Cloudinary
    ("Cloudinary URL", r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+", "HIGH"),
    
    # npm
    ("npm Token", r"npm_[A-Za-z0-9]{36}", "HIGH"),
    
    # DigitalOcean
    ("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "HIGH"),
    ("DigitalOcean OAuth", r"doo_v1_[a-f0-9]{64}", "HIGH"),
    
    # Shopify
    ("Shopify Access Token", r"shpat_[a-fA-F0-9]{32}", "HIGH"),
    ("Shopify Shared Secret", r"shpss_[a-fA-F0-9]{32}", "HIGH"),
    
    # Square
    ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "HIGH"),
    ("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "HIGH"),
    
    # PayPal
    ("PayPal Braintree Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "HIGH"),
    
    # Picatic
    ("Picatic API Key", r"sk_live_[0-9a-z]{32}", "HIGH"),
    
    # Discord
    ("Discord Bot Token", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", "HIGH"),
    ("Discord Webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "HIGH"),
    
    # Telegram
    ("Telegram Bot Token", r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "HIGH"),
    
    # Generic high entropy (long strings)
    ("High Entropy String", r"['\"][A-Za-z0-9+/=_\-]{40,}['\"]", "LOW"),
]

# Compiled patterns for performance
COMPILED_PATTERNS = [(name, re.compile(pattern), severity) for name, pattern, severity in SECRET_PATTERNS]


# ============================================================
# DOWNLOADER
# ============================================================
class JSDownloader:
    def __init__(self, output_dir="downloads", max_workers=10, timeout=30, user_agent=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.user_agent})
        return session

    @staticmethod
    def _url_to_filename(url):
        """Create a safe, unique filename from a URL."""
        parsed = urlparse(url)
        # Build a readable prefix
        base = (parsed.netloc + parsed.path).strip("/")
        # Remove weird chars
        base = re.sub(r"[^a-zA-Z0-9._\-]", "_", base)
        # Avoid overly long filenames
        if len(base) > 100:
            base = base[:100]
        # Add a short hash to avoid collisions
        digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
        if not base.endswith(".js"):
            base += ".js"
        return f"{base}_{digest}"

    def download(self, url):
        """Download a single JS file. Returns (url, path, success, error)."""
        url = url.strip()
        if not url or url.startswith("#"):
            return url, None, False, "empty/comment"

        if not url.startswith(("http://", "https://")):
            return url, None, False, "invalid scheme"

        filename = self._url_to_filename(url)
        filepath = self.output_dir / filename

        # Skip if already downloaded
        if filepath.exists() and filepath.stat().st_size > 0:
            return url, str(filepath), True, "cached"

        try:
            resp = self.session.get(url, timeout=self.timeout, stream=True, allow_redirects=True)
            resp.raise_for_status()

            # Only save if it looks like text/javascript
            ctype = resp.headers.get("Content-Type", "").lower()
            if ctype and not any(x in ctype for x in ("javascript", "ecmascript", "text/plain", "text/html", "application/json", "octet-stream")):
                # Still save but note the content type
                pass

            with open(filepath, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            # Sanity check: ensure file isn't empty
            if filepath.stat().st_size == 0:
                filepath.unlink(missing_ok=True)
                return url, None, False, "empty response"

            return url, str(filepath), True, "downloaded"

        except requests.exceptions.Timeout:
            return url, None, False, "timeout"
        except requests.exceptions.SSLError:
            return url, None, False, "ssl error"
        except requests.exceptions.ConnectionError:
            return url, None, False, "connection error"
        except requests.exceptions.HTTPError as e:
            return url, None, False, f"http {e.response.status_code}"
        except Exception as e:
            return url, None, False, f"error: {e.__class__.__name__}"

    def download_all(self, urls):
        """Download all URLs concurrently."""
        results = []
        total = len(urls)

        print(f"{Fore.CYAN}[*] Downloading {total} URLs with {self.max_workers} workers...")
        print(f"{Fore.CYAN}[*] Output directory: {self.output_dir.resolve()}\n")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.download, url): url for url in urls}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                url, path, success, msg = future.result()
                results.append((url, path, success, msg))

                if success:
                    icon = f"{Fore.GREEN}✓"
                    detail = msg
                else:
                    icon = f"{Fore.RED}✗"
                    detail = msg

                # Truncate long URLs for display
                display_url = url if len(url) < 80 else url[:77] + "..."
                print(f"  {icon} [{completed}/{total}] {display_url} {Fore.YELLOW}({detail})")

        return results


# ============================================================
# ANALYZER
# ============================================================
class SecretAnalyzer:
    def __init__(self, max_file_size_mb=20):
        self.max_file_size = max_file_size_mb * 1024 * 1024

    @staticmethod
    def _get_line_number(text, match_start):
        return text[:match_start].count("\n") + 1

    @staticmethod
    def _get_context(text, match_start, match_end, context=60):
        start = max(0, match_start - context)
        end = min(len(text), match_end + context)
        snippet = text[start:end].replace("\n", " ").strip()
        return snippet

    def analyze_file(self, filepath, url=None):
        """Analyze a single file for secrets. Returns list of findings."""
        findings = []
        path = Path(filepath)

        try:
            size = path.stat().st_size
            if size > self.max_file_size:
                return findings

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return findings

        # Deduplicate: track (pattern_name, matched_value) pairs
        seen = set()

        for name, pattern, severity in COMPILED_PATTERNS:
            for match in pattern.finditer(content):
                matched = match.group(0)
                # Skip super common false positives
                if self._is_false_positive(name, matched):
                    continue

                key = (name, matched)
                if key in seen:
                    continue
                seen.add(key)

                line_no = self._get_line_number(content, match.start())
                context = self._get_context(content, match.start(), match.end())

                findings.append({
                    "file": str(path),
                    "url": url,
                    "type": name,
                    "severity": severity,
                    "match": matched[:200],
                    "line": line_no,
                    "context": context,
                })

        return findings

    @staticmethod
    def _is_false_positive(name, matched):
        """Filter out obvious false positives."""
        # Skip JWT-like example tokens
        if name == "JSON Web Token" and "example" in matched.lower():
            return True

        # Skip common placeholder values
        placeholders = {
            "your_api_key", "your-api-key", "api_key_here",
            "xxxxxxxx", "aaaaaaaa", "00000000", "1234567890",
            "changeme", "placeholder", "example", "test_key",
            "your_secret", "insert_", "replace_",
        }
        lower = matched.lower()
        for p in placeholders:
            if p in lower:
                return True

        # Skip generic secrets that are clearly not secrets
        if name == "Generic Secret":
            if len(set(matched)) < 4:  # too few unique chars
                return True

        return False

    def analyze_all(self, files):
        """Analyze all files. `files` is list of (url, path) tuples."""
        all_findings = []
        total = len(files)

        print(f"\n{Fore.CYAN}[*] Analyzing {total} files for secrets...\n")

        for i, (url, path) in enumerate(files, 1):
            findings = self.analyze_file(path, url)
            if findings:
                all_findings.extend(findings)

        return all_findings


# ============================================================
# REPORTER
# ============================================================
SEVERITY_COLORS = {
    "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    "HIGH": Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.BLUE,
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_report(findings):
    """Print findings to terminal."""
    if not findings:
        print(f"{Fore.GREEN}[+] No secrets found.")
        return

    # Sort by severity then file
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["file"], f["line"]))

    print(f"\n{Fore.RED}{Style.BRIGHT}{'=' * 70}")
    print(f"{Fore.RED}{Style.BRIGHT}  🔍 SECRETS FOUND: {len(findings)}")
    print(f"{Fore.RED}{Style.BRIGHT}{'=' * 70}\n")

    current_file = None
    for f in findings:
        if f["file"] != current_file:
            current_file = f["file"]
            print(f"\n{Fore.CYAN}{Style.BRIGHT}📄 {current_file}")
            if f["url"]:
                print(f"   {Fore.CYAN}↳ {f['url']}")

        color = SEVERITY_COLORS.get(f["severity"], "")
        print(f"   {color}[{f['severity']}]{Style.RESET_ALL} {Fore.WHITE}{f['type']}{Style.RESET_ALL}")
        print(f"     Line {f['line']}: {Fore.YELLOW}{f['match']}{Style.RESET_ALL}")
        if f["context"]:
            print(f"     Context: {Fore.LIGHTBLACK_EX}{f['context']}{Style.RESET_ALL}")


def save_reports(findings, json_path="secrets_report.json", txt_path="secrets_report.txt"):
    """Save findings to JSON and text reports."""
    # JSON report
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }, f, indent=2)

    # Text report
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"JS Secret Scanner Report\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write("=" * 70 + "\n\n")

        findings_sorted = sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["file"]))
        for f_item in findings_sorted:
            f.write(f"[{f_item['severity']}] {f_item['type']}\n")
            f.write(f"  File: {f_item['file']}\n")
            if f_item["url"]:
                f.write(f"  URL: {f_item['url']}\n")
            f.write(f"  Line: {f_item['line']}\n")
            f.write(f"  Match: {f_item['match']}\n")
            f.write(f"  Context: {f_item['context']}\n")
            f.write("-" * 70 + "\n")

    print(f"\n{Fore.GREEN}[+] JSON report saved to: {json_path}")
    print(f"{Fore.GREEN}[+] Text report saved to: {txt_path}")


# ============================================================
# MAIN
# ============================================================
def read_urls(filepath):
    """Read URLs from file, one per line."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return urls


def main():
    parser = argparse.ArgumentParser(
        description="Download JS files from URLs and analyze them for secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_secret_scanner.py js_files.txt
  python js_secret_scanner.py js_files.txt -o ./js_downloads -w 20
  python js_secret_scanner.py js_files.txt --urls-only
  python js_secret_scanner.py js_files.txt --analyze-only ./js_downloads
        """,
    )
    parser.add_argument("input", help="File containing URLs (one per line)")
    parser.add_argument("-o", "--output", default="js_downloads", help="Output directory (default: js_downloads)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent downloads (default: 10)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--urls-only", action="store_true", help="Only download, skip analysis")
    parser.add_argument("--analyze-only", metavar="DIR", help="Skip download, analyze files in DIR")
    parser.add_argument("--json-out", default="secrets_report.json", help="JSON report output path")
    parser.add_argument("--txt-out", default="secrets_report.txt", help="Text report output path")
    parser.add_argument("--max-size", type=int, default=20, help="Max file size in MB for analysis (default: 20)")

    args = parser.parse_args()

    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          JS Secret Scanner - Download & Analyze          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(Style.RESET_ALL)

    downloaded = []  # list of (url, path)

    # ---- Phase 1: Download ----
    if not args.analyze_only:
        if not os.path.isfile(args.input):
            print(f"{Fore.RED}[!] Input file not found: {args.input}")
            sys.exit(1)

        urls = read_urls(args.input)
        if not urls:
            print(f"{Fore.RED}[!] No URLs found in {args.input}")
            sys.exit(1)

        print(f"{Fore.GREEN}[+] Loaded {len(urls)} URLs from {args.input}")

        downloader = JSDownloader(
            output_dir=args.output,
            max_workers=args.workers,
            timeout=args.timeout,
        )
        results = downloader.download_all(urls)

        success = sum(1 for _, _, ok, _ in results if ok)
        print(f"\n{Fore.GREEN}[+] Downloads complete: {success}/{len(urls)} successful")

        for url, path, ok, _ in results:
            if ok and path:
                downloaded.append((url, path))
    else:
        # Analyze-only mode: enumerate files in directory
        d = Path(args.analyze_only)
        if not d.is_dir():
            print(f"{Fore.RED}[!] Directory not found: {args.analyze_only}")
            sys.exit(1)
        for f in sorted(d.rglob("*")):
            if f.is_file():
                downloaded.append((None, str(f)))
        print(f"{Fore.GREEN}[+] Found {len(downloaded)} files in {args.analyze_only}")

    # ---- Phase 2: Analyze ----
    if args.urls_only:
        print(f"\n{Fore.YELLOW}[*] --urls-only specified, skipping analysis.")
        return

    if not downloaded:
        print(f"{Fore.RED}[!] No files to analyze.")
        sys.exit(1)

    analyzer = SecretAnalyzer(max_file_size_mb=args.max_size)
    findings = analyzer.analyze_all(downloaded)

    # ---- Phase 3: Report ----
    print_report(findings)

    if findings:
        save_reports(findings, args.json_out, args.txt_out)

    # Summary
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}")
    print(f"  Files downloaded: {len(downloaded)}")
    print(f"  Total findings:   {len(findings)}")

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_sev:
            color = SEVERITY_COLORS[sev]
            print(f"  {color}{sev}: {by_sev[sev]}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.")
        sys.exit(130)
