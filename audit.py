#!/usr/bin/env python3
"""
SiteLeak Auditor — v1.2

Improvements over v1.1:
  • Asset scanning: fetch same-origin JS/CSS per page (hash + YARA/malware/PII patterns)
  • PII/API-key pattern detector (low-false-positive, configurable list in code)
  • JSON export alongside HTML (for CI pipelines)
  • Configurable User-Agent and per-request delay (throttling)
  • Option to respect robots.txt Disallow when crawling
  • Enhanced CSP audit (flags data: and blob: for scripts; wildcard default-src)
  • Cookie audit adds SameSite checks
  • TLS: includes days-to-expiry
  • WordPress/Joomla/Laravel fingerprints improved and targeted leak checks refined
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from PySide6 import QtCore, QtGui, QtWidgets

try:
    import xml.etree.ElementTree as ET
except Exception:
    ET = None

APP_NAME = "SiteLeak Auditor"
VERSION = "1.2"
DEFAULT_UA = f"SiteLeakAuditor/{VERSION} (+legal testing with authorization)"
TIMEOUT = 12

COMMON_PORTS = [80, 443]
COMMON_DIRS = [
    "admin/", ".git/", ".svn/", "backup/", "backups/", "dump/", "dumps/", "logs/",
    "uploads/", "images/", "private/", "test/", "tmp/", ".well-known/", ".env",
]
COMMON_FILES = [
    ".env", ".env.backup", ".env.old", ".git/HEAD", ".git/config", "wp-config.php.bak",
    "config.php~", "config.old.php", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    ".DS_Store", "server-status", "phpinfo.php", "sitemap.xml", "robots.txt",
    "readme.html", "readme.txt",
]
CANDIDATE_APIS = ["api/", "v1/", "v2/", "graphql", "admin/", "rest/", "wp-json/"]

# Trackers & Suspicious JS patterns
TRACKER_SIGNATURES = {
    "Google Analytics": ["www.googletagmanager.com/gtm.js", "www.google-analytics.com/analytics.js", "gtag("],
    "Google Ads": ["pagead2.googlesyndication.com"],
    "Meta Pixel": ["connect.facebook.net/en_US/fbevents.js", "fbq("],
    "TikTok Pixel": ["analytics.tiktok.com", "ttq("],
    "Hotjar": ["static.hotjar.com/c/hotjar-"],
    "FullStory": ["fullstory.com/s/fs.js"],
}
MALWARE_JS_HINTS = [
    r"atob\(\s*'[A-Za-z0-9+/=]{40,}'\s*\)",
    r"eval\(\s*atob\(",
    r"new Function\(",
    r"document\.write\(.*<iframe",
    r"coinhive|webmine|coin\-miner|cryptonight|miner\.js",
]

# Light-touch API key/PII patterns (heuristic; may FP — severity LOW by default)
PII_PATTERNS = {
    "Google API key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub token": r"ghp_[0-9A-Za-z]{36}",
    "Stripe live key": r"sk_live_[0-9a-zA-Z]{24,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Slack token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Twilio SID": r"AC[a-f0-9]{32}",
}

# CMS fingerprints & leak paths
CMS_LEAK_PATHS: Dict[str, List[str]] = {
    "wordpress": [
        "wp-config.php.bak", "wp-config.php.save", "wp-config.php~", "readme.html",
        "wp-json/", "xmlrpc.php", "wp-content/uploads/", "wp-includes/", "wp-admin/",
        "wp-json/wp/v2/users"
    ],
    "joomla": [
        "administrator/", "readme.txt", "configuration.php.bak", "configuration.php~",
    ],
    "laravel": [
        ".env", "storage/logs/laravel.log", "_ignition/health-check", "_ignition/execute-solution",
    ],
}
CMS_META_PATTERNS = {"wordpress": re.compile(r"wordpress", re.I),
                     "joomla": re.compile(r"joomla", re.I),
                     "laravel": re.compile(r"laravel", re.I)}
CMS_COOKIE_HINTS = {
    "wordpress": ["wordpress_", "wp-settings", "wp-saving-post", "wordpress_test_cookie"],
    "joomla": ["joomla_", "joomla_remember_me"],
    "laravel": ["laravel_session"],
}

@dataclass
class AssetFinding:
    url: str
    content_type: str
    size: int
    sha256: str
    matches: List[str] = field(default_factory=list)  # YARA rule names or pattern labels

@dataclass
class Finding:
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    ip: str = ""
    ports: Dict[int, bool] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, Dict[str, str]] = field(default_factory=dict)
    tls: Dict[str, str] = field(default_factory=dict)
    pages_crawled: int = 0
    external_domains: List[str] = field(default_factory=list)
    trackers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)  # e.g., saved files
    cms: Dict[str, bool] = field(default_factory=dict)  # detected CMS flags
    assets: List[AssetFinding] = field(default_factory=list)  # scanned JS/CSS
    summary_score: Dict[str, int] = field(default_factory=dict)

# ------------------------- YARA support ---------------------------------------
class YaraBundle:
    def __init__(self, path: Optional[str]) -> None:
        self.path = path
        self.rules = None
        if path:
            try:
                import yara  # type: ignore
                rule_files = {}
                p = Path(path)
                if p.is_dir():
                    for f in p.glob("**/*.*"):
                        if f.suffix.lower() in (".yar", ".yara"):
                            rule_files[f.name] = str(f)
                elif p.is_file():
                    rule_files[p.name] = str(p)
                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
            except Exception:
                self.rules = None

    def scan_bytes(self, data: bytes) -> List[str]:
        if not (self.rules and data):
            return []
        try:
            matches = self.rules.match(data=data)
            return [m.rule for m in matches]
        except Exception:
            return []

# ------------------------- Helpers --------------------------------------------
class HttpClient:
    def __init__(self, ua: str, delay_ms: int) -> None:
        self.sess = requests.Session()
        self.ua = ua or DEFAULT_UA
        self.delay = max(0, delay_ms) / 1000.0
        self.last = 0.0

    def get(self, url: str, allow_redirects: bool = True, timeout: int = TIMEOUT) -> Optional[requests.Response]:
        # simple client-side throttle
        now = time.time()
        if self.last and self.delay and now - self.last < self.delay:
            time.sleep(self.delay - (now - self.last))
        try:
            resp = self.sess.get(url, headers={"User-Agent": self.ua}, timeout=timeout, allow_redirects=allow_redirects)
        except Exception:
            return None
        self.last = time.time()
        return resp

def is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False

def normalize_target(target: str) -> Tuple[str, Optional[str]]:
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return t.rstrip("/"), None
    return "https://" + t.rstrip("/"), "http://" + t.rstrip("/")

def tcp_check(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def get_tls_info(host: str, port: int = 443) -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version() or ""
                if cert:
                    subj = "/".join(["%s=%s" % (a[0], a[1]) for a in cert.get("subject", [])[0]]) if cert.get("subject") else ""
                    iss = "/".join(["%s=%s" % (a[0], a[1]) for a in cert.get("issuer", [])[0]]) if cert.get("issuer") else ""
                    info.update({
                        "subject": subj,
                        "issuer": iss,
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "subjectAltName": ", ".join([v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]),
                    })
                    # Expiry days (approximate)
                    try:
                        import datetime as dt
                        from email.utils import parsedate_to_datetime
                        end = parsedate_to_datetime(cert.get("notAfter"))
                        delta = (end - dt.datetime.utcnow()).days
                        info["days_to_expiry"] = str(delta)
                    except Exception:
                        pass
    except Exception:
        pass
    return info

def parse_links(base_url: str, html: str) -> Tuple[List[str], List[str], List[str]]:
    soup = BeautifulSoup(html, "html5lib")
    internal: List[str] = []
    external: List[str] = []
    assets: List[str] = []  # same-origin JS/CSS
    base_host = urlparse(base_url).netloc

    for tag in soup.find_all(["a", "script", "link", "iframe"]):
        href = tag.get("href") or tag.get("src")
        if not href:
            continue
        url = urljoin(base_url, href)
        if not url:
            continue
        netloc = urlparse(url).netloc
        if netloc and netloc != base_host:
            external.append(url)
        else:
            if tag.name in ("script", "link") and (url.endswith(".js") or "text/javascript" in (tag.get("type") or "") or (tag.name == "link" and (tag.get("rel") or [""])[0] in ("stylesheet",))):
                assets.append(url)
            else:
                internal.append(url)

    # de-dup
    internal = list(dict.fromkeys(internal))
    external = list(dict.fromkeys(external))
    assets = list(dict.fromkeys(assets))
    return internal, external, assets

def scan_for_trackers(html: str) -> List[str]:
    found = []
    for name, needles in TRACKER_SIGNATURES.items():
        if any(n in html for n in needles):
            found.append(name)
    return found

def scan_for_malware_hints(text: str) -> List[str]:
    return [pat for pat in MALWARE_JS_HINTS if re.search(pat, text, re.I)]


# --- Credential Leak Finder ---
CRED_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws[^\n]{0,40}?(secret|access)[^\n]{0,10}?[:=\s][\"\']?([0-9a-zA-Z/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}",
    "GitHub Fine-grained Token": r"github_pat_[0-9A-Za-z_]{80,120}",
    "Slack Token": r"xox(?:p|b|o|a|s)-[0-9A-Za-z-]{10,}",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}",
    "Twilio Auth Token": r"(?i)twilio[^\n]{0,40}?(token|auth)[^\n]{0,10}?[:=\s][\"\']?([0-9a-f]{32})",
    "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Private Key Block": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "Basic Auth in URL": r"https?://[^/\s:@]+:[^@\s/]+@[^/\s]+",
    "Postgres DSN": r"postgres(?:ql)?://[^\s:@]+:[^\s@]+@[^\s:/]+:\d+/[A-Za-z0-9_\-]+",
    "MySQL DSN": r"mysql://[^\s:@]+:[^\s@]+@[^\s:/]+:\d+/[A-Za-z0-9_\-]+",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s:@]+:[^\s@]+@[^\s/]+/[A-Za-z0-9_\-]+",
    "Azure Storage Key": r"(?i)AccountKey=([A-Za-z0-9+/=]{40,80})",
    "Firebase API": r"(?i)firebase.{0,20}?api(?:[_\- ]?key)?[\"\']?\s*[:=]\s*[\"\']?[A-Za-z0-9\-_]{30,}",
}

def _shannon_entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    import collections
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c/length) * log2(c/length) for c in counts.values())

def scan_for_credentials(text: str):
    """
    Return list of suspected credential leaks with context.
    """
    findings = []
    if not text:
        return findings
    # Regex signatures
    for name, rx in CRED_PATTERNS.items():
        for m in re.finditer(rx, text):
            snippet = text[max(0, m.start()-30): m.end()+30]
            findings.append({
                "type": "Credential Leak",
                "name": name,
                "match": m.group(0)[:100],
                "context": snippet[:200]
            })
    # High-entropy generic tokens within quotes
    for m in re.finditer(r"[\"\']([A-Za-z0-9/+_\-=]{24,})[\"\']", text):
        token = m.group(1)
        if len(token) >= 32 and _shannon_entropy(token) >= 4.0:
            snippet = text[max(0, m.start()-20): m.end()+20]
            findings.append({
                "type": "Credential Leak",
                "name": "High-entropy token (possible secret)",
                "match": token[:100],
                "context": snippet[:200]
            })
    return findings

def scan_for_userpass(text: str):
    """Heuristic scan for username/password pairs in client-visible code.
    Returns a list of dicts with 'username', 'password', 'context'.
    We purposefully keep this conservative to reduce false positives.
    """
    if not text:
        return []
    findings = []
    # Common key aliases for usernames
    user_keys = r"(?:user(?:name)?|login|email|db_user|dbuser|ftp_user|ftpuser)"
    pass_keys = r"(?:pass(?:word)?|db_pass|dbpass|ftp_pass|ftppass|secret|token)"
    # Pattern 1: JSON/JS-style key-value pairs near each other within 120 chars
    rx_pair = re.compile(
        rf"(?i)(?:{user_keys})\s*[:=]\s*[\"']([\w.@+-]{1,128})[\"']\s*[,;\n\r\t ]{{0,40}}(?:{pass_keys})\s*[:=]\s*[\"']([^\s\"']{{1,256}})[\"']"
    )
    # Pattern 2: .env style on separate lines
    rx_env = re.compile(
        rf"(?im)^(?:{user_keys})\s*=\s*([\w.@+-]{{1,128}})\s*$[\s\S]{{0,40}}^(?:{pass_keys})\s*=\s*([^\s]{{1,256}})$"
    )
    # Pattern 3: password then username (reverse order)
    rx_pair_rev = re.compile(
        rf"(?i)(?:{pass_keys})\s*[:=]\s*[\"']([^\s\"']{{1,256}})[\"']\s*[,;\n\r\t ]{{0,40}}(?:{user_keys})\s*[:=]\s*[\"']([\w.@+-]{{1,128}})[\"']"
    )

    for rx in (rx_pair, rx_env, rx_pair_rev):
        for m in rx.finditer(text):
            u = m.group(1)
            p = m.group(2)
            # Filter trivial placeholders
            trivial = {"username", "user", "admin@example.com", "password", "pass", "changeme", "example"}
            if u.lower() in trivial and p.lower() in trivial:
                continue
            start = max(0, m.start()-40); end = min(len(text), m.end()+40)
            findings.append({
                "username": u[:200],
                "password": p[:400],
                "context": text[start:end]
            })
    return findings
def scan_for_pii(text: str) -> List[str]:
    hits = []
    for label, pat in PII_PATTERNS.items():
        if re.search(pat, text):
            hits.append(label)
    return hits

def analyze_headers(resp: requests.Response, findings: List[Finding]) -> Dict[str, str]:
    h = {k: v for k, v in resp.headers.items()}
    def miss(name: str, rec: str, sev: str = "LOW"):
        if name not in h:
            findings.append(Finding(
                title=f"Missing security header: {name}",
                severity=sev,
                description=f"The response from {resp.url} lacks {name}.",
                recommendation=rec,
            ))
    miss("Strict-Transport-Security", "Enable HSTS to enforce HTTPS.")
    miss("Content-Security-Policy", "Set a restrictive CSP to mitigate XSS.", "MEDIUM")
    miss("X-Frame-Options", "Use SAMEORIGIN or DENY to prevent clickjacking.")
    miss("X-Content-Type-Options", "Add nosniff to prevent MIME sniffing.")
    if "X-Powered-By" in h:
        findings.append(Finding(
            title="X-Powered-By header exposes stack",
            severity="INFO",
            description=f"Server discloses backend via X-Powered-By: {h.get('X-Powered-By')}",
            recommendation="Remove or minimize identifying headers.",
        ))
    # CORS wildcard
    aco = h.get("Access-Control-Allow-Origin")
    if aco and aco.strip() == "*":
        findings.append(Finding(
            title="Overly broad CORS policy",
            severity="MEDIUM",
            description=f"Access-Control-Allow-Origin is '*' on {resp.url}.",
            recommendation="Scope CORS to trusted origins; avoid wildcard with credentials.",
        ))
    return h

def inspect_cookies(resp: requests.Response, findings: List[Finding]) -> Dict[str, Dict[str, str]]:
    jar: Dict[str, Dict[str, str]] = {}
    for c in resp.cookies:
        attrs = {
            "secure": str(c.secure).lower(),
            "httponly": str("httponly" in (c._rest or {}).keys()).lower(),
            "samesite": (c._rest or {}).get("samesite", "").lower(),
            "domain": c.domain or "",
            "path": c.path or "",
        }
        jar[c.name] = attrs
        if attrs["secure"] != "true":
            findings.append(Finding(
                title=f"Cookie without Secure flag: {c.name}",
                severity="LOW",
                description="Cookie is set without the 'Secure' attribute.",
                recommendation="Set 'Secure' for all cookies set over HTTPS.",
            ))
        if attrs["httponly"] != "true":
            findings.append(Finding(
                title=f"Cookie without HttpOnly: {c.name}",
                severity="LOW",
                description="Cookie is set without 'HttpOnly'.",
                recommendation="Set 'HttpOnly' for session and sensitive cookies.",
            ))
        if not attrs["samesite"]:
            findings.append(Finding(
                title=f"Cookie without SameSite: {c.name}",
                severity="LOW",
                description="Cookie lacks SameSite attribute (Lax/Strict).",
                recommendation="Specify SameSite for cookies to mitigate CSRF.",
            ))
    return jar

def parse_csp(url: str, csp_value: str) -> List[Finding]:
    issues: List[Finding] = []
    try:
        directives = {}
        for part in csp_value.split(';'):
            part = part.strip()
            if not part:
                continue
            k, *vals = part.split()
            directives[k.lower()] = [v.lower() for v in vals]
        script = directives.get('script-src') or directives.get('default-src') or []
        default = directives.get('default-src') or []
        def flag(title, sev, desc, rec):
            issues.append(Finding(title=title, severity=sev, description=f"{url}: {desc}", recommendation=rec))
        if "'unsafe-inline'" in script:
            flag("CSP allows 'unsafe-inline' scripts","MEDIUM","script-src permits 'unsafe-inline'","Use nonces/hashes and remove 'unsafe-inline'.")
        if "'unsafe-eval'" in script:
            flag("CSP allows 'unsafe-eval'","MEDIUM","script-src permits 'unsafe-eval'","Remove 'unsafe-eval' and avoid eval-like constructs.")
        if "*" in script or any(s.endswith("*") for s in script):
            flag("CSP script-src uses wildcards","LOW","script-src contains wildcard sources","Pin to exact domains; consider SRI and nonces.")
        if "data:" in script or "blob:" in script:
            flag("CSP allows data:/blob: in scripts","LOW","data:/blob: allowed in script-src","Avoid data/blob script sources; use external or inline with nonce+hash.")
        fa = directives.get('frame-ancestors', [])
        if fa and ('*' in fa or ('none' not in fa and "'self'" not in fa)):
            flag("Weak frame-ancestors policy","LOW","frame-ancestors broad or missing 'none'/'self'","Restrict embedding with 'none' or trusted origins.")
        if "*" in default:
            flag("CSP default-src wildcard","LOW","default-src uses '*'","Tighten default-src; declare per-resource directives.")
    except Exception as e:
        issues.append(Finding(
            title="CSP parse error",
            severity="INFO",
            description=f"Could not parse CSP on {url}: {e}",
        ))
    return issues

def detect_cms(html: str, headers: Dict[str, str], cookies: Dict[str, Dict[str, str]]) -> List[str]:
    found: set[str] = set()
    try:
        soup = BeautifulSoup(html, "html5lib")
        gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if gen and gen.get("content"):
            txt = gen.get("content", "")
            for cms, pat in CMS_META_PATTERNS.items():
                if pat.search(txt):
                    found.add(cms)
    except Exception:
        pass
    xp = headers.get("X-Powered-By", "")
    if re.search(r"wordpress", xp, re.I):
        found.add("wordpress")
    if re.search(r"laravel", xp, re.I):
        found.add("laravel")
    for cms, hints in CMS_COOKIE_HINTS.items():
        for name in cookies.keys():
            if any(name.lower().startswith(h.lower()) for h in hints):
                found.add(cms)
    if re.search(r"wp-content|wp-includes|/wp-json/", html, re.I):
        found.add("wordpress")
    if re.search(r"/administrator/index.php|/media/system/js/", html, re.I):
        found.add("joomla")
    if re.search(r"name=\"csrf-token\"|/storage/framework/", html, re.I):
        found.add("laravel")
    return sorted(found)

# ------------------------- Scanner core ---------------------------------------
class SiteScanner:
    def __init__(self, target: str, client: HttpClient, max_pages: int = 30, max_sitemap_urls: int = 150,
                 yara_bundle: Optional[YaraBundle] = None, respect_robots: bool = True, max_assets_per_page: int = 6, expose_credentials: bool = True, userpass_scan: bool = True) -> None:
        self.target, self.alt = normalize_target(target)
        self.client = client
        self.max_pages = max_pages
        self.max_sitemap_urls = max_sitemap_urls
        self.yara = yara_bundle
        self.respect_robots = respect_robots
        self.max_assets_per_page = max_assets_per_page
        self.expose_credentials = expose_credentials
        self.userpass_scan = userpass_scan
        self.userpass_scan = userpass_scan
        self.robots_disallows: List[str] = []

    def resolve_ip(self) -> str:
        host = urlparse(self.target).hostname or self.target
        try:
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def run(self) -> ScanResult:
        res = ScanResult(target=self.target)
        res.ip = self.resolve_ip()

        # Ports
        host = self._host()
        res.ports = {p: tcp_check(host, p) for p in COMMON_PORTS}

        # Initial fetch (https then http)
        resp = self.client.get(self.target)
        if not (resp and resp.ok) and self.alt:
            resp = self.client.get(self.alt)
            if resp and resp.ok:
                res.target = self.alt

        if resp and resp.ok:
            res.headers = analyze_headers(resp, res.findings)
            res.cookies = inspect_cookies(resp, res.findings)
            if res.ports.get(443, False):
                res.tls = get_tls_info(host, 443)

            # robots & sitemap discovery
            self.load_robots(res)
            sitemap_urls = self.discover_sitemaps(res)
            sitemap_links = self.parse_sitemaps(sitemap_urls)

            # Crawl queue
            to_visit: List[str] = [resp.url] + sitemap_links[: self.max_sitemap_urls]
            visited: set[str] = set()
            pages = 0
            external_domains: set[str] = set()

            while to_visit and pages < self.max_pages:
                url = to_visit.pop(0)
                if url in visited or (self.respect_robots and self.is_disallowed(url)):
                    continue
                r = self.client.get(url)
                visited.add(url)
                if not (r and r.ok and (r.text or r.content)):
                    continue
                pages += 1

                # Per-page CSP
                csp = r.headers.get('Content-Security-Policy')
                if csp:
                    res.findings.extend(parse_csp(url, csp))

                text = r.text or ""
                # Trackers, malware hints, PII
                for t in scan_for_trackers(text):
                    if t not in res.trackers:
                        res.trackers.append(t)
                hits = scan_for_malware_hints(text)
                if hits:
                    res.findings.append(Finding(
                        title="Suspicious script patterns detected",
                        severity="MEDIUM",
                        description=f"Page {url} contains patterns often used for obfuscated JS or cryptominers.",
                        evidence=", ".join(hits)[:400],
                        recommendation="Review scripts, remove obfuscation, verify integrity (SRI/CSP).",
                    ))
                pii = scan_for_pii(text)
                if pii:
                    res.findings.append(Finding(
                        title="Potential API key/PII patterns exposed",
                        severity="LOW",
                        description=f"Page {url} contains strings resembling: {', '.join(pii)}",
                        recommendation="Rotate keys, move secrets to server-side; consider secret scanning in CI.",
                    ))

                # Credential leak finder
                
                cred_hits = scan_for_credentials(text)
                if cred_hits:
                    for ch in cred_hits:
                        evidence = ch['match'] if self.expose_credentials else (ch['match'][:6] + '…' + ch['match'][-4:])
                        res.findings.append(Finding(
                            title=f"Possible credential leak: {ch['name']}",
                            severity="HIGH",
                            description=f"Found {ch['name']} on {url}. Snippet: {ch['context']}",
                            evidence=evidence,
                            recommendation="Remove secrets from client-side code, rotate the credential, and add secret scanning to CI/CD."
                        ))
                # Username/Password pair finder (optional)
                if self.userpass_scan:
                    up_hits = scan_for_userpass(text)
                    for up in up_hits:
                        evidence = f"{up['username']} / {up['password']}" if self.expose_credentials else f"{up['username']} / ******"
                        res.findings.append(Finding(
                            title="Possible username/password pair exposed",
                            severity="HIGH",
                            description=f"Found a username/password pair on {url}. Snippet: {up['context']}",
                            evidence=evidence,
                            recommendation="Never ship credentials to clients. Remove from front-end; store server-side and rotate immediately."
                        ))
                    for ch in cred_hits:
                        evidence = ch['match'] if self.expose_credentials else (ch['match'][:6] + '…' + ch['match'][-4:])
                        res.findings.append(Finding(
                            title=f"Possible credential leak: {ch['name']}",
                            severity="HIGH",
                            description=f"Found {ch['name']} on {url}. Snippet: {ch['context']}",
                            evidence=evidence,
                            recommendation="Remove secrets from client-side code, rotate the credential, and add secret scanning to CI/CD."
                        ))

                # CMS on this page
                page_cookies = {c.name: {} for c in r.cookies}
                cms_hits = detect_cms(text, {k: v for k, v in r.headers.items()}, page_cookies)
                for c in cms_hits:
                    res.cms[c] = True

                # Links & assets
                internal, external, assets = parse_links(url, text)
                external_domains.update([re.sub(r"^www\.", "", urlparse(u).netloc) for u in external if u])

                # Same-origin asset scan (JS/CSS only), limited per page
                assets = [a for a in assets if urlparse(a).netloc == urlparse(self.target).netloc][: self.max_assets_per_page]
                res.assets.extend(self.scan_assets(assets))

                # Queue more pages
                for u in internal:
                    if u not in visited and (not self.respect_robots or not self.is_disallowed(u)):
                        if len(to_visit) < (self.max_pages * 3):
                            to_visit.append(u)

            res.pages_crawled = pages
            res.external_domains = sorted(external_domains)

            # Artifacts
            for special in ["robots.txt", "sitemap.xml", ".well-known/security.txt"]:
                s_url, s_resp = self.check_path(res.target, special)
                if s_resp and s_resp.ok:
                    res.artifacts[special] = s_url
                    if special == "robots.txt" and "Disallow" in s_resp.text:
                        disallows = ", ".join(re.findall(r"Disallow:\s*(\S+)", s_resp.text))[:600]
                        if disallows:
                            res.findings.append(Finding(
                                title="robots.txt disallows reveal paths",
                                severity="INFO",
                                description=f"robots.txt lists disallowed paths that might hint at sensitive areas.",
                                evidence=disallows,
                                recommendation="Ensure sensitive areas are protected by auth; do not rely on robots.txt for security.",
                            ))

            # Generic leak checks + CMS-specific
            to_check = set(COMMON_FILES + COMMON_DIRS)
            for cms in res.cms.keys():
                to_check.update(CMS_LEAK_PATHS.get(cms, []))

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(self.check_path, res.target, p): p for p in to_check}
                for fut in concurrent.futures.as_completed(futs):
                    path = futs[fut]
                    try:
                        url, r = fut.result()
                    except Exception:
                        continue
                    if not r:
                        continue
                    if r.status_code == 200:
                        body = (r.text or "")[:800]
                        if re.search(r"<title>Index of /|Directory listing for /", body, re.I):
                            res.findings.append(Finding(
                                title="Open directory listing",
                                severity="MEDIUM",
                                description=f"{url} exposes a directory listing.",
                                evidence=body[:200],
                                recommendation="Disable autoindex / directory listing, restrict via auth.",
                            ))
                        elif any(s in path for s in [".env", ".git", "db.sql", "dump.sql", "laravel.log", "wp-config"]):
                            sev = "HIGH" if any(x in path for x in [".env", "wp-config", "db.sql", "dump.sql"]) else "MEDIUM"
                            res.findings.append(Finding(
                                title="Potential sensitive file exposed",
                                severity=sev,
                                description=f"{path} appears accessible at {url}.",
                                evidence=body[:400],
                                recommendation="Remove from webroot; store secrets outside deploy dir; restrict via server rules.",
                            ))
                        elif path in ("phpinfo.php", "server-status"):
                            res.findings.append(Finding(
                                title="Server info endpoint exposed",
                                severity="MEDIUM",
                                description=f"{url} leaks environment or module info.",
                                recommendation="Disable or restrict to localhost/admins only.",
                            ))
                        elif path == "wp-json/wp/v2/users" and "name" in body and "slug" in body:
                            res.findings.append(Finding(
                                title="WordPress user enumeration via REST API",
                                severity="LOW",
                                description=f"{url} enumerates user names via REST.",
                                recommendation="Disable public user listing; limit endpoints or require auth.",
                            ))

            # CORS probes
            for api in CANDIDATE_APIS:
                u, r = self.check_path(res.target, api)
                if r and r.headers.get("Access-Control-Allow-Origin", "").strip() == "*":
                    res.findings.append(Finding(
                        title="Wildcard CORS on API path",
                        severity="MEDIUM",
                        description=f"{u} sets Access-Control-Allow-Origin: *",
                        recommendation="Restrict origins and avoid wildcard with credentials.",
                    ))

            # Simple score
            sev_weight = {"INFO": 0, "LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}
            score = 0
            buckets = {"INFO":0,"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
            for f in res.findings:
                buckets[f.severity] = buckets.get(f.severity,0)+1
                score += sev_weight.get(f.severity,0)
            buckets["weighted_score"] = score
            res.summary_score = buckets

        else:
            res.findings.append(Finding(
                title="Site unreachable",
                severity="HIGH",
                description=f"Could not fetch {self.target} (and fallback {self.alt or 'n/a'}).",
                recommendation="Verify DNS, firewall, and service availability.",
            ))
        return res

    # -------- asset scanning
    def scan_assets(self, urls: List[str]) -> List[AssetFinding]:
        out: List[AssetFinding] = []
        def get(u: str) -> Tuple[str, Optional[requests.Response]]:
            return u, self.client.get(u)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(get, u) for u in urls]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    u, r = fut.result()
                except Exception:
                    continue
                if not (r and r.ok and r.content is not None):
                    continue
                ct = r.headers.get("Content-Type", "")
                data = r.content
                sha = hashlib.sha256(data).hexdigest()
                matches: List[str] = []
                text = ""
                try:
                    text = r.text
                except Exception:
                    text = ""
                # Malware/PII heuristics
                for pat in scan_for_malware_hints(text):
                    matches.append(f"hint:{pat}")
                for lbl in scan_for_pii(text):
                    matches.append(f"pii:{lbl}")
                    # Credential leak finder for assets
                    creds = scan_for_credentials(text)
                    for ch in creds:
                        matches.append(f"cred:{ch['name']}")
                    if self.expose_credentials and self.userpass_scan:
                        ups = scan_for_userpass(text)
                        if ups:
                            matches.append("userpass:pair")
                # YARA
                if self.yara:
                    for m in self.yara.scan_bytes(data):
                        matches.append(f"yara:{m}")
                out.append(AssetFinding(url=u, content_type=ct, size=len(data), sha256=sha, matches=matches))
        return out

    # -------------- robots & sitemaps
    def load_robots(self, res: ScanResult) -> None:
        self.robots_disallows = []
        r_url, r_resp = self.check_path(self.target, "robots.txt")
        if r_resp and r_resp.ok and r_resp.text:
            res.artifacts["robots.txt"] = r_url
            for m in re.findall(r"(?i)Disallow:\s*(\S+)", r_resp.text):
                self.robots_disallows.append(m.strip())

    def is_disallowed(self, url: str) -> bool:
        if not self.robots_disallows:
            return False
        path = urlparse(url).path or "/"
        for rule in self.robots_disallows:
            if rule == "/":
                return True
            if rule and path.startswith(rule):
                return True
        return False

    def discover_sitemaps(self, res: ScanResult) -> List[str]:
        urls: List[str] = []
        r_url, r_resp = self.check_path(self.target, "robots.txt")
        if r_resp and r_resp.ok and r_resp.text:
            for m in re.findall(r"(?i)Sitemap:\s*(\S+)", r_resp.text):
                urls.append(m.strip())
        s_url, s_resp = self.check_path(self.target, "sitemap.xml")
        if s_resp and s_resp.ok:
            urls.append(s_url)
        return list(dict.fromkeys(urls))

    def parse_sitemaps(self, sitemap_urls: List[str]) -> List[str]:
        links: List[str] = []
        base_host = urlparse(self.target).netloc
        for su in sitemap_urls:
            r = self.client.get(su)
            if not (r and r.ok and r.text):
                continue
            try:
                root = ET.fromstring(r.text) if ET else None
            except Exception:
                root = None
            if root is not None:
                if root.tag.endswith('sitemapindex'):
                    for loc in root.findall('.//{*}loc')[: self.max_sitemap_urls]:
                        u = (loc.text or '').strip()
                        if u:
                            cr = self.client.get(u)
                            if cr and cr.ok and cr.text:
                                try:
                                    child = ET.fromstring(cr.text) if ET else None
                                    if child is not None:
                                        for cloc in child.findall('.//{*}loc'):
                                            cu = (cloc.text or '').strip()
                                            if cu and urlparse(cu).netloc == base_host:
                                                links.append(cu)
                                except Exception:
                                    pass
                else:
                    for loc in root.findall('.//{*}loc'):
                        u = (loc.text or '').strip()
                        if u and urlparse(u).netloc == base_host:
                            links.append(u)
            else:
                for u in re.findall(r"https?://[^\s<]+", r.text):
                    if urlparse(u).netloc == base_host:
                        links.append(u)
        return list(dict.fromkeys(links))

    def check_path(self, base: str, path: str) -> Tuple[str, Optional[requests.Response]]:
        url = urljoin(base + "/", path)
        return url, self.client.get(url)

    def _host(self) -> str:
        return urlparse(self.target).hostname or self.target

# ------------------------- Reports --------------------------------------------
REPORT_CSS = """
body { font-family: Inter, Segoe UI, Roboto, sans-serif; background:#0e1116; color:#e6edf3; }
.container { max-width: 1040px; margin: 2rem auto; padding: 1rem; }
h1,h2,h3 { color:#cdd9e5; }
.sev-INFO{color:#9aa7b4}.sev-LOW{color:#8bc34a}.sev-MEDIUM{color:#ffca28}.sev-HIGH{color:#ff7043}.sev-CRITICAL{color:#ef5350}
.card{background:#111722;border:1px solid #202938;border-radius:12px;padding:16px;margin:12px 0;}
.kv{display:grid;grid-template-columns:260px 1fr;gap:6px}
small{color:#8b98a5}
code{background:#1a2230;padding:2px 6px;border-radius:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#1a2230;margin-right:6px}
table{width:100%;border-collapse:collapse}
th,td{border-bottom:1px solid #202938;padding:8px;text-align:left;vertical-align:top}
"""

def build_html_report(r: ScanResult) -> str:
    cred_findings = [f for f in r.findings if f.title.lower().startswith("possible credential leak")]
    cred_banner = ""
    if cred_findings:
        cred_banner = "<div class='card' style='border:1px solid #5b342f;background:#201112'><h3 class='sev-HIGH'>Credential data included</h3><p>Report contains full credential values as requested. Handle and store securely.</p></div>"
    def esc(s: str) -> str:
        return (s or "").replace("<", "&lt;").replace(">", "&gt;")
    kv_rows = "".join([
        f"<div>Target</div><div>{esc(r.target)}</div>",
        f"<div>Resolved IP</div><div>{esc(r.ip)}</div>",
        f"<div>Open Ports</div><div>{', '.join([str(p) for p,v in r.ports.items() if v]) or 'None'}</div>",
        f"<div>Pages Crawled</div><div>{r.pages_crawled}</div>",
        f"<div>External Domains</div><div>{esc(', '.join(r.external_domains[:60]))}</div>",
        f"<div>Trackers</div><div>{esc(', '.join(r.trackers) or 'None detected')}</div>",
        f"<div>Detected CMS</div><div>{esc(cms_badges)}</div>",
        f"<div>Score</div><div>{json.dumps(r.summary_score)}</div>",
    ])
    tls_rows = "".join([f"<div>{esc(k)}</div><div>{esc(v)}</div>" for k,v in r.tls.items()])
    header_rows = "".join([f"<div>{esc(k)}</div><div>{esc(v)}</div>" for k,v in r.headers.items()])
    findings_html = "".join([
        f"<div class='card'><h3 class='sev-{esc(f.severity)}'>[{esc(f.severity)}] {esc(f.title)}</h3>"
        f"<p>{esc(f.description)}</p>" + (f"<pre><code>{esc(f.evidence)}</code></pre>" if f.evidence else "") +
        (f"<p><small>Recommendation:</small> {esc(f.recommendation)}</p>" if f.recommendation else "") +
        "</div>"
        for f in r.findings
    ])
    artifacts = "".join([f"<li><a href='{esc(u)}'>{esc(name)}</a></li>" for name,u in r.artifacts.items()])
    assets_rows = "".join([
        f"<tr><td><a href='{esc(a.url)}'>{esc(a.url)}</a></td>"
        f"<td>{esc(a.content_type)}</td><td>{a.size}</td><td><code>{a.sha256[:16]}…</code></td><td>{esc(', '.join(a.matches))}</td></tr>"
        for a in r.assets
    ])
    html = f"""<!doctype html>
<html><head><meta charset='utf-8'>
<title>SiteLeak Auditor Report - {esc(r.target)}</title>
<style>{REPORT_CSS}</style></head>
<body>
<div class='container'>
  <h1>SiteLeak Auditor — Report</h1>
  <p><small>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</small></p>
  <div class='card'><h2>Summary</h2><div class='kv'>{kv_rows}</div></div>
  {cred_banner}
  <div class='card'><h2>TLS</h2><div class='kv'>{tls_rows or 'No TLS info (port 443 closed?)'}</div></div>
  <div class='card'><h2>Response Headers (root)</h2><div class='kv'>{header_rows or 'n/a'}</div></div>
  <div class='card'><h2>Artifacts</h2><ul>{artifacts or '<li>None</li>'}</ul></div>
  <div class='card'><h2>Assets (same-origin JS/CSS)</h2>
    <table><thead><tr><th>URL</th><th>Type</th><th>Size</th><th>SHA256</th><th>Matches</th></tr></thead>
    <tbody>{assets_rows or '<tr><td colspan="5">No assets scanned</td></tr>'}</tbody></table>
  </div>
  <div class='card'><h2>Findings</h2>{findings_html or '<p>No issues detected at the chosen depth. Increase scope to be sure.</p>'}</div>
</div>
</body></html>"""
    return html

def result_to_json(r: ScanResult) -> str:
    d = asdict(r)
    d["findings"] = [asdict(f) for f in r.findings]
    d["assets"] = [asdict(a) for a in r.assets]
    d["generated_at"] = time.strftime('%Y-%m-%d %H:%M:%S')
    d["version"] = VERSION
    return json.dumps(d, indent=2)

# ------------------------- GUI -------------------------------------------------
class Worker(QtCore.QThread):
    progress = QtCore.Signal(str)
    done = QtCore.Signal(object)

    def __init__(self, target: str, max_pages: int, max_sitemap: int, yara_path: Optional[str],
                 ua: str, delay_ms: int, respect_robots: bool, max_assets: int, expose_credentials: bool, userpass_scan: bool) -> None:
        super().__init__()
        self.target = target
        self.max_pages = max_pages
        self.max_sitemap = max_sitemap
        self.yara_path = yara_path
        self.ua = ua
        self.delay_ms = delay_ms
        self.respect_robots = respect_robots
        self.max_assets = max_assets
        self.expose_credentials = expose_credentials
        self.userpass_scan = userpass_scan
        self.userpass_scan = userpass_scan

    def run(self) -> None:
        try:
            self.progress.emit(f"Starting scan of {self.target}…")
            yb = YaraBundle(self.yara_path) if self.yara_path else None
            if yb and not yb.rules:
                self.progress.emit("[i] YARA: no compiled rules (check directory/files and syntax). Proceeding without YARA.")
                yb = None
            client = HttpClient(self.ua, self.delay_ms)
            scanner = SiteScanner(self.target, client, max_pages=self.max_pages, max_sitemap_urls=self.max_sitemap,
                                  yara_bundle=yb, respect_robots=self.respect_robots, max_assets_per_page=self.max_assets,
                                  expose_credentials=self.expose_credentials, userpass_scan=self.userpass_scan)
            res = scanner.run()
            self.progress.emit("Scan complete. Building report…")
            self.done.emit(res)
        except Exception as e:
            self.progress.emit(f"Error: {e}")
            self.done.emit(None)

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1100, 840)

        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        v = QtWidgets.QVBoxLayout(central)

        # Target box
        box = QtWidgets.QGroupBox("Target")
        form = QtWidgets.QFormLayout(box)
        self.target_edit = QtWidgets.QLineEdit()
        self.target_edit.setPlaceholderText("https://example.com or 203.0.113.5")
        self.depth_spin = QtWidgets.QSpinBox()
        self.depth_spin.setRange(1, 1000); self.depth_spin.setValue(60)
        self.sitemap_spin = QtWidgets.QSpinBox()
        self.sitemap_spin.setRange(0, 5000); self.sitemap_spin.setValue(300)
        form.addRow("URL or IP:", self.target_edit)
        form.addRow("Pages to crawl (max):", self.depth_spin)
        form.addRow("Sitemap URLs to seed (max):", self.sitemap_spin)
        v.addWidget(box)

        # YARA + settings
        ybox = QtWidgets.QGroupBox("Scanning settings")
        g = QtWidgets.QGridLayout(ybox)
        self.yara_path = QtWidgets.QLineEdit(); self.yara_path.setPlaceholderText("Path to .yar/.yara file or directory (optional)")
        browse = QtWidgets.QPushButton("Browse…")
        browse.clicked.connect(self._pick_yara)
        self.ua_edit = QtWidgets.QLineEdit(); self.ua_edit.setText(DEFAULT_UA)
        self.delay_spin = QtWidgets.QSpinBox(); self.delay_spin.setRange(0, 5000); self.delay_spin.setSuffix(" ms"); self.delay_spin.setValue(100)
        self.robots_check = QtWidgets.QCheckBox("Respect robots.txt (Disallow)"); self.robots_check.setChecked(True)
        self.assets_spin = QtWidgets.QSpinBox(); self.assets_spin.setRange(0, 50); self.assets_spin.setValue(6)
        self.expose_creds_check = QtWidgets.QCheckBox("Include full credentials in report (DANGEROUS)")
        self.expose_creds_check.setChecked(True)
        self.userpass_check = QtWidgets.QCheckBox("Scan for username/password pairs")
        self.userpass_check.setChecked(True)
        g.addWidget(QtWidgets.QLabel("YARA rules:"), 0,0); g.addWidget(self.yara_path,0,1); g.addWidget(browse,0,2)
        g.addWidget(QtWidgets.QLabel("User-Agent:"), 1,0); g.addWidget(self.ua_edit,1,1,1,2)
        g.addWidget(QtWidgets.QLabel("Delay per request:"), 2,0); g.addWidget(self.delay_spin,2,1)
        g.addWidget(self.robots_check,2,2)
        g.addWidget(QtWidgets.QLabel("Assets per page (max):"), 3,0); g.addWidget(self.assets_spin,3,1)
        g.addWidget(self.expose_creds_check,3,2)
        g.addWidget(self.userpass_check,4,2)
        v.addWidget(ybox)

        # Buttons
        btn_row = QtWidgets.QHBoxLayout()
        self.scan_btn = QtWidgets.QPushButton("Scan")
        self.export_btn = QtWidgets.QPushButton("Export HTML…")
        self.export_json_btn = QtWidgets.QPushButton("Export JSON…")
        self.export_btn.setEnabled(False); self.export_json_btn.setEnabled(False)
        btn_row.addWidget(self.scan_btn); btn_row.addStretch(1)
        btn_row.addWidget(self.export_btn); btn_row.addWidget(self.export_json_btn)
        v.addLayout(btn_row)

        # Log
        self.log = QtWidgets.QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet("background:#0b0f14;color:#dfe6ee;font-family:Consolas,Monaco,monospace")
        v.addWidget(self.log, 1)

        self._apply_theme()
        self.scan_btn.clicked.connect(self.start_scan)
        self.export_btn.clicked.connect(self.export_report_html)
        self.export_json_btn.clicked.connect(self.export_report_json)
        self.result: Optional[ScanResult] = None

    def _apply_theme(self) -> None:
        palette = self.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(18, 22, 28))
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(18, 22, 28))
        palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(25, 29, 36))
        palette.setColor(QtGui.QPalette.Text, QtGui.QColor(221, 227, 234))
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(221, 227, 234))
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(25, 29, 36))
        palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(221, 227, 234))
        self.setPalette(palette)
        self.setStyleSheet("QGroupBox{border:1px solid #2a2f3a;border-radius:10px;margin-top:10px;padding:8px;} QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;} QPushButton{padding:6px 12px;border-radius:8px;background:#1e2430;} QPushButton:hover{background:#2a3140;}")

    def _pick_yara(self) -> None:
        dlg = QtWidgets.QFileDialog(self)
        dlg.setFileMode(QtWidgets.QFileDialog.AnyFile)
        dlg.setNameFilter("YARA rules (*.yar *.yara);;All files (*)")
        if dlg.exec():
            sel = dlg.selectedFiles()[0]
            self.yara_path.setText(sel)

    def start_scan(self) -> None:
        target = self.target_edit.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, APP_NAME, "Enter a URL or IP.")
            return
        self.log.clear()
        self.scan_btn.setEnabled(False)
        self.worker = Worker(
            target,
            self.depth_spin.value(),
            self.sitemap_spin.value(),
            self.yara_path.text().strip() or None,
            self.ua_edit.text().strip() or DEFAULT_UA,
            self.delay_spin.value(),
            self.robots_check.isChecked(),
            self.assets_spin.value(),
            self.expose_creds_check.isChecked(),
            self.userpass_check.isChecked(),
        )
        self.worker.progress.connect(self.log.appendPlainText)
        self.worker.done.connect(self._on_done)
        self.worker.start()

    def _on_done(self, res: Optional[ScanResult]) -> None:
        self.scan_btn.setEnabled(True)
        if not res:
            self.log.appendPlainText("Scan failed.")
            return
        self.result = res
        self.log.appendPlainText(f"Found {len(res.findings)} findings. CMS: {', '.join(sorted(res.cms.keys())) or 'None'}. Assets scanned: {len(res.assets)}.")
        self.log.appendPlainText(f"Score: {res.summary_score}")
        for f in res.findings:
            self.log.appendPlainText(f"[{f.severity}] {f.title} — {f.description}")
        self.export_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)

    def export_report_html(self) -> None:
        if not self.result:
            return
        html = build_html_report(self.result)
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save HTML report", str(Path.home() / "SiteLeakReport.html"), "HTML (*.html)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        # Optional PDF (wkhtmltopdf + pdfkit)
        try:
            import pdfkit  # type: ignore
            pdf_path = re.sub(r"\.html?$", ".pdf", path)
            pdfkit.from_string(html, pdf_path)
            self.log.appendPlainText(f"Report saved: {path}\nPDF saved: {pdf_path}")
        except Exception:
            self.log.appendPlainText(f"Report saved: {path} (PDF skipped; install wkhtmltopdf + pdfkit)")

    def export_report_json(self) -> None:
        if not self.result:
            return
        js = result_to_json(self.result)
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON report", str(Path.home() / "SiteLeakReport.json"), "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(js)
        self.log.appendPlainText(f"JSON saved: {path}")

def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    win = MainWindow()
    win.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())