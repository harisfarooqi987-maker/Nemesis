#!/usr/bin/env python3
"""
Nemesis – Autonomous Bug Bounty Probe
Version 1.0.0 – Crafted by Haris Farooqi

A fully async, modular security scanner for authorized assessments & bug bounty.
Usage: python3 nemesis.py -u https://example.com --threads 20 --rate-limit 10 --format html
"""
import argparse
import asyncio
import base64
import csv
import io
import json
import logging
import os
import re
import socket
import ssl
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Pattern
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, quote

# ----------------------------------------------------------------------
# Optional dependencies – graceful fallback if not installed
# ----------------------------------------------------------------------
try:
    from fake_useragent import UserAgent as _UserAgent
    _ua = _UserAgent()
    def random_ua() -> str:
        return _ua.random
except ImportError:
    def random_ua() -> str:
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

try:
    from cvss import CVSS3
    HAS_CVSS = True
except ImportError:
    HAS_CVSS = False

try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

# Mandatory imports (install via pip)
import aiohttp
import tldextract
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

console = Console(highlight=False)
logger = logging.getLogger("nemesis")

# ============================ BANNER ============================
BANNER = r"""
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
   🔥  The Autonomous Bug Bounty Assassin  🔥
           Crafted by Haris Farooqi
"""

# ============================ UTILS ==============================
def generate_token() -> str:
    """Create a unique, short, URL-safe token for reflection checks."""
    return base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")

def estimate_cvss(vector: str) -> float:
    """Estimate CVSS 3.1 score from vector string; uses cvss library if available."""
    if HAS_CVSS:
        try:
            return CVSS3(vector).scores()[0]
        except Exception:
            pass
    # Fallback rough estimates
    if "C:H/I:H/A:H" in vector: return 9.8
    if "C:H/I:H/A:N" in vector: return 8.1
    if "C:L/I:L/A:N" in vector: return 6.1
    if "C:N/I:L/A:N" in vector: return 4.3
    if "C:N/I:N/A:N" in vector: return 0.0
    return 5.0   # default Medium

def severity_from_score(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score >= 0.1: return "Low"
    return "Informational"

def is_redirect(status: int) -> bool:
    return status in (301, 302, 303, 307, 308)

# SQL error patterns for error-based injection detection
ERROR_SQL = [
    re.compile(p, re.IGNORECASE) for p in [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Driver.*SQL",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB",
        r"ORA-\d{5}",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SqlClient",
    ]
]

# Paths to check for sensitive file exposure
SENSITIVE_FILES = [
    "/.env", "/.git/config", "/.DS_Store", "/wp-config.php",
    "/config.php", "/admin/.git/config", "/backup.sql",
    "/phpinfo.php", "/server-status", "/crossdomain.xml",
]

# ============================ CONFIG =============================
@dataclass
class Scope:
    domain: str
    include_subdomains: bool = True
    regex: Optional[Pattern] = None

    def in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname
        if not host:
            return False
        host = host.lower()
        if self.regex and self.regex.search(host):
            return True
        ext = tldextract.extract(host)
        registered = f"{ext.domain}.{ext.suffix}"
        if self.include_subdomains:
            return host == registered or host.endswith("." + registered)
        return host == self.domain

@dataclass
class ScanConfig:
    target: str
    threads: int = 10
    timeout: int = 15
    depth: int = 3
    rate_limit: float = 5.0
    proxy: Optional[str] = None
    user_agent: str = "Nemesis/1.0"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    output: Optional[str] = None
    formats: Set[str] = field(default_factory=lambda: {"html"})
    respect_robots: bool = True
    max_urls: int = 500
    resume: bool = False
    verbose: bool = False
    scope: Optional[Scope] = None

    def __post_init__(self):
        self.target = self.target.rstrip("/")
        if not self.scope:
            self.scope = Scope(domain=urlparse(self.target).hostname)

# ========================= HTTP CLIENT ===========================
class RateLimiter:
    """Token bucket rate limiter per host."""
    def __init__(self, rps: float):
        self.rps = rps
        self.tokens = defaultdict(lambda: rps)
        self.last = defaultdict(float)
        self.lock = asyncio.Lock()

    async def acquire(self, host: str):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last[host]
            self.last[host] = now
            self.tokens[host] += elapsed * self.rps
            if self.tokens[host] > self.rps:
                self.tokens[host] = self.rps
            if self.tokens[host] < 1.0:
                wait = (1.0 - self.tokens[host]) / self.rps
                await asyncio.sleep(wait)
                self.tokens[host] = 0
            else:
                self.tokens[host] -= 1.0

class HttpClient:
    """Async HTTP client with retry, session persistence, and rate limiting."""
    def __init__(self, config: ScanConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
        headers = {"User-Agent": self.config.user_agent}
        if self.config.user_agent == "random":
            headers["User-Agent"] = random_ua()
        headers.update(self.config.custom_headers)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            connector=connector,
            headers=headers,
            cookies=self.config.cookies or None,
            trust_env=True,
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def request(self, url: str, method: str = "GET", **kwargs) -> Optional[aiohttp.ClientResponse]:
        host = urlparse(url).hostname or ""
        for attempt in range(3):
            await self.rate_limiter.acquire(host)
            try:
                resp = await self.session.request(
                    method, url, allow_redirects=False,
                    proxy=self.config.proxy, **kwargs
                )
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Request {url} attempt {attempt+1}: {e}")
                await asyncio.sleep(0.7 * (2 ** attempt))
        return None

# ============================ CRAWLER ============================
class Crawler:
    """Recursive crawler with JS analysis, form extraction, robots/sitemap parsing."""
    def __init__(self, config: ScanConfig, http: HttpClient):
        self.config = config
        self.http = http
        self.visited: Set[str] = set()
        self.found_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.disallowed: List[str] = []
        self.sitemap_entries: List[str] = []
        self.graphql_detected = False
        self.ws_detected = False
        self.semaphore = asyncio.Semaphore(config.threads)
        self.pending: asyncio.Queue = asyncio.Queue()

    async def load_robots(self):
        robots_url = urljoin(self.config.target, "/robots.txt")
        resp = await self.http.request(robots_url)
        if resp and resp.status == 200:
            text = await resp.text()
            for line in text.splitlines():
                low = line.strip().lower()
                if low.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self.disallowed.append(urljoin(self.config.target, path))
                elif low.startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    await self._parse_sitemap(sm)

    async def _parse_sitemap(self, url: str):
        try:
            resp = await self.http.request(url)
            if resp and resp.status == 200:
                soup = BeautifulSoup(await resp.text(), "xml")
                for loc in soup.find_all("loc"):
                    href = loc.text.strip()
                    if self.config.scope.in_scope(href):
                        self.sitemap_entries.append(href)
                        await self.pending.put((href, 0))
        except Exception as e:
            logger.debug(f"Sitemap parse error {url}: {e}")

    def _allowed(self, url: str) -> bool:
        if not self.config.respect_robots:
            return True
        for d in self.disallowed:
            if url.startswith(d):
                return False
        return True

    async def _process_url(self, url: str, depth: int):
        if url in self.visited or not self.config.scope.in_scope(url) or depth > self.config.depth:
            return
        if not self._allowed(url):
            return
        self.visited.add(url)
        resp = await self.http.request(url)
        if not resp:
            return
        if resp.status == 200:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct:
                html = await resp.text()
                await self._extract_links(html, url)
                await self._extract_js(html, url)
            elif "application/xml" in ct or url.endswith(".xml"):
                await self._parse_sitemap(url)
        elif is_redirect(resp.status):
            loc = resp.headers.get("Location")
            if loc:
                next_url = urljoin(url, loc)
                if self.config.scope.in_scope(next_url):
                    await self.pending.put((next_url, depth + 1))

    async def _extract_links(self, html: str, base: str):
        soup = BeautifulSoup(html, "html.parser")
        # Links & resources
        for tag, attr in [("a", "href"), ("link", "href"), ("area", "href"),
                          ("script", "src"), ("iframe", "src")]:
            for el in soup.find_all(tag, **{attr: True}):
                href = el[attr].strip()
                abs_url = urljoin(base, href)
                if self.config.scope.in_scope(abs_url):
                    self.found_urls.add(abs_url)
                    await self.pending.put((abs_url, 0))
        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            if action:
                form_url = urljoin(base, action)
                self.forms.append({"url": form_url, "method": method, "inputs": inputs})

    async def _extract_js(self, html: str, base: str):
        soup = BeautifulSoup(html, "html.parser")
        for script in soup.find_all("script", src=True):
            js_url = urljoin(base, script["src"])
            if self.config.scope.in_scope(js_url):
                self.js_endpoints.add(js_url)

    async def _analyze_js(self, js_url: str):
        resp = await self.http.request(js_url)
        if not resp or resp.status != 200:
            return
        content = await resp.text()
        # API-like endpoints
        for ep in re.findall(r"""["']((?:https?:)?//[^"']*?(?:/api/|/graphql|/v[12]/)[^"']*?)["']""", content):
            if self.config.scope.in_scope(ep):
                self.api_endpoints.add(ep)
        # GraphQL & WebSocket
        if re.search(r"(graphql|__schema)", content, re.I):
            self.graphql_detected = True
        if re.search(r"ws[s]?://", content):
            self.ws_detected = True

    async def _worker(self):
        while True:
            url, depth = await self.pending.get()
            try:
                async with self.semaphore:
                    await self._process_url(url, depth)
            except Exception as e:
                logger.debug(f"Worker error: {e}")
            finally:
                self.pending.task_done()

    async def run(self) -> Dict:
        """Execute the crawl and return gathered data."""
        await self.load_robots()
        await self.pending.put((self.config.target, 0))
        for sm in self.sitemap_entries:
            await self.pending.put((sm, 0))

        workers = [asyncio.create_task(self._worker()) for _ in range(self.config.threads)]
        with Progress(SpinnerColumn(), TextColumn("[cyan]Crawling..."), BarColumn(), TimeElapsedColumn()) as prog:
            task = prog.add_task("crawl", total=None)
            while not self.pending.empty() and len(self.visited) < self.config.max_urls:
                await asyncio.sleep(0.2)
            for w in workers:
                w.cancel()

        # Analyze discovered JS files
        if self.js_endpoints:
            with Progress(transient=True) as prog:
                t = prog.add_task("[cyan]Analyzing JS", total=len(self.js_endpoints))
                for js in self.js_endpoints:
                    await self._analyze_js(js)
                    prog.advance(t)

        logger.info(f"Crawled {len(self.visited)} URLs, found {len(self.forms)} forms")
        return {
            "visited": self.visited,
            "forms": self.forms,
            "api_endpoints": list(self.api_endpoints),
            "graphql": self.graphql_detected,
            "ws": self.ws_detected,
        }

# ======================== SECURITY HEADERS =======================
HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "check": lambda v: "max-age=" in v and "includeSubDomains" in v,
        "advice": "Set HSTS with max-age >= 31536000 and includeSubDomains."
    },
    "Content-Security-Policy": {
        "check": lambda v: "default-src" in v and "object-src" in v,
        "advice": "Implement a strong CSP to mitigate XSS and data injection."
    },
    "X-Frame-Options": {
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "advice": "Use DENY or SAMEORIGIN to prevent clickjacking."
    },
    "X-Content-Type-Options": {
        "check": lambda v: v.lower() == "nosniff",
        "advice": "Set to 'nosniff' to stop MIME-type sniffing."
    },
    "Referrer-Policy": {
        "check": lambda v: "no-referrer" in v or "strict-origin" in v,
        "advice": "Use a strict Referrer-Policy (e.g., strict-origin-when-cross-origin)."
    },
    "Permissions-Policy": {
        "check": lambda v: len(v) > 0,
        "advice": "Define a restrictive Permissions-Policy header."
    },
    "Cross-Origin-Opener-Policy": {
        "check": lambda v: v.lower() in ("same-origin", "same-origin-allow-popups"),
        "advice": "Set COOP to same-origin to isolate browsing contexts."
    },
    "Cross-Origin-Embedder-Policy": {
        "check": lambda v: v.lower() == "require-corp",
        "advice": "Use COEP require-corp to enable cross-origin isolation."
    },
    "Cross-Origin-Resource-Policy": {
        "check": lambda v: v.lower() in ("same-origin", "same-site"),
        "advice": "Set CORP to same-origin to restrict resource loading."
    },
}

def analyze_security_headers(headers: Dict[str, str]) -> List[Dict]:
    """Return list of findings for missing or weakly configured security headers."""
    findings = []
    for header, spec in HEADER_CHECKS.items():
        if header not in headers:
            findings.append({
                "type": f"Missing {header}",
                "severity": "Medium",
                "confidence": "Confirmed",
                "evidence": f"{header} header not present.",
                "remediation": spec["advice"],
                "cwe": "CWE-693",
                "owasp": "A05:2021-Security Misconfiguration"
            })
        else:
            value = headers[header]
            if not spec["check"](value):
                findings.append({
                    "type": f"Weak {header}",
                    "severity": "Low",
                    "confidence": "Confirmed",
                    "evidence": f"{header}: {value}",
                    "remediation": spec["advice"],
                    "cwe": "CWE-693",
                    "owasp": "A05:2021-Security Misconfiguration"
                })
    return findings

async def check_cors(http_client: HttpClient, base_url: str) -> List[Dict]:
    """Test for CORS misconfigurations using various Origin headers."""
    findings = []
    test_origins = {
        "wildcard": "*",
        "null": "null",
        "evil": "https://evil.com",
        "subdomain": f"{base_url.rstrip('/')}.evil.com",
    }
    for name, origin in test_origins.items():
        resp = await http_client.request(base_url, headers={"Origin": origin})
        if not resp:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao:
            if acao == "*" and acac == "true":
                findings.append({
                    "type": "CORS Misconfiguration (credentials with wildcard)",
                    "severity": "High",
                    "confidence": "Confirmed",
                    "evidence": f"Origin: {origin} -> ACAO: *, ACAC: true",
                    "remediation": "Never use wildcard with credentials. Specify exact origins.",
                    "cwe": "CWE-942",
                    "owasp": "A01:2021-Broken Access Control"
                })
            elif acao == origin:
                findings.append({
                    "type": "CORS Misconfiguration (origin reflection)",
                    "severity": "Medium",
                    "confidence": "Confirmed",
                    "evidence": f"Origin: {origin} reflected back in ACAO.",
                    "remediation": "Do not reflect arbitrary origins.",
                    "cwe": "CWE-942",
                    "owasp": "A01:2021"
                })
    return findings

# =========================== TLS ANALYSIS ==========================
async def analyze_tls(target: str) -> Dict:
    """Perform basic TLS/certificate checks."""
    host = urlparse(target).hostname
    port = 443
    ctx = ssl.create_default_context()
    result = {"host": host}
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                not_after = cert.get("notAfter")
                expired = False
                if not_after:
                    try:
                        expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        expired = expire_date < datetime.now(timezone.utc)
                    except:
                        pass
                result.update({
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires": not_after,
                    "expired": expired,
                    "san": cert.get("subjectAltName", []),
                    "key_size": ssock.server_public_key.key_size if hasattr(ssock.server_public_key, "key_size") else None,
                    "cipher": cipher,
                    "version": ssock.version(),
                })
    except Exception as e:
        result["error"] = str(e)
    return result

def generate_tls_findings(tls_info: Dict) -> List[Dict]:
    """Convert TLS analysis results into security findings."""
    findings = []
    if "error" in tls_info:
        findings.append({
            "type": "TLS Connection Error",
            "severity": "Informational",
            "evidence": tls_info["error"],
            "remediation": "Ensure TLS is properly configured.",
            "cwe": "CWE-310"
        })
        return findings
    if tls_info.get("expired"):
        findings.append({
            "type": "Expired SSL/TLS Certificate",
            "severity": "High",
            "evidence": f"Certificate expired {tls_info['expires']}",
            "remediation": "Renew the certificate immediately.",
            "cwe": "CWE-298"
        })
    if tls_info.get("key_size") and tls_info["key_size"] < 2048:
        findings.append({
            "type": "Weak TLS Key Size",
            "severity": "Medium",
            "evidence": f"RSA key size {tls_info['key_size']} bits",
            "remediation": "Use at least 2048-bit RSA or ECDSA.",
            "cwe": "CWE-326"
        })
    if tls_info.get("version") and "TLSv1.0" in tls_info["version"]:
        findings.append({
            "type": "Deprecated TLS Protocol",
            "severity": "Medium",
            "evidence": f"Protocol {tls_info['version']}",
            "remediation": "Disable TLS 1.0/1.1; use TLS 1.2+",
            "cwe": "CWE-326"
        })
    return findings

# ====================== FINGERPRINTING =============================
TECH_SIGNATURES = {
    "React": {"html": ["react.production.min.js", "react.development.js"]},
    "Vue": {"html": ["vue.js", "vue.min.js"]},
    "Angular": {"html": ["ng-app", "angular.js"]},
    "Next.js": {"html": ["__NEXT_DATA__", "/_next/static/"]},
    "Laravel": {"headers": ["XSRF-TOKEN"]},
    "Django": {"headers": ["csrftoken"]},
    "Express": {"headers": ["x-powered-by"], "values": ["express"]},
    "ASP.NET": {"html": ["__VIEWSTATE", ".aspx"], "headers": ["x-powered-by"], "values": ["ASP.NET"]},
    "Spring Boot": {"headers": ["x-application-context"]},
    "WordPress": {"html": ["wp-content", "wp-includes"]},
    "Shopify": {"html": ["cdn.shopify.com", "myshopify.com"]},
}

WAF_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "__cfduid"]},
    "Akamai": {"headers": ["X-Akamai-Transformed", "AkamaiGHost"]},
    "Fastly": {"headers": ["X-Served-By"]},
    "Imperva": {"headers": ["X-Iinfo"]},
    "AWS CloudFront": {"headers": ["X-Cache"], "values": ["Hit from cloudfront"]},
}

def detect_technologies(headers: Dict[str, str], html: str) -> Dict[str, Set[str]]:
    """Identify frameworks, CDN/WAF from headers and HTML content."""
    tech = set()
    waf = set()
    for name, sigs in TECH_SIGNATURES.items():
        if "headers" in sigs:
            for hdr in sigs["headers"]:
                if hdr in headers:
                    value = headers[hdr]
                    if "values" in sigs and any(v.lower() in value.lower() for v in sigs["values"]):
                        tech.add(name)
                    else:
                        tech.add(name)
        if "html" in sigs:
            for frag in sigs["html"]:
                if frag.lower() in html.lower():
                    tech.add(name)
    for name, sigs in WAF_SIGNATURES.items():
        if "headers" in sigs:
            for hdr in sigs["headers"]:
                if hdr in headers:
                    if "values" in sigs:
                        value = headers[hdr]
                        if any(v.lower() in value.lower() for v in sigs["values"]):
                            waf.add(name)
                    else:
                        waf.add(name)
    return {"technologies": tech, "waf_cdn": waf}

# ======================= VULN SCANNER =============================
class VulnScanner:
    """Scans for XSS, SQLi, Open Redirects, and sensitive files, with evidence."""
    def __init__(self, config: ScanConfig, http: HttpClient, findings_db: List[Dict]):
        self.config = config
        self.http = http
        self.findings = findings_db   # shared list to append results

    async def _get_baseline(self, url: str) -> Tuple[Optional[str], int]:
        resp = await self.http.request(url)
        if resp:
            return await resp.text(), resp.status
        return None, 0

    async def scan_xss(self, urls: Set[str]):
        token = generate_token()
        payload = f"{token}'><img src=x onerror=alert(1)>"
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for param in params:
                test_params = params.copy()
                test_params[param] = [payload]
                qs = "&".join(f"{k}={quote(v[0])}" for k, v in test_params.items())
                test_url = urlunparse(parsed._replace(query=qs))
                resp = await self.http.request(test_url)
                if not resp:
                    continue
                text = await resp.text()
                if token in text:
                    self.findings.append({
                        "type": "Reflected XSS",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Unique token {token} reflected in response.",
                        "confidence": "Confirmed",
                        "severity": "High",
                        "cwe": "CWE-79",
                        "owasp": "A03:2021-Injection",
                        "cvss": 6.1,
                        "remediation": "Output-encode user data; set CSP."
                    })
                    break   # one finding per URL is enough

    async def scan_sqli(self, urls: Set[str]):
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            baseline_text, _ = await self._get_baseline(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in ["'", "\"", "1' OR '1'='1"]:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    qs = "&".join(f"{k}={quote(v[0])}" for k, v in test_params.items())
                    test_url = urlunparse(parsed._replace(query=qs))
                    resp = await self.http.request(test_url)
                    if not resp:
                        continue
                    text = await resp.text()
                    # Error-based detection
                    for err in ERROR_SQL:
                        if err.search(text):
                            self.findings.append({
                                "type": "SQL Injection (Error-based)",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Database error pattern: {err.pattern}",
                                "confidence": "Confirmed",
                                "severity": "Critical",
                                "cwe": "CWE-89",
                                "owasp": "A03:2021-Injection",
                                "cvss": 9.8,
                                "remediation": "Use parameterized queries / prepared statements."
                            })
                            return
                    # Boolean-based: significant length change
                    if baseline_text and text and abs(len(text) - len(baseline_text)) > 300:
                        self.findings.append({
                            "type": "SQL Injection (Boolean-based)",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Response length changed by {abs(len(text)-len(baseline_text))} bytes.",
                            "confidence": "Potential",
                            "severity": "High",
                            "cwe": "CWE-89",
                            "owasp": "A03:2021-Injection",
                            "cvss": 8.5,
                            "remediation": "Use parameterized queries."
                        })
                        return

    async def scan_open_redirect(self, urls: Set[str]):
        payload = "//evil.com"
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for param in params:
                if any(k in param.lower() for k in ["url", "redirect", "next", "goto"]):
                    test_params = params.copy()
                    test_params[param] = [payload]
                    qs = "&".join(f"{k}={quote(v[0])}" for k, v in test_params.items())
                    test_url = urlunparse(parsed._replace(query=qs))
                    resp = await self.http.request(test_url)
                    if resp and is_redirect(resp.status):
                        loc = resp.headers.get("Location", "")
                        if "evil.com" in loc:
                            self.findings.append({
                                "type": "Open Redirect",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Redirects to {loc}",
                                "confidence": "Confirmed",
                                "severity": "Medium",
                                "cwe": "CWE-601",
                                "owasp": "A01:2021-Broken Access Control",
                                "cvss": 6.1,
                                "remediation": "Validate redirect URLs against a whitelist."
                            })

    async def scan_sensitive_files(self, base_url: str):
        for path in SENSITIVE_FILES:
            test_url = urljoin(base_url, path)
            resp = await self.http.request(test_url)
            if not resp:
                continue
            if resp.status == 200:
                content = await resp.text()
                if len(content) > 20:   # not empty / error page
                    self.findings.append({
                        "type": "Sensitive File Exposure",
                        "url": test_url,
                        "evidence": f"Status 200, length {len(content)} bytes",
                        "confidence": "Confirmed",
                        "severity": "Medium",
                        "cwe": "CWE-200",
                        "owasp": "A01:2021",
                        "cvss": 5.3,
                        "remediation": "Restrict access to sensitive files, disable directory listing."
                    })

    async def run(self, visited_urls: Set[str], base_url: str):
        await asyncio.gather(
            self.scan_xss(visited_urls),
            self.scan_sqli(visited_urls),
            self.scan_open_redirect(visited_urls),
            self.scan_sensitive_files(base_url),
        )

# =========================== REPORTER ==============================
class Reporter:
    """Generates reports in HTML, JSON, CSV formats with dashboard."""
    def __init__(self, findings: List[Dict], config: ScanConfig, stats: Dict, tech_info: Dict):
        self.findings = findings
        self.config = config
        self.stats = stats
        self.tech_info = tech_info

    def to_json(self) -> str:
        return json.dumps(self.findings, indent=2)

    def to_csv(self) -> str:
        output = io.StringIO()
        if not self.findings:
            return "No findings."
        writer = csv.DictWriter(output, fieldnames=self.findings[0].keys())
        writer.writeheader()
        writer.writerows(self.findings)
        return output.getvalue()

    def to_html(self) -> str:
        """Generate a self-contained HTML dashboard with Chart.js."""
        findings = self.findings
        # Count severities
        sev_counts = defaultdict(int)
        for f in findings:
            sev_counts[f.get("severity", "Informational")] += 1

        # Prepare chart data
        labels = ["Critical", "High", "Medium", "Low", "Informational"]
        data = [sev_counts.get(l, 0) for l in labels]

        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nemesis Scan Report – {self.config.target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
h1 {{ color: #b91c1c; }}
.card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
canvas {{ max-width: 600px; margin: 0 auto; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background-color: #b91c1c; color: white; }}
.sev-Critical {{ background-color: #dc3545; color: white; }}
.sev-High {{ background-color: #fd7e14; color: white; }}
.sev-Medium {{ background-color: #ffc107; }}
.sev-Low {{ background-color: #0dcaf0; }}
.sev-Informational {{ background-color: #6c757d; color: white; }}
</style>
</head>
<body>
<h1>🔥 Nemesis Scan Report</h1>
<div class="card">
<p><strong>Target:</strong> {self.config.target}</p>
<p><strong>Scan Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
<p><strong>Author:</strong> Haris Farooqi</p>
</div>

<div class="card">
<h2>Executive Summary</h2>
<p>Total Findings: {len(findings)}</p>
<ul>
  {"".join(f"<li>{l}: {sev_counts[l]}</li>" for l in labels if sev_counts[l])}
</ul>
</div>

<div class="card">
<h2>Risk Distribution</h2>
<canvas id="severityChart"></canvas>
</div>

<script>
const ctx = document.getElementById('severityChart').getContext('2d');
new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: {json.dumps(labels)},
        datasets: [{{
            data: {json.dumps(data)},
            backgroundColor: ['#dc3545','#fd7e14','#ffc107','#0dcaf0','#6c757d']
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom' }} }}
    }}
}});
</script>

<div class="card">
<h2>Asset & Technology Summary</h2>
<p><strong>Technologies Detected:</strong> {", ".join(self.tech_info.get("technologies", [])) or "None"}</p>
<p><strong>WAF/CDN:</strong> {", ".join(self.tech_info.get("waf_cdn", [])) or "None"}</p>
<p><strong>URLs Crawled:</strong> {self.stats.get('crawled', 0)}</p>
<p><strong>Forms Found:</strong> {self.stats.get('forms', 0)}</p>
</div>

<div class="card">
<h2>Findings ({len(findings)})</h2>
<table>
<tr><th>#</th><th>Type</th><th>Severity</th><th>Confidence</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr>
{"".join(f"<tr class=\"sev-{f.get('severity','Informational').replace(' ','')}\"><td>{i+1}</td><td>{f['type']}</td><td>{f.get('severity','')}</td><td>{f.get('confidence','')}</td><td>{f.get('url','')}</td><td>{f.get('evidence','')}</td><td>{f.get('remediation','')}</td></tr>" for i,f in enumerate(findings))}
</table>
</div>
</body>
</html>"""
        return html

    def save(self, filename: str, fmt: str):
        if fmt == "json":
            with open(filename, "w") as f:
                f.write(self.to_json())
        elif fmt == "csv":
            with open(filename, "w", newline="") as f:
                f.write(self.to_csv())
        elif fmt == "html":
            with open(filename, "w") as f:
                f.write(self.to_html())
        else:
            raise ValueError(f"Unsupported format: {fmt}")

# ============================ MAIN CLI =============================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Nemesis – Autonomous Bug Bounty Probe by Haris Farooqi",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-u", "--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent workers (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Max requests/second per host")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--headers", help="File containing custom headers (key:value per line)")
    parser.add_argument("--cookies", help="File containing cookies (name=value per line)")
    parser.add_argument("--output", help="Output file base name (without extension)")
    parser.add_argument("--format", default="html", help="Report formats: html,json,csv (comma-separated)")
    parser.add_argument("--user-agent", default="Nemesis/1.0", help="User-Agent string or 'random'")
    parser.add_argument("--scope", help="Restrict scanning to this domain")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt")
    parser.add_argument("--max-urls", type=int, default=500, help="Maximum URLs to crawl")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()

def load_headers_file(filepath: str) -> Dict[str, str]:
    if not filepath:
        return {}
    headers = {}
    with open(filepath) as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def load_cookies_file(filepath: str) -> Dict[str, str]:
    if not filepath:
        return {}
    cookies = {}
    with open(filepath) as f:
        for line in f:
            if "=" in line:
                k, v = line.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

async def main():
    args = parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    console.print(BANNER, style="bold red")

    # Build config
    custom_headers = {}
    if args.headers:
        custom_headers = load_headers_file(args.headers)
    cookies = {}
    if args.cookies:
        cookies = load_cookies_file(args.cookies)

    config = ScanConfig(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        depth=args.depth,
        rate_limit=args.rate_limit,
        proxy=args.proxy,
        user_agent=args.user_agent,
        custom_headers=custom_headers,
        cookies=cookies,
        output=args.output,
        formats=set(args.format.split(",")),
        respect_robots=not args.ignore_robots,
        max_urls=args.max_urls,
        verbose=args.verbose,
        scope=Scope(domain=args.scope) if args.scope else None,
    )

    findings: List[Dict] = []
    stats = {}
    tech_info = {}

    async with HttpClient(config) as http:
        # Crawl
        crawler = Crawler(config, http)
        crawl_data = await crawler.run()   # <--- FIXED: removed extra argument
        stats["crawled"] = len(crawl_data["visited"])
        stats["forms"] = len(crawl_data["forms"])

        # Analyze homepage for technology / headers / TLS
        home_resp = await http.request(config.target)
        if home_resp:
            home_html = await home_resp.text()
            headers = home_resp.headers

            # Fingerprinting
            tech_info = detect_technologies(headers, home_html)

            # Security headers
            header_findings = analyze_security_headers(headers)
            findings.extend(header_findings)

            # CORS
            cors_findings = await check_cors(http, config.target)
            findings.extend(cors_findings)

            # TLS
            tls_info = await analyze_tls(config.target)
            tls_findings = generate_tls_findings(tls_info)
            findings.extend(tls_findings)

        # Vulnerability scanning
        scanner = VulnScanner(config, http, findings)
        await scanner.run(crawl_data["visited"], config.target)

    # Reporting
    reporter = Reporter(findings, config, stats, tech_info)
    out_base = config.output or config.target.replace("://", "_").replace("/", "_")
    for fmt in config.formats:
        filename = f"{out_base}.{fmt}"
        reporter.save(filename, fmt)
        console.print(f"[+] Report saved: {filename}", style="green")

    # Terminal summary
    table = Table(title="Nemesis Findings", box=box.MINIMAL)
    table.add_column("Type", style="bold red")
    table.add_column("Severity", style="yellow")
    table.add_column("Confidence", style="cyan")
    for f in findings:
        table.add_row(f["type"], f.get("severity", ""), f.get("confidence", ""))
    console.print(table)
    console.print(f"\n[bold green]Scan complete. {len(findings)} finding(s) reported.[/]")
    console.print("[italic]Crafted with precision by Haris Farooqi[/]")

if __name__ == "__main__":
    asyncio.run(main())
