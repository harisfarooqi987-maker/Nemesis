Nemesis —  Bug Bounty 
<p align="center"> <img src="https://raw.githubusercontent.com/harisfarooqi/nemesis/main/assets/banner.png" alt="Nemesis Banner" width="100%" /> </p><p align="center"> <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version"> <img src="https://img.shields.io/badge/python-3.9%2B-green?style=flat-square&logo=python" alt="Python"> <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License"> <img src="https://img.shields.io/github/stars/harisfarooqi/nemesis?style=flat-square" alt="Stars"> </p>
✨ Why Nemesis?
Verified findings – Reflected XSS is confirmed via unique token injection; SQL injection is detected through error patterns and response length comparison; sensitive files are reported only when directly accessible (200 OK). 403? Protected. No false 
Blazing fast – Async engine with connection pooling, configurable concurrency, per‑host rate limiting, and retry with exponential backoff.
Complete coverage – Crawls recursively with depth control, parses robots.txt and sitemap.xml, extracts JavaScript endpoints, HTML forms, and GraphQL/WebSocket indicators.
Technology intelligence – Detects frameworks (React, Vue, Laravel, etc.) and CDN/WAF providers (Cloudflare, Akamai, Fastly, …).
Security posture analysis – Tests all critical headers (HSTS, CSP, X‑Frame‑Options, COOP/COEP/CORP, Permissions‑Policy…) and performs TLS certificate validation.
Professional reports – Self‑contained HTML dashboard with Chart.js risk doughnut, executive summary, asset inventory, and detailed finding tables (CWE, OWASP, CVSS, evidence, remediation). Export to JSON or CSV with one flag.
Fallback‑safe – Works without optional libraries; graceful degradation for CVSS calculation and Markdown rendering.
📦 Installation
1)Prerequisites
Python 3.9 or newer.
2)Install required packages
bash
git clone https://github.com/harisfarooqi/nemesis.git
cd nemesis
pip install -r requirements.txt
3)requirements.txt

text
aiohttp>=3.9
beautifulsoup4>=4.12
rich>=13.7
tldextract>=5.1
fake-useragent>=1.5
4)Optional – for precise CVSS scores and enhanced Markdown
pip install cvss markdown
🚀 Quick Start
python nemesis.py -u https://example.com
Advanced example
python nemesis.py \
  -u https://target.com \
  --threads 20 \
  --depth 3 \
  --rate-limit 10 \
  --format html,json,csv \
  --output my_scan \
  --proxy http://127.0.0.1:8080 \
  --user-agent random \
  --verbose
  ⚙️ Command‑Line Reference
Flag       	 Description	                                  Default
-u / --target	 Target URL (required)	                              –
--threads	 Concurrent workers	                              10
--timeout	 Request timeout (seconds)	                      15
--depth	Maximum  crawl depth	                                      3
--rate-limit	 Requests/second per host	                      5.0
--proxy	Proxy    URL (e.g., http://127.0.0.1:8080)	              –
--headers	 File with custom headers (Key: Value per line)	      –
--cookies	 File with cookies (name=value per line)	      –
--output	 Report base filename (without extension)	      auto from target
--format	 Output formats: html, json, csv (comma‑separated )   html
--user-agent	 User‑Agent string, or random	                      Nemesis/1.0
--scope	Restrict to this domain (sub‑domains included)	              parsed from target
--ignore-robots	 Ignore robots.txt disallow rules	              False
--max-urls	 Maximum URLs to crawl	                              500
--verbose	 Enable debug logging	                              False
📊 Sample HTML Report
<p align="center"> <img src="https://raw.githubusercontent.com/harisfarooqi/nemesis/main/assets/report-preview.png" alt="HTML Dashboard" width="90%" /> </p>
🧠 How It Works
Nemesis is built around an asynchronous pipeline:

Crawler – Starts from the target, respects scope/robots, and recursively follows links. It extracts forms, JavaScript endpoints, and parses sitemaps.

Fingerprinter – Analyses headers and HTML to identify frameworks, CDNs, and WAFs.

Security Analyser – Checks all relevant response headers, performs CORS misconfiguration tests, and runs a TLS scan (certificate, cipher, key size).

Vulnerability Scanner – Injects test payloads into query parameters. Findings are only reported when a verification step succeeds (e.g., token reflected for XSS, SQL error message present, or redirect to external domain for open redirect). Sensitive files are flagged only when HTTP 200 is returned.

Reporter – Collects all findings and statistics, renders them into a self‑contained HTML page, or exports as JSON/CSV.
🤝 Development & Contributing
Contributions are welcome. Please open an issue to discuss your idea before submitting a pull request.

To run in development mode:

bash
git clone https://github.com/harisfarooqi/nemesis.git
cd nemesis
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python nemesis.py -u http://testphp.vulnweb.com --verbose
📝 License
MIT © Haris Farooqi.
Use responsibly and only on systems you are authorised to test.
👤 Author
Haris Farooqi
Security researcher & toolsmith.
GitHub · Twitter
