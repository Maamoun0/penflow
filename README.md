# 🛡️ PenFlow — Autonomous Web Application Security Research Framework

Developed by **Ahmed Maamoun**

**PenFlow** is a modular, high-performance security research and automated reconnaissance engine designed for web application security auditing, vulnerability discovery, and deep attack surface mapping. 

Built on an asynchronous, multi-agent architecture with active adversarial falsification, PenFlow conducts thorough vulnerability assessments with high accuracy and zero false positives.

---

## 🔥 Key Features

### 🌐 1. Deep Reconnaissance & Scope Expansion
- **Multi-Level Subdomain & Sub-subdomain Discovery**: Combines Certificate Transparency logs (OSINT) with active high-density DNS brute-forcing for deep multi-tier subdomains (e.g., `api.dev.target.com`, `admin.staging.target.com`).
- **Sensitive File & Directory Fuzzing**: Probes exposed configuration files (`.env`), backups (`.sql`, `.zip`), source control leaks (`.git/HEAD`, `.svn`), and sensitive endpoints.
- **Wildcard Crawler Scope**: Intelligent BFS crawler extracts links and JavaScript routes dynamically across root domain boundaries (`*.target.com`).

### 🤖 2. 18 Specialized Security Capability Agents
PenFlow employs 18 dedicated capability agents, each targeting specific vulnerability classes:

1. **GraphQL Security Engine**: Introspection check, Field Suggestion schema harvesting, Query Batching abuse, Depth Limit DoS, and Alias Amplification testing.
2. **Multi-Vector CORS Auditor**: Probes 7 CORS bypass vectors including arbitrary origins, null origin, subdomain trust, prefix/suffix flaws, and HTTP downgrade.
3. **NoSQL & SQL Injection Specialist**: Error-based, boolean-blind, and time-based blind SQLi across MySQL, PostgreSQL, Oracle, MSSQL, SQLite, and MongoDB.
4. **SSTI & OS Command Injection Matrix**: 6-engine template evaluation matrix (Jinja2, Twig, FreeMarker, Smarty, ERB, Velocity) and OS command execution.
5. **HTTP Request Smuggling**: Detects CL.TE, TE.CL, and TE.TE HTTP desynchronization flaws between reverse proxies and origin backends.
6. **Subdomain Takeover Auditor**: Fingerprints 12 dangling cloud services (AWS S3, GitHub Pages, Heroku, Fastly, Azure, Netlify, Vercel, Pantheon, etc.).
7. **Parameter Discovery Engine**: Brute-forces 300+ hidden query parameters and 8 reverse proxy/auth bypass headers (`X-Forwarded-For`, `X-Original-URL`).
8. **Reflected & Stored XSS Agent**: Parameterized query injection with WAF-bypass polyglots and stored POST form testing.
9. **IDOR / BOLA Agent**: Differential cross-session object identifier manipulation.
10. **BFLA Agent**: Broken Function Level Authorization & HTTP method tampering (GET -> POST/PUT/DELETE).
11. **OAuth 2.0 & JWT Security Agent**: Weak signatures, `none` algorithm, kid parameter tampering, and redirect URI manipulation.
12. **Race Condition Engine**: Synchronized burst HTTP execution testing for TOCTOU and financial state flaws.
13. **Rate Limit Bypass Agent**: IP rotation, header spoofing, and null-byte parameter truncation testing.
14. **Mass Assignment Agent**: Hidden parameter pollution and privilege elevation probing.
15. **Information Disclosure Agent**: Server headers, stack trace, and sensitive metadata disclosure checks.
16. **Open Redirect Agent**: Outbound parameter redirection testing.
17. **Security Configuration Auditor**: OWASP 14-point HTTP security headers audit with risk scoring.
18. **Capabilities Orchestrator**: Dynamic capability resolver and worker pool manager.

### 🛡️ 3. Adversarial Critic Verification Engine
Every candidate finding is passed through a 9-rule falsification engine:
- Soft 404 & custom error body filtering
- WAF block signature detection
- SSTI literal reflection validation
- Timing anomaly verification (for blind injections)
- Content-length differential & JSON field-count comparison

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+**
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/Maamoun0/penflow.git
cd penflow

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Standard Fast Recon Scan
```bash
python -m penflow scan example.com
```

### Deep Autonomous Research Scan
```bash
python -m penflow scan example.com --deep
```

### Scan via Interception Proxy (e.g. Burp Suite / Caido)
```bash
python -m penflow scan example.com --proxy http://127.0.0.1:8080 --deep
```

---

## 🧪 Testing & Quality Assurance

PenFlow comes with a comprehensive unit test suite covering all 18 capability agents, recon modules, and validation logic.

```bash
# Run all unit tests
python -m pytest tests/unit -v
```

---

## 👨‍💻 Author

**Ahmed Maamoun**
- GitHub: [@Maamoun0](https://github.com/Maamoun0)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
