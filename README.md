# CyberRegis Server

Threat-intelligence and attack-surface analysis API. Backend for [CyberRegis-Client](https://github.com/Kathan2004/CyberRegis-Client).

Give it an IP, domain, URL or packet capture. It correlates VirusTotal, AbuseIPDB, Google Safe Browsing, Shodan, OTX, MalwareBazaar, NVD and MITRE ATT&CK, runs its own active checks (ports, TLS, headers, email auth, security.txt), and returns a scored risk report. Results are stored, can be exported, and can be pushed to Telegram.

```
client ──► Flask API (KALE.py) ──► api/* blueprints ──► netguard (SSRF guard) ──► target
                    │                      │
                    │                      └──► provider APIs (VT, AbuseIPDB, Shodan, OTX, NVD ...)
                    └──► SQLite (scan history, IOCs, feeds, CVE cache)   └──► Telegram alerts / bot
```

## Capabilities

| Area | Endpoints |
|---|---|
| IP reputation | `POST /api/check-ip` |
| URL analysis (Safe Browsing, TLS, redirects, keywords, RDAP) | `POST /api/check-url` |
| Domain posture (WHOIS, DNS, DNSSEC, WAF, security.txt, robots.txt) | `POST /api/analyze-domain` |
| Email security (SPF, DMARC, DKIM) | `POST /api/email-security` |
| Port and vulnerability scan (nmap, socket fallback) | `POST /api/scan-ports`, `POST /api/vulnerability-scan` |
| TLS and HTTP header grading | `POST /api/ssl-analysis`, `POST /api/security-headers` |
| PCAP analysis (flows, protocols, VT lookup, charts) | `POST /api/analyze-pcap` |
| IOC store | `GET/POST /api/iocs`, `DELETE /api/iocs/<id>`, `POST /api/iocs/check` |
| Threat feeds | `GET /api/threat-feeds`, `/insights`, `/search`, `POST /refresh` |
| CVE and ATT&CK | `GET /api/cve/search`, `/api/cve/<id>`, `/api/mitre/*` |
| Shodan proxy (35 routes) | `/api/shodan/*` |
| Reports and history | `POST /api/reports/generate`, `GET /api/scan-history` |
| AI analyst (Gemini) | `POST /api/chat` |
| Health | `GET /api/health` (only unauthenticated route) |

## Security model

- **Authentication.** Every `/api/*` route except `/api/health` requires `API_TOKEN`, sent as `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **Safe defaults.** The server binds to `127.0.0.1`. It refuses to bind to a public interface without a token, and refuses `FLASK_ENV=production` without one.
- **SSRF guard.** `netguard.py` resolves every caller-supplied host and rejects loopback, RFC1918, link-local (cloud metadata), CGNAT, multicast and IPv6-local addresses. Redirects are re-checked hop by hop. `ALLOW_PRIVATE_TARGETS=true` lifts this, for isolated labs only.
- **Uploads.** PCAP files are stored under random names and deleted after analysis.
- **Telegram bot.** It only obeys chat IDs listed in `TELEGRAM_CHAT_ID`.
- **Rate limiting.** `flask-limiter` is enabled, along with nosniff, frame-deny, no-referrer and no-store response headers.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Run it

### Local

```bash
git clone https://github.com/Kathan2004/CyberRegis_Server.git && cd CyberRegis_Server
python -m venv .venv && source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env                                     # add the provider keys you have
python KALE.py
curl http://127.0.0.1:5000/api/health
```

### Docker

```bash
docker build -t cyberregis-server .
docker run --env-file .env -e API_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))") -p 127.0.0.1:5000:5000 cyberregis-server
```

### Example call

```bash
curl -s http://127.0.0.1:5000/api/check-ip \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}' | jq .
```

## Configuration

All settings come from environment variables; see [.env.example](.env.example). Every provider key is optional: a check whose key is missing is skipped and reported as unavailable.

## Development

```bash
pip install -r requirements-dev.txt
pytest -q tests                         # unit tests (SSRF guard, auth)
ruff check --select E9,F63,F7,F82,F401 .
python scripts/smoke/validate_e2e.py    # live smoke checks against a running server
```

CI runs the tests, the lint and a gitleaks secret scan on every push and pull request.

## Layout

```
KALE.py              app factory, auth, CORS, headers, entry point
config.py            environment-driven settings
netguard.py          outbound target validation and safe_get
database.py          SQLite persistence
all_functions.py     recon engine (DNS, WHOIS, ports, TLS, headers)
api/                 Flask blueprints, one per feature area
services/            CVE, MITRE, Shodan, threat feeds, notifications
tests/               pytest suite
scripts/smoke/       live-server smoke scripts
docs/                API notes, diagrams, paper sources
```

## Legal

Only scan systems you own or are authorised to test.
