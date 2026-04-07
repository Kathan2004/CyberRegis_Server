# CyberRegis Server

## Prerequisites
- Python 3.10+
- Git

## 1) Clone
```bash
git clone https://github.com/Kathan2004/CyberRegis_Server.git
cd CyberRegis_Server
```

## 2) Create virtual environment
```bash
python -m venv .venv
```

## 3) Activate virtual environment
### Windows (PowerShell)
```powershell
.\.venv\Scripts\Activate.ps1
```

### macOS/Linux
```bash
source .venv/bin/activate
```

## 4) Install dependencies
```bash
pip install -r requirements.txt
```

## 5) Configure environment
Create `.env` in project root (or copy from `.env.example` if available) and set values as needed:

```env
FLASK_ENV=development
FLASK_DEBUG=true
FLASK_PORT=5000
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
SAFE_BROWSING_KEY=
SSL_VERIFY=true
```

## 6) Run server
```bash
python KALE.py
```

Server endpoints:
- Health: `http://127.0.0.1:5000/api/health`
- Dashboard: `http://127.0.0.1:5000/api/dashboard/stats`

## 7) Quick smoke test
```bash
curl http://127.0.0.1:5000/api/health
```

## Notes
- These are normal local startup commands (no proxy-bypass commands).
- Keep `SSL_VERIFY=true` for standard environments.
