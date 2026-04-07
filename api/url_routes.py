"""
URL Analysis Blueprint
Google Safe Browsing + domain reputation.
"""
import time
import logging
import requests
from datetime import datetime
from urllib.parse import urlparse
import urllib.parse
import re
import whois
import socket
import ssl as _ssl
from flask import Blueprint, request as flask_request
from api.responses import success_response, error_response
from api.validators import validate_url
from config import get_config
import database as db

logger = logging.getLogger(__name__)
url_bp = Blueprint("url", __name__)
cfg = get_config()


@url_bp.route("/api/check-url", methods=["POST"])
def check_url():
    """URL safety analysis: Safe Browsing + SSL + WHOIS + keyword heuristics."""
    start = time.time()
    try:
        data = flask_request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        valid, err = validate_url(url)
        if not valid:
            return error_response(err, 400)

        parsed = urlparse(url)
        domain = parsed.netloc

        # ── Google Safe Browsing ─────────────────────────
        threat_analysis = _check_safe_browsing(url)

        # ── SSL Check ────────────────────────────────────
        ssl_info = _check_ssl(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"}

        # ── Suspicious Patterns ──────────────────────────
        patterns = _check_suspicious_keywords(url)

        # ── Domain Analysis ──────────────────────────────
        domain_analysis = _analyze_domain(domain)

        # ── Build response ───────────────────────────────
        result = {
            "url_analysis": {
                "input_url": url,
                "parsed_details": {
                    "scheme": parsed.scheme,
                    "domain": domain,
                    "path": parsed.path,
                    "query_params": dict(urllib.parse.parse_qsl(parsed.query)),
                    "fragment": parsed.fragment,
                },
                "security_check_time": datetime.utcnow().isoformat() + "Z",
            },
            "threat_analysis": threat_analysis,
            "additional_checks": {
                "ssl_security": ssl_info,
                "suspicious_patterns": patterns,
                "domain_analysis": domain_analysis,
            },
            "recommendations": _generate_url_recommendations(threat_analysis, patterns, domain_analysis),
        }

        duration_ms = int((time.time() - start) * 1000)
        risk = threat_analysis.get("risk_level", patterns.get("risk_level", "low"))

        # Wrap in legacy PrettyJSONResponse structure for frontend compat
        response = {
            "data": result,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "success",
            "scan_duration_ms": duration_ms,
        }

        try:
            db.save_scan("url", url, result, risk_level=risk,
                         summary=f"URL check: {domain}", duration_ms=duration_ms)
        except Exception:
            pass

        try:
            from services.notification_service import notify
            notify("url", url, response)
        except Exception:
            pass

        return response, 200

    except Exception as e:
        logger.error(f"URL check error: {e}")
        return error_response(str(e), 500)


def _check_safe_browsing(url: str) -> dict:
    if not cfg.SAFE_BROWSING_KEY:
        return {"is_malicious": False, "threats_found": 0, "threat_details": [],
                "google_safe_browsing": {"status": "not_configured"}}
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={cfg.SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "cyberregis", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(api_url, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {
            "is_malicious": bool(data.get("matches")),
            "threats_found": len(data.get("matches", [])),
            "threat_details": data.get("matches", []),
            "google_safe_browsing": {"status": "checked", "response_code": resp.status_code},
        }
    except Exception as e:
        logger.warning(f"Safe Browsing API error: {e}")
        return {"is_malicious": False, "threats_found": 0, "threat_details": [],
                "google_safe_browsing": {"status": "error", "error": str(e)}}


def _check_ssl(url: str) -> dict:
    try:
        domain = urlparse(url).netloc
        context = _ssl._create_unverified_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                return {"valid": bool(cert), "status_code": 200}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _check_suspicious_keywords(url: str) -> dict:
    suspicious_words = [
        "login", "signin", "account", "bank", "verify", "secure", "update",
        "payment", "password", "credential", "wallet", "bitcoin", "crypto",
        "paypal", "apple", "microsoft", "amazon", "netflix",
    ]
    url_lower = url.lower()
    found = [w for w in suspicious_words if w in url_lower]
    return {
        "found": bool(found),
        "matches": found,
        "risk_level": "high" if len(found) > 2 else "medium" if found else "low",
    }


def _analyze_domain(domain: str) -> dict:
    suspicious_patterns = {
        "number_substitution": bool(re.search(r'\d+', domain)),
        "special_chars": bool(re.search(r'[^a-zA-Z0-9\-\.]', domain)),
        "suspicious_tld": domain.split(".")[-1] in ["xyz", "tk", "ml", "ga", "cf", "top", "buzz", "info"],
        "length": len(domain),
        "subdomains": len(domain.split(".")) - 1,
    }
    risk_score = 0
    risk_factors = []
    if suspicious_patterns["number_substitution"]:
        risk_score += 1
        risk_factors.append("Contains number substitution")
    if suspicious_patterns["suspicious_tld"]:
        risk_score += 2
        risk_factors.append("Uses suspicious TLD")
    if suspicious_patterns["length"] > 30:
        risk_score += 1
        risk_factors.append("Unusually long domain name")
    if suspicious_patterns["subdomains"] > 2:
        risk_score += 1
        risk_factors.append("Multiple subdomains")

    # WHOIS
    whois_data = {}
    try:
        w = whois.whois(domain)
        whois_data = {
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": w.get("name_servers"),
            "status": w.get("status"),
        }
    except Exception:
        whois_data = {"error": "WHOIS lookup failed"}

    return {
        "analysis": suspicious_patterns,
        "risk_score": risk_score,
        "risk_level": "high" if risk_score > 3 else "medium" if risk_score > 1 else "low",
        "risk_factors": risk_factors,
        "whois": whois_data,
    }


def _generate_url_recommendations(threat: dict, patterns: dict, domain: dict) -> list:
    recs = []
    if threat.get("is_malicious"):
        recs.extend([
            "AVOID this website — flagged as malicious by Google Safe Browsing",
            "Scan your device for malware immediately",
            "Report this URL to your IT security department",
        ])
    elif patterns.get("risk_level") == "high":
        recs.extend([
            "Proceed with extreme caution — multiple suspicious indicators",
            "Verify the website's authenticity before entering any data",
            "Avoid entering credentials or sensitive information",
        ])
    elif domain.get("risk_level") == "high":
        recs.extend([
            "Domain shows suspicious characteristics",
            "Verify the website's legitimacy through other channels",
        ])
    else:
        recs.append("No immediate threats detected — maintain standard security practices")
    return recs
