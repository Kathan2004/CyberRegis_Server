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
import socket
import ssl as _ssl
from flask import Blueprint, request as flask_request
from api.responses import success_response, error_response
from api.validators import validate_url
from config import get_config
import database as db
from services.shodan_service import ShodanService

logger = logging.getLogger(__name__)
url_bp = Blueprint("url", __name__)
cfg = get_config()
shodan = ShodanService()


@url_bp.route("/api/check-url", methods=["POST"])
def check_url():
    """URL safety analysis: Safe Browsing + SSL + WHOIS + keyword heuristics."""
    start = time.time()
    try:
        data = flask_request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        valid, err = validate_url(url)
        if not valid:
            return error_response(err or "Invalid URL", 400)

        parsed = urlparse(url)
        domain = parsed.netloc

        threat_analysis = _check_safe_browsing(url)
        ssl_info = _check_ssl(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"}
        http_behavior = _analyze_http_behavior(url)
        patterns = _check_suspicious_keywords(url)
        domain_analysis = _analyze_domain(domain)
        shodan_data = _shodan_url_enrichment(domain)

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
                "http_behavior": http_behavior,
                "shodan": shodan_data,
            },
            "risk_summary": _build_url_risk_summary(threat_analysis, patterns, domain_analysis, ssl_info, http_behavior),
            "recommendations": _generate_url_recommendations(threat_analysis, patterns, domain_analysis, ssl_info, http_behavior),
        }

        duration_ms = int((time.time() - start) * 1000)
        risk = threat_analysis.get("risk_level", patterns.get("risk_level", "low"))

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
                cert = ssock.getpeercert()
                cert_map = cert if isinstance(cert, dict) else {}
                cipher = ssock.cipher()
                expiry_raw = cert_map.get("notAfter")
                expiry_days = None
                if expiry_raw:
                    try:
                        expiry_dt = datetime.strptime(str(expiry_raw), "%b %d %H:%M:%S %Y %Z")
                        expiry_days = (expiry_dt - datetime.utcnow()).days
                    except Exception:
                        expiry_days = None
                issuer = {k: v for tup in cert_map.get("issuer", []) for k, v in tup}
                subject = {k: v for tup in cert_map.get("subject", []) for k, v in tup}
                return {
                    "valid": bool(cert_map),
                    "status_code": 200,
                    "tls_version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "expires_in_days": expiry_days,
                    "issuer": issuer.get("commonName") or issuer.get("organizationName"),
                    "subject": subject.get("commonName") or subject.get("organizationName"),
                }
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
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    extra_flags = {
        "has_ip_host": bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)),
        "has_punycode": "xn--" in domain,
        "has_at_symbol": "@" in url,
        "long_url": len(url) > 120,
        "too_many_subdomains": domain.count(".") >= 3,
    }
    extra_score = sum(1 for v in extra_flags.values() if v)
    base_score = len(found)
    score = min(100, (base_score * 12) + (extra_score * 15))

    return {
        "found": bool(found),
        "matches": found,
        "flags": extra_flags,
        "risk_score": score,
        "risk_level": "high" if score >= 60 else "medium" if score >= 25 else "low",
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

    # WHOIS/RDAP over HTTPS (firewall friendly)
    whois_data = _rdap_lookup(domain)

    return {
        "analysis": suspicious_patterns,
        "risk_score": risk_score,
        "risk_level": "high" if risk_score > 3 else "medium" if risk_score > 1 else "low",
        "risk_factors": risk_factors,
        "whois": whois_data,
    }


def _rdap_lookup(domain: str) -> dict:
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=10, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return {"error": f"RDAP lookup failed: HTTP {resp.status_code}"}
        data = resp.json()
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for prop in entity.get("vcardArray", [None, []])[1]:
                    if prop[0] == "fn":
                        registrar = prop[3]
                        break
                if registrar:
                    break
        created = None
        expires = None
        for ev in data.get("events", []):
            action = ev.get("eventAction")
            if action == "registration":
                created = ev.get("eventDate")
            elif action == "expiration":
                expires = ev.get("eventDate")
        return {
            "registrar": registrar,
            "creation_date": created,
            "expiration_date": expires,
            "status": data.get("status", []),
            "name_servers": [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")],
        }
    except Exception as e:
        return {"error": f"RDAP lookup failed: {str(e)}"}


def _shodan_url_enrichment(domain: str) -> dict:
    if not shodan.enabled:
        return {"enabled": False}
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"enabled": True, "error": f"DNS resolution failed: {e}"}

    host = shodan.host(ip, minify=True)
    if not host.get("ok"):
        return {"enabled": True, "error": host.get("error")}

    h = host.get("data", {})
    return {
        "enabled": True,
        "ip": h.get("ip_str") or ip,
        "org": h.get("org"),
        "isp": h.get("isp"),
        "asn": h.get("asn"),
        "ports": h.get("ports", []),
        "tags": h.get("tags", []) if isinstance(h.get("tags", []), list) else [],
        "vulnerabilities": sorted(list((h.get("vulns") or {}).keys()))[:20] if isinstance(h.get("vulns"), dict) else [],
        "last_update": h.get("last_update"),
    }


def _analyze_http_behavior(url: str) -> dict:
    try:
        resp = requests.get(url, timeout=12, verify=False, allow_redirects=True)
        history = [h.url for h in resp.history] + [resp.url]
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_count": len(resp.history),
            "redirect_chain": history,
            "server": resp.headers.get("Server"),
            "powered_by": resp.headers.get("X-Powered-By"),
            "content_type": resp.headers.get("Content-Type"),
            "hsts_present": "Strict-Transport-Security" in resp.headers,
            "set_cookie_count": len(resp.cookies.keys()),
        }
    except Exception as e:
        return {
            "status_code": None,
            "final_url": None,
            "redirect_count": 0,
            "redirect_chain": [],
            "error": str(e),
        }


def _build_url_risk_summary(threat: dict, patterns: dict, domain: dict, ssl_info: dict, http_behavior: dict) -> dict:
    factors = []
    score = 0

    if threat.get("is_malicious"):
        score += 80
        factors.append("Flagged by Google Safe Browsing")
    if patterns.get("risk_score", 0) > 0:
        score += min(35, int(patterns.get("risk_score", 0) * 0.4))
        factors.append("Suspicious URL pattern indicators present")
    if domain.get("risk_level") == "high":
        score += 20
        factors.append("Domain structure appears suspicious")
    if ssl_info and not ssl_info.get("valid", True):
        score += 15
        factors.append("TLS/SSL validation failed")
    if http_behavior.get("redirect_count", 0) >= 3:
        score += 10
        factors.append("Multiple redirects observed")
    if http_behavior.get("status_code") in (401, 403, 404, 500, 502, 503):
        score += 5
        factors.append(f"HTTP status {http_behavior.get('status_code')} observed")

    score = min(100, score)
    level = "high" if score >= 70 else "medium" if score >= 35 else "low"
    return {
        "overall_risk_score": score,
        "overall_risk_level": level,
        "factors": factors,
    }


def _generate_url_recommendations(threat: dict, patterns: dict, domain: dict, ssl_info: dict, http_behavior: dict) -> list:
    recs = []
    if threat.get("is_malicious"):
        recs.extend([
            {"category": "Threat Intel", "severity": "high", "text": "Avoid this website — flagged as malicious by Google Safe Browsing"},
            {"category": "Containment", "severity": "high", "text": "Block this URL/domain in web proxy and DNS controls"},
            {"category": "IR", "severity": "high", "text": "Investigate if any users accessed this URL recently"},
        ])
    elif patterns.get("risk_level") == "high":
        recs.extend([
            {"category": "Validation", "severity": "medium", "text": "Proceed with caution — multiple suspicious URL indicators detected"},
            {"category": "User Safety", "severity": "medium", "text": "Do not enter credentials or payment data until domain authenticity is confirmed"},
        ])
    elif domain.get("risk_level") == "high":
        recs.extend([
            {"category": "Domain", "severity": "medium", "text": "Domain characteristics are suspicious; verify ownership through trusted sources"},
        ])
    else:
        recs.append({"category": "General", "severity": "low", "text": "No immediate high-confidence threats detected"})

    expires_in_days = ssl_info.get("expires_in_days") if ssl_info else None
    try:
        expires_num = int(expires_in_days) if expires_in_days is not None else None
    except (TypeError, ValueError):
        expires_num = None
    if expires_num is not None and expires_num < 30:
        recs.append({"category": "TLS", "severity": "medium", "text": f"Certificate expires in {expires_num} days; monitor renewal risk"})
    if http_behavior.get("redirect_count", 0) >= 3:
        recs.append({"category": "HTTP", "severity": "medium", "text": "Excessive redirects observed; inspect redirect chain for phishing or cloaking"})

    return recs
