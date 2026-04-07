"""
IP Intelligence Blueprint
Comprehensive IP address analysis with multi-source enrichment.
"""
import time
import requests
import logging
from datetime import datetime
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_ip
from config import get_config
import database as db

logger = logging.getLogger(__name__)
ip_bp = Blueprint("ip", __name__)
cfg = get_config()


@ip_bp.route("/api/check-ip", methods=["POST"])
def check_ip():
    """Comprehensive IP address analysis with VirusTotal + AbuseIPDB."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get("ip", "").strip()
        valid, err = validate_ip(ip_address)
        if not valid:
            return error_response(err or "Invalid IP address", 400)

        # Collect all intelligence in one AbuseIPDB call
        abuse_data = _get_abuseipdb_data(ip_address)
        vt_data = _get_virustotal_ip(ip_address)
        geo_data = _get_geolocation(ip_address, abuse_data)
        shodan_data = _get_shodan_host(ip_address)
        abuse_reports = _extract_abuse_reports(abuse_data.get("reports", []))
        resolved_asn, resolved_as_name = _resolve_asn_details(abuse_data, vt_data, geo_data, shodan_data)

        # Build risk assessment from combined sources
        risk_assessment = _assess_risk(abuse_data, vt_data)

        # Technical details
        technical_details = {
            "as_name": resolved_as_name,
            "asn": resolved_asn,
            "is_public": abuse_data.get("isPublic", True),
            "is_tor": abuse_data.get("isTor", False),
            "usage_type": abuse_data.get("usageType") or "ISP",
            "organization": abuse_data.get("isp") or geo_data.get("organization") or "Unknown",
            "hostnames": abuse_data.get("hostnames") or [],
        }

        # Recommendations
        recommendations = _generate_recommendations(risk_assessment, vt_data, technical_details)

        # VT summary
        vt_risk = vt_data.get("risk_assessment", {})
        total_engines = vt_risk.get("total_engines", 0)
        malicious_count = vt_risk.get("malicious_count", 0)
        if total_engines == 0:
            vt_summary = f"IP {ip_address} has not been analyzed by any security engines."
        elif malicious_count == 0:
            vt_summary = f"IP {ip_address} analysed by {total_engines} engines — appears clean."
        else:
            vt_summary = (f"IP {ip_address} flagged by {vt_risk.get('detection_ratio', '0/0')} "
                          f"engines as potentially malicious (Risk: {vt_risk.get('risk_level', 'UNKNOWN')}).")

        duration_ms = int((time.time() - start) * 1000)

        result = {
            "ip_details": {
                "address": ip_address,
                "domain": abuse_data.get("domain", ""),
                "isp": geo_data.get("isp", "Unknown"),
                "location": geo_data.get("location", {}),
            },
            "abuseipdb": {
                "abuse_confidence_score": abuse_data.get("abuseConfidenceScore", 0),
                "total_reports": abuse_data.get("totalReports", 0),
                "num_distinct_users": abuse_data.get("numDistinctUsers", 0),
                "last_reported_at": abuse_data.get("lastReportedAt"),
                "country_code": abuse_data.get("countryCode"),
                "usage_type": abuse_data.get("usageType") or "Unknown",
                "isp": abuse_data.get("isp") or "Unknown",
                "domain": abuse_data.get("domain") or "",
                "hostnames": abuse_data.get("hostnames") or [],
                "is_public": abuse_data.get("isPublic", True),
                "is_tor": abuse_data.get("isTor", False),
                "is_whitelisted": abuse_data.get("isWhitelisted", False),
                "asn": abuse_data.get("asn", "Unknown"),
                "asn_name": abuse_data.get("asnName") or resolved_as_name,
                "reports": abuse_reports,
            },
            "risk_assessment": risk_assessment,
            "technical_details": technical_details,
            "virustotal": vt_data,
            "shodan": shodan_data,
            "virustotal_summary": vt_summary,
            "recommendations": recommendations,
            "scan_duration_ms": duration_ms,
        }

        # Match legacy response structure for frontend compatibility
        response = {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": result,
        }

        # Persist
        try:
            db.save_scan("ip", ip_address, result,
                         risk_level=str(risk_assessment.get("risk_level", "Unknown")),
                         score=float(risk_assessment.get("confidence_score", 0) or 0),
                         summary=vt_summary, duration_ms=duration_ms)
        except Exception as e:
            logger.warning(f"Failed to save scan: {e}")

        # Notify
        try:
            from services.notification_service import notify
            notify("ip", ip_address, response)
        except Exception:
            pass

        return response, 200

    except Exception as e:
        logger.error(f"IP analysis error: {e}")
        return error_response(f"IP analysis failed: {str(e)}", 500)


# ─── Internal helpers ────────────────────────────────────

def _get_abuseipdb_data(ip: str) -> dict:
    """Single AbuseIPDB call (instead of 3 redundant calls)."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": cfg.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception as e:
        logger.warning(f"AbuseIPDB error for {ip}: {e}")
        return {}


def _get_virustotal_ip(ip: str) -> dict:
    """VirusTotal IP reputation lookup."""
    try:
        if not cfg.VIRUSTOTAL_API_KEY:
            return _vt_fallback("No API key configured")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": cfg.VIRUSTOTAL_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values()) if stats else 0
            risk_score = min(100, int((malicious * 3 + suspicious * 2) / total * 100)) if total else 0
            comments = _get_virustotal_comments(ip)

            if risk_score >= 75:
                risk_level = "HIGH"
            elif risk_score >= 50:
                risk_level = "MEDIUM"
            elif risk_score >= 25:
                risk_level = "LOW"
            else:
                risk_level = "VERY_LOW"

            return {
                "risk_assessment": {
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
                    "total_engines": total,
                },
                "metadata": {
                    "reputation": attrs.get("reputation", 0),
                    "file_type": "IP Address",
                    "analysis_date": attrs.get("last_analysis_date"),
                    "as_owner": attrs.get("as_owner"),
                    "asn": attrs.get("asn"),
                    "network": attrs.get("network"),
                    "country": attrs.get("country"),
                    "continent": attrs.get("continent"),
                    "jarm": attrs.get("jarm"),
                    "total_votes": attrs.get("total_votes", {}),
                    "tags": attrs.get("tags", []),
                    "last_modification_date": attrs.get("last_modification_date"),
                },
                "data": {
                    "attributes": {
                        "stats": {"malicious": malicious, "suspicious": suspicious,
                                  "harmless": harmless, "undetected": undetected, "total": total},
                        "results": attrs.get("last_analysis_results", {}),
                    }
                },
                "community_comments": comments,
            }
        return _vt_fallback(f"HTTP {resp.status_code}")
    except Exception as e:
        return _vt_fallback(str(e))


def _vt_fallback(error_msg: str) -> dict:
    return {
        "risk_assessment": {"risk_score": 0, "risk_level": "UNKNOWN",
                            "malicious_count": 0, "suspicious_count": 0,
                            "detection_ratio": "0/0", "total_engines": 0},
        "metadata": {"reputation": 0, "file_type": "IP Address", "analysis_date": None,
                     "as_owner": None, "asn": None, "network": None, "country": None,
                     "continent": None, "jarm": None, "total_votes": {}, "tags": [],
                     "last_modification_date": None},
        "data": {"attributes": {"stats": {"malicious": 0, "suspicious": 0,
                                           "harmless": 0, "undetected": 0, "total": 0}, "results": {}}},
        "community_comments": [],
        "error": error_msg,
    }


def _get_virustotal_comments(ip: str) -> list:
    if not cfg.VIRUSTOTAL_API_KEY:
        return []
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
            headers={"x-apikey": cfg.VIRUSTOTAL_API_KEY},
            params={"limit": 5},
            timeout=12,
        )
        if resp.status_code != 200:
            return []
        rows = []
        for item in resp.json().get("data", []):
            attrs = item.get("attributes", {})
            rows.append({
                "id": item.get("id"),
                "author": attrs.get("user") or "anonymous",
                "date": attrs.get("date"),
                "text": attrs.get("text") or "",
            })
        return rows
    except Exception:
        return []


def _extract_abuse_reports(reports: list) -> list:
    cleaned = []
    if not isinstance(reports, list):
        return cleaned
    for report in reports[:10]:
        if not isinstance(report, dict):
            continue
        cleaned.append({
            "reported_at": report.get("reportedAt"),
            "comment": report.get("comment") or "",
            "categories": report.get("categories") or [],
            "reporter_country_code": report.get("reporterCountryCode"),
            "reporter_country_name": report.get("reporterCountryName"),
        })
    return cleaned


def _get_geolocation(ip: str, abuse_data: dict) -> dict:
    """Enrich geolocation from ip-api.com (fallback)."""
    fallback = {}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            fallback = resp.json()
    except Exception:
        pass

    return {
        "isp": abuse_data.get("isp") or fallback.get("isp", "Unknown"),
        "organization": abuse_data.get("isp") or fallback.get("org", "Unknown"),
        "as_raw": fallback.get("as"),
        "as_number": _normalize_asn(_extract_asn_number(fallback.get("as"))),
        "as_name": _extract_as_name(fallback.get("as")) or fallback.get("org"),
        "location": {
            "city": abuse_data.get("city") or fallback.get("city", "Unknown"),
            "region": abuse_data.get("region") or fallback.get("regionName", "Unknown"),
            "country": abuse_data.get("countryName") or fallback.get("country", "Unknown"),
            "country_code": abuse_data.get("countryCode") or fallback.get("countryCode", "Unknown"),
        },
    }


def _resolve_asn_details(abuse_data: dict, vt_data: dict, geo_data: dict, shodan_data: dict) -> tuple[str, str]:
    vt_meta = vt_data.get("metadata", {}) if isinstance(vt_data, dict) else {}
    shodan = shodan_data if isinstance(shodan_data, dict) else {}

    abuse_asn = _normalize_asn(abuse_data.get("asn"))
    vt_asn = _normalize_asn(vt_meta.get("asn"))
    geo_asn = _normalize_asn(geo_data.get("as_number"))
    shodan_asn = _normalize_asn(shodan.get("asn"))

    asn = abuse_asn or vt_asn or shodan_asn or geo_asn or "Unknown"

    abuse_name = _clean_text(abuse_data.get("asnName"))
    vt_name = _clean_text(vt_meta.get("as_owner"))
    shodan_name = _clean_text(shodan.get("org"))
    geo_name = _clean_text(geo_data.get("as_name"))

    as_name = abuse_name or vt_name or shodan_name or geo_name or "Unknown"
    return asn, as_name


def _get_shodan_host(ip: str) -> dict:
    if not getattr(cfg, "SHODAN_API_KEY", ""):
        return {"enabled": False}
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": cfg.SHODAN_API_KEY},
            timeout=12,
        )
        if resp.status_code != 200:
            return {"enabled": True, "error": f"HTTP {resp.status_code}"}

        data = resp.json()
        vulns = data.get("vulns", {})
        vuln_list = sorted(list(vulns.keys())) if isinstance(vulns, dict) else []
        ports = data.get("ports", []) if isinstance(data.get("ports", []), list) else []
        hostnames = data.get("hostnames", []) if isinstance(data.get("hostnames", []), list) else []

        return {
            "enabled": True,
            "ip": data.get("ip_str") or ip,
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "os": data.get("os"),
            "ports": ports[:25],
            "open_ports_count": len(ports),
            "hostnames": hostnames[:10],
            "tags": data.get("tags", []) if isinstance(data.get("tags", []), list) else [],
            "vulnerabilities": vuln_list[:20],
            "last_update": data.get("last_update"),
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}


def _clean_text(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "unknown", "n/a"}:
        return ""
    return text


def _normalize_asn(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.upper().startswith("AS"):
        suffix = text[2:].strip()
        return f"AS{suffix}" if suffix else ""
    if text.isdigit():
        return f"AS{text}"
    return text


def _extract_asn_number(as_field) -> str:
    text = _clean_text(as_field)
    if not text:
        return ""
    upper = text.upper()
    if upper.startswith("AS"):
        rest = text[2:].strip()
        parts = rest.split(maxsplit=1)
        candidate = parts[0] if parts else ""
        return candidate if candidate.isdigit() else ""
    parts = text.split(maxsplit=1)
    return parts[0] if parts and parts[0].isdigit() else ""


def _extract_as_name(as_field) -> str:
    text = _clean_text(as_field)
    if not text:
        return ""
    upper = text.upper()
    if upper.startswith("AS"):
        rest = text[2:].strip()
        parts = rest.split(maxsplit=1)
        return parts[1].strip() if len(parts) > 1 else ""
    parts = text.split(maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else text


def _assess_risk(abuse: dict, vt: dict) -> dict:
    abuse_score = abuse.get("abuseConfidenceScore", 0)
    total_reports = abuse.get("totalReports", 0)
    vt_score = vt.get("risk_assessment", {}).get("risk_score", 0)

    # Combined risk
    combined = max(abuse_score, vt_score)
    if combined > 75 or total_reports > 50:
        risk_level = "High"
    elif combined > 50 or total_reports > 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    categories = []
    if abuse_score > 75:
        categories.extend(["malware", "phishing"])
    if total_reports > 30:
        categories.append("botnet")
    if abuse.get("isTor"):
        categories.append("tor_exit_node")
    if abuse.get("isPublic") and abuse_score > 25:
        categories.append("public_proxy")
    if not categories:
        categories = ["clean"]

    return {
        "risk_level": risk_level,
        "confidence_score": abuse_score,
        "total_reports": total_reports,
        "last_reported": abuse.get("lastReportedAt") or datetime.utcnow().isoformat() + "Z",
        "categories": categories,
    }


def _generate_recommendations(risk: dict, vt: dict, tech: dict) -> list:
    recs = []
    level = risk.get("risk_level", "Unknown")
    vt_level = vt.get("risk_assessment", {}).get("risk_level", "UNKNOWN")

    if level == "High" or vt_level == "HIGH":
        recs.extend([
            "Block this IP address immediately in your firewall",
            "Investigate recent connections from this IP",
            "Report to your security team for incident response",
            "Monitor network traffic for lateral movement",
            "Check if any systems have been compromised",
        ])
    elif level == "Medium" or vt_level == "MEDIUM":
        recs.extend([
            "Monitor this IP for further suspicious activity",
            "Add to watchlist for automated alerting",
            "Verify if associated with legitimate services",
            "Implement additional network monitoring",
        ])
    else:
        recs.extend([
            "Continue standard monitoring",
            "Consider this IP as likely safe, maintain vigilance",
        ])

    cats = risk.get("categories", [])
    if "tor_exit_node" in cats:
        recs.append("TOR exit node — consider blocking unless required")
    if "botnet" in cats:
        recs.append("Botnet association detected — immediate blocking recommended")

    return recs[:6]
