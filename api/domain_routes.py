"""
Domain Analysis Blueprint
Comprehensive domain reconnaissance with enhanced capabilities.
"""
import time
import requests
import traceback
from datetime import datetime
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_domain, sanitize_domain
from all_functions import all_functions
import database as db
import logging

logger = logging.getLogger(__name__)
domain_bp = Blueprint("domain", __name__)


@domain_bp.route("/api/analyze-domain", methods=["POST"])
def analyze_domain():
    """Full domain reconnaissance: WHOIS, DNS, SSL, security features, subdomains."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        raw_domain = data.get("domain", "").strip()
        domain = sanitize_domain(raw_domain) if raw_domain else ""
        valid, err = validate_domain(domain)
        if not valid:
            return error_response(err, 400)

        recon = all_functions()

        domain_info = {
            "domain": domain,
            "whois": {},
            "dns_records": {},
            "ssl_info": {},
            "security_features": {},
            "subdomains": [],
            "geolocation": {},
            "technology": {},
        }
        recommendations = []

        # ── WHOIS ────────────────────────────────────────
        try:
            whois_data = recon.perform_whois_lookup(domain)
            if whois_data and isinstance(whois_data, list):
                whois_info = {}
                for item in whois_data:
                    field = item.get("Field", "").lower()
                    value = item.get("Value", "")
                    if "registrar" in field:
                        whois_info["registrar"] = value
                    elif "created" in field or "creation" in field:
                        whois_info["creation_date"] = value
                    elif "expires" in field or "expiration" in field:
                        whois_info["expiration_date"] = value
                    elif "registrant" in field:
                        whois_info["registrant"] = value
                    elif "country" in field:
                        whois_info["country"] = value
                    elif "name servers" in field:
                        whois_info["name_servers"] = value.split(", ")
                domain_info["whois"] = whois_info
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")

        # ── DNS Records ──────────────────────────────────
        try:
            dns_data = recon.get_dns_records(domain)
            if dns_data and isinstance(dns_data, list):
                dns_records = {}
                for item in dns_data:
                    record_type = item.get("Field", "")
                    value = item.get("Value", "")
                    if value and "No records found" not in value and "Error" not in value:
                        dns_records[record_type] = value.split(", ")
                domain_info["dns_records"] = dns_records
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")

        # TXT Records
        try:
            txt_data = recon.get_txt_records(domain)
            if txt_data and isinstance(txt_data, list):
                txt_records = []
                for item in txt_data:
                    if item.get("Field") == "TXT Records":
                        txt_records.append(item.get("Value", ""))
                if txt_records:
                    domain_info["dns_records"]["TXT"] = txt_records
        except Exception as e:
            logger.warning(f"TXT records lookup failed: {e}")

        # ── SSL Certificate ──────────────────────────────
        try:
            ssl_data = recon.get_ssl_chain_details(domain)
            if ssl_data and isinstance(ssl_data, list):
                ssl_info = {}
                for item in ssl_data:
                    field = item.get("Field", "").lower()
                    value = item.get("Value", "")
                    if "issuer" in field:
                        ssl_info["issuer"] = value
                    elif "subject" in field:
                        ssl_info["subject"] = value
                    elif "valid from" in field:
                        ssl_info["valid_from"] = value
                    elif "valid until" in field:
                        ssl_info["valid_until"] = value
                    elif "days until expiry" in field:
                        try:
                            ssl_info["days_until_expiry"] = int(value)
                        except (ValueError, TypeError):
                            ssl_info["days_until_expiry"] = value
                ssl_info["valid"] = bool(ssl_info)
                domain_info["ssl_info"] = ssl_info
        except Exception as e:
            logger.warning(f"SSL lookup failed: {e}")
            domain_info["ssl_info"] = {"valid": False}

        # SSL Labs Grade
        try:
            ssl_labs_data = recon.fetch_ssl_labs_report_table(domain)
            if ssl_labs_data and isinstance(ssl_labs_data, list):
                for item in ssl_labs_data:
                    if item.get("Field") == "Grade":
                        domain_info["ssl_info"]["grade"] = item.get("Value", "N/A")
                        break
        except Exception:
            pass

        # ── Security Features ────────────────────────────
        security_features = {}

        # DNSSEC
        try:
            dnssec_data = recon.check_dnssec(domain)
            dnssec_enabled = False
            if dnssec_data and isinstance(dnssec_data, list):
                for item in dnssec_data:
                    if "keys found" in item.get("Value", "").lower():
                        dnssec_enabled = True
                        break
            security_features["dnssec"] = dnssec_enabled
        except Exception:
            security_features["dnssec"] = False

        # DMARC
        try:
            dmarc_data = recon.get_dmarc_record(domain)
            dmarc_record = None
            if dmarc_data and isinstance(dmarc_data, list):
                for item in dmarc_data:
                    if item.get("Field") == "DMARC Record" and "No DMARC" not in item.get("Value", ""):
                        dmarc_record = item.get("Value", "")
                        break
            security_features["dmarc"] = dmarc_record or "Not configured"
        except Exception:
            security_features["dmarc"] = "Not configured"

        # WAF Detection
        try:
            waf_data = recon.detect_waf(domain)
            waf_detected = "None"
            if waf_data and isinstance(waf_data, list):
                for item in waf_data:
                    value = item.get("Value", "")
                    if "No WAF found" not in value:
                        waf_detected = value
                        break
            security_features["waf_detected"] = waf_detected
        except Exception:
            security_features["waf_detected"] = "Unknown"

        # robots.txt
        try:
            robots_data = recon.check_robots_txt(domain)
            robots_present = False
            robots_url = None
            if robots_data and isinstance(robots_data, list):
                for item in robots_data:
                    if (item.get("Field") != "Error" and item.get("Field") != "Not Found"
                            and item.get("Value") != "Not Found"):
                        robots_present = True
                        robots_url = f"http://{domain}/robots.txt"
                        break
            security_features["robots_txt"] = {"present": robots_present, "url": robots_url}
        except Exception:
            security_features["robots_txt"] = {"present": False, "url": None}

        # security.txt
        try:
            security_txt_data = recon.check_security_txt(domain)
            security_txt_present = False
            security_txt_url = None
            if security_txt_data and isinstance(security_txt_data, list):
                for item in security_txt_data:
                    if (item.get("Field") != "Error" and item.get("Field") != "Not Found"
                            and item.get("Value") != "Not Found"):
                        security_txt_present = True
                        try:
                            resp = requests.get(f"http://{domain}/.well-known/security.txt", timeout=5)
                            if resp.status_code == 200:
                                security_txt_url = f"http://{domain}/.well-known/security.txt"
                            else:
                                resp = requests.get(f"http://{domain}/security.txt", timeout=5)
                                if resp.status_code == 200:
                                    security_txt_url = f"http://{domain}/security.txt"
                        except Exception:
                            security_txt_url = f"http://{domain}/.well-known/security.txt"
                        break
            security_features["security_txt"] = {"present": security_txt_present, "url": security_txt_url}
        except Exception:
            security_features["security_txt"] = {"present": False, "url": None}

        domain_info["security_features"] = security_features

        # ── Subdomains ───────────────────────────────────
        try:
            subdomain_data = recon.fetch_subdomains(domain)
            subdomains = []
            if subdomain_data and isinstance(subdomain_data, list):
                for item in subdomain_data:
                    if item.get("Field") == "Subdomain":
                        sub = item.get("Value", "")
                        if sub and sub not in subdomains:
                            subdomains.append(sub)
            domain_info["subdomains"] = subdomains[:50]
        except Exception:
            domain_info["subdomains"] = []

        # ── Geolocation ──────────────────────────────────
        try:
            geo_data = recon.get_ip_info_from_a_record(domain)
            if geo_data and isinstance(geo_data, list):
                geo_info = {}
                for item in geo_data:
                    field = item.get("Field", "").lower()
                    value = item.get("Value", "")
                    if "ip address" in field:
                        geo_info["ip"] = value
                    elif "country" in field:
                        geo_info["country"] = value
                    elif "city" in field:
                        geo_info["city"] = value
                    elif "isp" in field:
                        geo_info["isp"] = value
                    elif "organization" in field:
                        geo_info["organization"] = value
                domain_info["geolocation"] = geo_info
        except Exception:
            pass

        # ── Recommendations ──────────────────────────────
        if not security_features.get("dnssec", False):
            recommendations.append({
                "category": "DNS", "severity": "medium",
                "text": "Enable DNSSEC for enhanced DNS security",
                "mitre": "T1584.001"
            })
        if security_features.get("dmarc") == "Not configured":
            recommendations.append({
                "category": "Email", "severity": "high",
                "text": "Configure DMARC policy for email security",
                "mitre": "T1566"
            })
        days_until_expiry = domain_info["ssl_info"].get("days_until_expiry", 0)
        try:
            days_until_expiry = int(days_until_expiry)
        except (ValueError, TypeError):
            days_until_expiry = 0
        if 0 < days_until_expiry < 30:
            recommendations.append({
                "category": "SSL", "severity": "high",
                "text": f"SSL certificate expires in {days_until_expiry} days — plan for renewal",
                "mitre": "T1557"
            })
        if not security_features.get("security_txt", {}).get("present"):
            recommendations.append({
                "category": "Policy", "severity": "low",
                "text": "Add security.txt for vulnerability disclosure",
                "mitre": None
            })
        if not security_features.get("robots_txt", {}).get("present"):
            recommendations.append({
                "category": "Policy", "severity": "info",
                "text": "Add robots.txt for web crawler guidance",
                "mitre": None
            })
        if security_features.get("waf_detected") == "None":
            recommendations.append({
                "category": "Infrastructure", "severity": "medium",
                "text": "Consider implementing a Web Application Firewall (WAF)",
                "mitre": "T1190"
            })

        duration_ms = int((time.time() - start) * 1000)

        # Calculate overall risk score
        risk_score = _calculate_domain_risk(domain_info, security_features)

        response_data = {
            "domain_info": domain_info,
            "recommendations": recommendations,
            "risk_score": risk_score,
            "scan_duration_ms": duration_ms,
        }

        # Save to database
        try:
            db.save_scan("domain", domain, response_data,
                         risk_level=risk_score["level"], score=risk_score["score"],
                         summary=f"Domain scan: {domain}", duration_ms=duration_ms)
        except Exception as e:
            logger.warning(f"Failed to save scan history: {e}")

        return success_response(response_data)

    except Exception as e:
        logger.error(f"Domain analysis error: {e}\n{traceback.format_exc()}")
        return error_response(f"Domain analysis failed: {str(e)}", 500)


@domain_bp.route("/api/security-file-content", methods=["POST"])
def get_security_file_content():
    """Fetch robots.txt or security.txt content from a target domain."""
    try:
        data = request.get_json(silent=True) or {}
        file_type = data.get("file_type", "").strip()
        domain = sanitize_domain(data.get("domain", ""))

        if not file_type or file_type not in ("robots", "security"):
            return error_response("file_type must be 'robots' or 'security'", 400)
        valid, err = validate_domain(domain)
        if not valid:
            return error_response(err, 400)

        if file_type == "robots":
            urls = [f"http://{domain}/robots.txt"]
        else:
            urls = [
                f"http://{domain}/.well-known/security.txt",
                f"http://{domain}/security.txt",
            ]

        for url in urls:
            try:
                resp = requests.get(url, timeout=15, allow_redirects=True)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "").lower()
                    text = resp.text

                    # Reject HTML error pages masquerading as 200
                    if "text/html" in ct:
                        keywords = (
                            ["user-agent:", "disallow:", "allow:", "sitemap:"]
                            if file_type == "robots"
                            else ["contact:", "expires:", "encryption:", "policy:"]
                        )
                        if not any(kw in text.lower() for kw in keywords):
                            continue

                    return success_response({
                        "domain": domain,
                        "file_type": file_type,
                        "url": url,
                        "content": text,
                        "content_length": len(text),
                        "last_modified": resp.headers.get("last-modified", "Unknown"),
                        "content_type": resp.headers.get("content-type", "text/plain"),
                    })
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue

        return error_response(
            f"{file_type}.txt not found for {domain}",
            404, error_code="FILE_NOT_FOUND"
        )

    except Exception as e:
        logger.error(f"Security file content error: {e}")
        return error_response(str(e), 500)


def _calculate_domain_risk(domain_info: dict, security_features: dict) -> dict:
    """Calculate an overall domain risk score 0-100.

    Model: start from a neutral baseline and apply penalties/bonuses.
    This avoids classifying typical domains as high-risk only because
    optional controls (e.g. DNSSEC/WAF/security.txt) are absent.
    """
    score = 65
    factors = []

    ssl = domain_info.get("ssl_info", {})
    if ssl.get("valid"):
        score += 10
    else:
        score -= 25
        factors.append("No valid SSL certificate")

    days = ssl.get("days_until_expiry", 0)
    try:
        days = int(days)
    except (ValueError, TypeError):
        days = 0

    if days > 90:
        score += 5
    elif 30 < days <= 90:
        score += 2
    elif 0 < days <= 30:
        score -= 10
        factors.append("SSL certificate expiring soon")

    # DNSSEC is good to have, but absence alone should not force high risk
    if security_features.get("dnssec"):
        score += 5
    else:
        factors.append("DNSSEC not enabled")

    dmarc_value = security_features.get("dmarc")
    if dmarc_value and dmarc_value != "Not configured":
        score += 10
    else:
        score -= 8
        factors.append("No DMARC policy")

    waf_value = security_features.get("waf_detected")
    if waf_value and waf_value not in ("None", "Unknown"):
        score += 6

    if security_features.get("security_txt", {}).get("present"):
        score += 2

    if security_features.get("robots_txt", {}).get("present"):
        score += 2

    if domain_info.get("whois", {}).get("registrar"):
        score += 6
    else:
        score -= 5
        factors.append("WHOIS data missing or incomplete")

    if domain_info.get("dns_records"):
        score += 6
    else:
        score -= 12
        factors.append("DNS records missing")

    score = max(0, min(score, 100))

    if score >= 80:
        level = "low"
    elif score >= 55:
        level = "medium"
    elif score >= 30:
        level = "high"
    else:
        level = "critical"

    return {"score": score, "level": level, "factors": factors}
