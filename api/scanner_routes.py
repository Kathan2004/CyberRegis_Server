"""
Scanner Blueprint
Port scanning & vulnerability assessment.
"""
import time
import logging
import socket
from collections import Counter
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_target
from all_functions import all_functions
import database as db
from services.shodan_service import ShodanService

logger = logging.getLogger(__name__)
scanner_bp = Blueprint("scanner", __name__)
shodan = ShodanService()


@scanner_bp.route("/api/scan-ports", methods=["POST"])
def scan_ports():
    """Enhanced port scanning with service detection."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        valid, err = validate_target(target)
        if not valid:
            return error_response(err or "Invalid target", 400)

        recon = all_functions()
        result = recon.scan_ports_detailed(target)
        duration_ms = int((time.time() - start) * 1000)

        # Enrich with risk info
        open_ports = [p for p in result.get("ports", []) if p.get("state") == "open"]
        high_risk_ports = {21, 23, 25, 445, 3389, 5900, 6379, 27017, 1433, 3306, 5432}
        high_risk = [p for p in open_ports if p.get("port") in high_risk_ports]
        services = Counter((p.get("service") or "unknown") for p in open_ports)
        attack_surface_score = min(100, len(open_ports) * 5 + len(high_risk) * 8)
        risk_level = "high" if high_risk else ("medium" if len(open_ports) > 5 else "low")
        result["risk_summary"] = {
            "open_ports": len(open_ports),
            "high_risk_ports": len(high_risk),
            "risk_level": risk_level,
            "attack_surface_score": attack_surface_score,
            "high_risk_port_details": [
                {
                    "port": p.get("port"),
                    "service": p.get("service") or "unknown",
                    "reason": "Commonly targeted exposed service",
                }
                for p in high_risk
            ],
            "top_services": [{"service": svc, "count": cnt} for svc, cnt in services.most_common(5)],
            "recommendations": [
                "Restrict high-risk ports using firewall ACLs",
                "Expose administrative ports only over VPN/private networks",
                "Verify service patch levels and disable unused services",
            ] if open_ports else ["No open ports detected in scanned range"],
        }

        if shodan.enabled:
            shodan_ip = target
            if any(ch.isalpha() for ch in target):
                try:
                    shodan_ip = socket.gethostbyname(target)
                except Exception:
                    shodan_ip = target

            shodan_host = shodan.host(shodan_ip, minify=True)
            if shodan_host.get("ok"):
                h = shodan_host.get("data", {})
                result["shodan"] = {
                    "enabled": True,
                    "ip": h.get("ip_str") or shodan_ip,
                    "org": h.get("org"),
                    "isp": h.get("isp"),
                    "asn": h.get("asn"),
                    "ports": h.get("ports", []),
                    "vulnerabilities": sorted(list((h.get("vulns") or {}).keys()))[:20] if isinstance(h.get("vulns"), dict) else [],
                    "last_update": h.get("last_update"),
                }
            else:
                result["shodan"] = {"enabled": True, "error": shodan_host.get("error")}
        else:
            result["shodan"] = {"enabled": False}

        result["scan_duration_ms"] = duration_ms

        try:
            db.save_scan("port", target, result,
                         risk_level=result["risk_summary"]["risk_level"],
                         summary=f"{len(open_ports)} open ports", duration_ms=duration_ms)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        return error_response(str(e), 500)


@scanner_bp.route("/api/vulnerability-scan", methods=["POST"])
def vulnerability_scan():
    """Vulnerability assessment based on service detection."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        valid, err = validate_target(target)
        if not valid:
            return error_response(err or "Invalid target", 400)

        recon = all_functions()
        result = recon.vulnerability_scan(target)
        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

        vulnerabilities = result.get("vulnerabilities", [])
        sev = result.get("severity_breakdown", {})
        high = int(sev.get("high", 0) + sev.get("critical", 0))
        medium = int(sev.get("medium", 0))
        low = int(sev.get("low", 0))
        top_findings = sorted(vulnerabilities, key=lambda v: v.get("risk_score", 0), reverse=True)[:3]
        result["risk_summary"] = {
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "max_risk_score": result.get("max_risk_score", top_findings[0].get("risk_score", 0) if top_findings else 0),
            "top_findings": [
                {
                    "service": v.get("service"),
                    "port": v.get("port"),
                    "severity": v.get("severity"),
                    "risk_score": v.get("risk_score", 0),
                }
                for v in top_findings
            ],
            "prioritized_actions": [
                "Patch or harden highest-risk exposed services first",
                "Restrict internet exposure of administrative and database ports",
                "Enable continuous vulnerability and configuration monitoring",
            ],
        }

        try:
            vulns = result.get("vulnerabilities", [])
            db.save_scan("vuln", target, result,
                         risk_level="high" if len(vulns) > 3 else "medium" if vulns else "low",
                         summary=f"{len(vulns)} potential vulnerabilities",
                         duration_ms=duration_ms)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"Vulnerability scan error: {e}")
        return error_response(str(e), 500)
