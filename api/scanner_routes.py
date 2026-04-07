"""
Scanner Blueprint
Port scanning & vulnerability assessment.
"""
import time
import logging
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_target
from all_functions import all_functions
import database as db

logger = logging.getLogger(__name__)
scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/api/scan-ports", methods=["POST"])
def scan_ports():
    """Enhanced port scanning with service detection."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        valid, err = validate_target(target)
        if not valid:
            return error_response(err, 400)

        recon = all_functions()
        result = recon.scan_ports_detailed(target)
        duration_ms = int((time.time() - start) * 1000)

        # Enrich with risk info
        open_ports = [p for p in result.get("ports", []) if p.get("state") == "open"]
        high_risk = [p for p in open_ports if p.get("port") in (21, 23, 25, 445, 3389, 5900)]
        result["risk_summary"] = {
            "open_ports": len(open_ports),
            "high_risk_ports": len(high_risk),
            "risk_level": "high" if high_risk else ("medium" if len(open_ports) > 5 else "low"),
        }
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
            return error_response(err, 400)

        recon = all_functions()
        result = recon.vulnerability_scan(target)
        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

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
