"""
Security Analysis Blueprint
SSL/TLS, security headers, and email security scanning.
"""
import time
import logging
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_domain, validate_url, sanitize_domain
from all_functions import all_functions
import database as db

logger = logging.getLogger(__name__)
security_bp = Blueprint("security", __name__)


@security_bp.route("/api/ssl-analysis", methods=["POST"])
def ssl_analysis():
    """Detailed SSL/TLS analysis."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        domain = sanitize_domain(data.get("domain", ""))
        valid, err = validate_domain(domain)
        if not valid:
            return error_response(err, 400)

        recon = all_functions()
        result = recon.ssl_detailed_analysis(domain)
        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

        try:
            db.save_scan("ssl", domain, result,
                         summary=f"SSL analysis: {domain}", duration_ms=duration_ms)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"SSL analysis error: {e}")
        return error_response(str(e), 500)


@security_bp.route("/api/security-headers", methods=["POST"])
def security_headers():
    """Security headers analysis with scoring."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        if not url:
            return error_response("URL is required", 400)
        # Auto-prepend https if missing
        if not url.startswith("http"):
            url = f"https://{url}"
        valid, err = validate_url(url)
        if not valid:
            return error_response(err, 400)

        recon = all_functions()
        result = recon.security_headers_scan(url)
        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

        try:
            db.save_scan("headers", url, result,
                         risk_level=result.get("grade"),
                         score=result.get("security_score"),
                         summary=f"Headers grade: {result.get('grade')}",
                         duration_ms=duration_ms)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"Security headers error: {e}")
        return error_response(str(e), 500)


@security_bp.route("/api/email-security", methods=["POST"])
def email_security():
    """Email security analysis (SPF, DMARC, DKIM)."""
    start = time.time()
    try:
        data = request.get_json(silent=True) or {}
        domain = sanitize_domain(data.get("domain", ""))
        valid, err = validate_domain(domain)
        if not valid:
            return error_response(err, 400)

        recon = all_functions()
        result = recon.email_security_deep_scan(domain)
        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

        try:
            es = result.get("email_security", {})
            db.save_scan("email", domain, result,
                         risk_level=es.get("grade"),
                         score=es.get("total_score"),
                         summary=f"Email security grade: {es.get('grade')}",
                         duration_ms=duration_ms)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"Email security error: {e}")
        return error_response(str(e), 500)
