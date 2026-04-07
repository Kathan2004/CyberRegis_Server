"""
Monitoring & Dashboard Blueprint
Health checks, system status, scan history, analytics.
"""
import sys
import os
import logging
from datetime import datetime
from flask import Blueprint, request
from api.responses import success_response, error_response
import database as db

logger = logging.getLogger(__name__)
monitoring_bp = Blueprint("monitoring", __name__)

_start_time = datetime.utcnow()


@monitoring_bp.route("/api/health", methods=["GET"])
def health_check():
    return success_response({
        "service": "CyberRegis Threat Intelligence Platform",
        "version": "2.0.0",
        "status": "healthy",
        "uptime_seconds": int((datetime.utcnow() - _start_time).total_seconds()),
    })


@monitoring_bp.route("/api/status", methods=["GET"])
def system_status():
    """Detailed system metrics."""
    try:
        import psutil
        proc = psutil.Process(os.getpid())
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return success_response({
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=0.5),
                "memory_percent": mem.percent,
                "memory_available_gb": round(mem.available / (1024 ** 3), 2),
                "disk_percent": disk.percent,
                "disk_free_gb": round(disk.free / (1024 ** 3), 2),
            },
            "process": {
                "pid": os.getpid(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "memory_mb": round(proc.memory_info().rss / (1024 ** 2), 1),
                "threads": proc.num_threads(),
                "uptime_seconds": int((datetime.utcnow() - _start_time).total_seconds()),
            },
        })
    except ImportError:
        return success_response({
            "system": {"note": "Install psutil for detailed metrics"},
            "process": {
                "pid": os.getpid(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            },
        })


@monitoring_bp.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Aggregated dashboard analytics."""
    try:
        stats = db.get_scan_stats()
        ioc_stats = db.get_ioc_stats()
        return success_response({
            "scans": stats,
            "iocs": ioc_stats,
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return error_response(str(e), 500)


@monitoring_bp.route("/api/scan-history", methods=["GET"])
def scan_history():
    """Retrieve scan history with filtering."""
    scan_type = request.args.get("type")
    target = request.args.get("target")
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    results = db.get_scan_history(scan_type=scan_type, target=target,
                                  limit=limit, offset=offset)
    return success_response({
        "scans": results,
    }, meta={"limit": limit, "offset": offset})


@monitoring_bp.route("/api/scan-history/<int:scan_id>", methods=["GET"])
def scan_detail(scan_id):
    """Retrieve a single scan result by ID."""
    result = db.get_scan_by_id(scan_id)
    if not result:
        return error_response("Scan not found", 404)
    return success_response(result)


@monitoring_bp.route("/api/monitoring-results", methods=["GET"])
def monitoring_results():
    """Legacy endpoint — returns active endpoint list + recent activity."""
    stats = db.get_scan_stats()
    return success_response({
        "server_status": "running",
        "uptime_seconds": int((datetime.utcnow() - _start_time).total_seconds()),
        "total_scans": stats.get("total_scans", 0),
        "scans_today": stats.get("today", 0),
        "active_endpoints": [
            "/api/check-url", "/api/check-ip", "/api/analyze-domain",
            "/api/scan-ports", "/api/vulnerability-scan", "/api/ssl-analysis",
            "/api/security-headers", "/api/email-security", "/api/analyze-pcap",
            "/api/chat", "/api/iocs", "/api/threat-feeds", "/api/cve",
            "/api/mitre/techniques", "/api/dashboard/stats", "/api/scan-history",
        ],
        "scan_stats": stats,
    })
