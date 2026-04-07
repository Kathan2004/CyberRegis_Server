"""
Report Generation Blueprint
Generate security assessment reports.
"""
import logging
import json
from datetime import datetime
from flask import Blueprint, request
from api.responses import success_response, error_response
import database as db

logger = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/api/reports/generate", methods=["POST"])
def generate_report():
    """Generate a comprehensive security report. Target is optional; omit for a platform-wide report."""
    try:
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        report_type = data.get("type", "summary")  # summary | detailed | executive

        # Gather scan history — scoped to target or platform-wide
        if target:
            scans = db.get_scan_history(target=target, limit=100)
        else:
            scans = db.get_scan_history(limit=500)

        if not scans:
            return error_response("No scan data found. Run some scans first.", 404)

        # Build report
        report_label = target if target else "All Targets"
        report = {
            "target": report_label,
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "executive_summary": _build_executive_summary(report_label, scans),
            "scan_results": _organize_scan_results(scans),
            "risk_assessment": _aggregate_risk(scans),
            "recommendations": _aggregate_recommendations(scans),
            "timeline": _build_timeline(scans),
            "total_scans": len(scans),
            "unique_targets": len({s.get("target") for s in scans if s.get("target")}),
        }

        return success_response(report)
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return error_response(str(e), 500)


@reports_bp.route("/api/reports/targets", methods=["GET"])
def list_report_targets():
    """List all unique targets that have been scanned (for report generation)."""
    try:
        from database import _connect
        conn = _connect()
        rows = conn.execute("""
            SELECT target, COUNT(*) as scan_count,
                   MAX(created_at) as last_scanned,
                   MIN(created_at) as first_scanned
            FROM scan_history
            GROUP BY target
            ORDER BY scan_count DESC
            LIMIT 100
        """).fetchall()
        conn.close()
        targets = [dict(r) for r in rows]
        return success_response({"targets": targets})
    except Exception as e:
        logger.error(f"Report targets error: {e}")
        return error_response(str(e), 500)


def _build_executive_summary(target: str, scans: list) -> dict:
    scan_types = set(s.get("scan_type") for s in scans)
    risk_levels = [s.get("risk_level") for s in scans if s.get("risk_level")]

    # Determine overall risk
    risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_risk = max(risk_levels, key=lambda r: risk_priority.get(str(r).lower(), 0), default="unknown")

    return {
        "target": target,
        "overall_risk": max_risk,
        "scan_coverage": list(scan_types),
        "total_assessments": len(scans),
        "findings_count": len([s for s in scans if s.get("risk_level") and
                               str(s["risk_level"]).lower() in ("high", "critical")]),
    }


def _organize_scan_results(scans: list) -> dict:
    organized = {}
    for scan in scans:
        stype = scan.get("scan_type", "unknown")
        if stype not in organized:
            organized[stype] = []
        organized[stype].append({
            "id": scan.get("id"),
            "target": scan.get("target"),
            "risk_level": scan.get("risk_level"),
            "score": scan.get("score"),
            "summary": scan.get("summary"),
            "created_at": scan.get("created_at"),
            "duration_ms": scan.get("duration_ms"),
        })
    return organized


def _aggregate_risk(scans: list) -> dict:
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for scan in scans:
        level = str(scan.get("risk_level", "unknown")).lower()
        if level in risk_counts:
            risk_counts[level] += 1
        else:
            risk_counts["unknown"] += 1

    total = len(scans)
    high_critical = risk_counts["critical"] + risk_counts["high"]
    overall_score = max(0, 100 - (high_critical * 20) - (risk_counts["medium"] * 10))

    return {
        "distribution": risk_counts,
        "overall_score": overall_score,
        "high_critical_count": high_critical,
        "total_assessed": total,
    }


def _aggregate_recommendations(scans: list) -> list:
    all_recs = []
    seen = set()
    for scan in scans:
        result = scan.get("result", {})
        if isinstance(result, dict):
            recs = result.get("recommendations", [])
            if isinstance(recs, list):
                for rec in recs:
                    text = rec.get("text", rec) if isinstance(rec, dict) else str(rec)
                    if text not in seen:
                        seen.add(text)
                        all_recs.append({
                            "text": text,
                            "category": rec.get("category", "General") if isinstance(rec, dict) else "General",
                            "severity": rec.get("severity", "medium") if isinstance(rec, dict) else "medium",
                        })
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_recs.sort(key=lambda r: severity_order.get(r["severity"], 5))
    return all_recs[:20]


def _build_timeline(scans: list) -> list:
    timeline = []
    for scan in sorted(scans, key=lambda s: s.get("created_at", ""), reverse=True)[:20]:
        timeline.append({
            "time": scan.get("created_at"),
            "type": scan.get("scan_type"),
            "target": scan.get("target"),
            "risk_level": scan.get("risk_level"),
            "summary": scan.get("summary"),
        })
    return timeline
