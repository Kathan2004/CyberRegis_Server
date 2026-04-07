"""
Threat Intelligence Blueprint
IOC management, CVE lookup, MITRE ATT&CK mapping, threat feed aggregation.
"""
import time
import logging
from urllib.parse import quote
from flask import Blueprint, request
from api.responses import success_response, error_response, paginated_response
from api.validators import validate_cve_id, validate_ip, validate_domain
import database as db

logger = logging.getLogger(__name__)
threat_intel_bp = Blueprint("threat_intel", __name__)


def _append_lookup_link(links: list[dict], seen: set[str], label: str, url: str | None) -> None:
    if not url or url in seen:
        return
    seen.add(url)
    links.append({"label": label, "url": url})


def _build_live_lookup_links(ioc: dict) -> list[dict]:
    value = (ioc.get("value") or ioc.get("indicator") or "").strip()
    ioc_type = (ioc.get("ioc_type") or "").strip().lower()
    source = (ioc.get("source") or ioc.get("feed_name") or "").strip().lower()
    source_root = source.split(":", 1)[0]
    source_reference = (ioc.get("reference") or "").strip()
    if not value:
        return []

    links: list[dict] = []
    seen: set[str] = set()

    if source_root == "feodotracker" and ioc_type == "ip":
        _append_lookup_link(links, seen, "Feodo", f"https://feodotracker.abuse.ch/browse/host/{quote(value)}/")
    elif source_root == "urlhaus":
        _append_lookup_link(links, seen, "URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={quote(value)}")
    elif source_root == "malwarebazaar" and ioc_type == "hash":
        _append_lookup_link(links, seen, "MalwareBazaar", f"https://bazaar.abuse.ch/sample/{quote(value)}/")
    elif source_root == "threatfox" and source_reference:
        _append_lookup_link(links, seen, "ThreatFox", source_reference)

    if ioc_type == "ip":
        _append_lookup_link(links, seen, "VirusTotal", f"https://www.virustotal.com/gui/ip-address/{quote(value)}/detection")
        _append_lookup_link(links, seen, "AbuseIPDB", f"https://www.abuseipdb.com/check/{quote(value)}")
        _append_lookup_link(links, seen, "OTX", f"https://otx.alienvault.com/indicator/ip/{quote(value)}")
        _append_lookup_link(links, seen, "Shodan", f"https://www.shodan.io/host/{quote(value)}")
    elif ioc_type == "domain":
        _append_lookup_link(links, seen, "VirusTotal", f"https://www.virustotal.com/gui/domain/{quote(value)}/detection")
        _append_lookup_link(links, seen, "urlscan", f"https://urlscan.io/search/#domain:{quote(value)}")
        _append_lookup_link(links, seen, "OTX", f"https://otx.alienvault.com/indicator/domain/{quote(value)}")
    elif ioc_type == "url":
        encoded_value = quote(value, safe="")
        _append_lookup_link(links, seen, "VirusTotal", f"https://www.virustotal.com/gui/search/{encoded_value}")
        _append_lookup_link(links, seen, "urlscan", f"https://urlscan.io/search/#{quote(value)}")
        _append_lookup_link(links, seen, "URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={encoded_value}")
        _append_lookup_link(links, seen, "OTX", f"https://otx.alienvault.com/browse/global/pulses?q={encoded_value}")
    elif ioc_type == "hash":
        _append_lookup_link(links, seen, "VirusTotal", f"https://www.virustotal.com/gui/file/{quote(value)}/detection")
        _append_lookup_link(links, seen, "MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search={quote(value)}")
        _append_lookup_link(links, seen, "OTX", f"https://otx.alienvault.com/browse/global/pulses?q={quote(value)}")
    elif ioc_type == "email":
        _append_lookup_link(links, seen, "VirusTotal", f"https://www.virustotal.com/gui/search/{quote(value)}")
        _append_lookup_link(links, seen, "OTX", f"https://otx.alienvault.com/browse/global/pulses?q={quote(value)}")

    _append_lookup_link(links, seen, "Source", source_reference or None)
    return links


def _build_ioc_reference(ioc: dict) -> str | None:
    links = _build_live_lookup_links(ioc)
    return links[0]["url"] if links else None


# ──────────────────────────────────────────────────────
#  IOC Management
# ──────────────────────────────────────────────────────

@threat_intel_bp.route("/api/iocs", methods=["GET"])
def list_iocs():
    """List indicators of compromise with filtering."""
    ioc_type = request.args.get("type")
    severity = request.args.get("severity")
    source = request.args.get("source")
    search = request.args.get("q")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    auto_refresh = request.args.get("auto_refresh", "true").lower() != "false"

    iocs = db.get_iocs(ioc_type=ioc_type, severity=severity, source=source,
                       search=search, limit=limit, offset=offset)

    # Bootstrap IOC data from feeds if empty and caller didn't explicitly disable it
    if auto_refresh and not iocs:
        try:
            from services.threat_feed_service import refresh_all_feeds
            refresh_all_feeds()
            iocs = db.get_iocs(ioc_type=ioc_type, severity=severity, source=source,
                               search=search, limit=limit, offset=offset)
        except Exception as e:
            logger.warning(f"IOC bootstrap refresh failed: {e}")

    stats = db.get_ioc_stats()

    for ioc in iocs:
        ioc["lookup_links"] = _build_live_lookup_links(ioc)
        ioc["reference_url"] = _build_ioc_reference(ioc)

    return success_response({
        "iocs": iocs,
        "stats": stats,
    }, meta={"limit": limit, "offset": offset, "total": stats.get("total", 0)})


@threat_intel_bp.route("/api/iocs", methods=["POST"])
def create_ioc():
    """Add a new indicator of compromise."""
    data = request.get_json(silent=True) or {}
    ioc_type = data.get("ioc_type", "").strip()
    value = data.get("value", "").strip()

    if not ioc_type or ioc_type not in ("ip", "domain", "url", "hash", "email"):
        return error_response("ioc_type must be one of: ip, domain, url, hash, email", 400)
    if not value:
        return error_response("value is required", 400)

    ioc_id = db.add_ioc(
        ioc_type=ioc_type,
        value=value,
        threat_type=data.get("threat_type"),
        severity=data.get("severity", "medium"),
        source=data.get("source", "manual"),
        tags=data.get("tags", []),
        description=data.get("description"),
        mitre_ids=data.get("mitre_ids", []),
    )

    return success_response({"id": ioc_id, "value": value}, message="IOC added", status_code=201)


@threat_intel_bp.route("/api/iocs/<int:ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    """Deactivate an IOC."""
    db.delete_ioc(ioc_id)
    return success_response(message="IOC deactivated")


@threat_intel_bp.route("/api/iocs/check", methods=["POST"])
def check_ioc():
    """Check if a value matches any known IOC."""
    data = request.get_json(silent=True) or {}
    value = data.get("value", "").strip()
    if not value:
        return error_response("value is required", 400)

    match = db.check_ioc(value)
    if match:
        return success_response({"match": True, "ioc": match})
    return success_response({"match": False, "ioc": None})


# ──────────────────────────────────────────────────────
#  Threat Feeds
# ──────────────────────────────────────────────────────

@threat_intel_bp.route("/api/threat-feeds", methods=["GET"])
def list_threat_feeds():
    """List aggregated threat feed entries."""
    feed_name = request.args.get("feed")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(int(request.args.get("offset", 0)), 0)
    auto_refresh = request.args.get("auto_refresh", "true").lower() != "false"

    entries = db.get_threat_feed_entries(feed_name=feed_name, limit=limit, offset=offset)
    total = db.count_threat_feed_entries(feed_name=feed_name)

    # Bootstrap feed cache if empty
    if auto_refresh and not entries:
        try:
            from services.threat_feed_service import refresh_all_feeds
            refresh_all_feeds()
            entries = db.get_threat_feed_entries(feed_name=feed_name, limit=limit, offset=offset)
            total = db.count_threat_feed_entries(feed_name=feed_name)
        except Exception as e:
            logger.warning(f"Threat feed bootstrap refresh failed: {e}")

    for entry in entries:
        entry["lookup_links"] = _build_live_lookup_links(entry)

    return success_response(
        {"entries": entries, "total": total},
        meta={"limit": limit, "offset": offset, "total": total, "has_more": offset + len(entries) < total}
    )


@threat_intel_bp.route("/api/threat-feeds/refresh", methods=["POST"])
def refresh_threat_feeds():
    """Trigger a refresh of external threat feeds."""
    try:
        from services.threat_feed_service import refresh_all_feeds
        results = refresh_all_feeds()
        return success_response(results, message="Threat feeds refreshed")
    except Exception as e:
        logger.error(f"Threat feed refresh error: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/threat-feeds/insights", methods=["GET"])
def get_threat_feed_insights():
    """Return live public source insights and trend metadata."""
    force_refresh = request.args.get("refresh", "false").lower() == "true"
    try:
        from services.threat_feed_service import get_live_source_insights
        data = get_live_source_insights(force_refresh=force_refresh)
        return success_response(data)
    except Exception as e:
        logger.error(f"Threat feed insights error: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/threat-feeds/search", methods=["GET"])
def search_threat_feeds():
    """Search across all threat feeds and active IOCs.

    If no query is provided, return the latest available indicators so the UI
    can show a useful default view instead of an empty state.
    """
    query = request.args.get("q", "").strip()

    results = db.search_threat_feeds(query)
    for item in results:
        item["lookup_links"] = _build_live_lookup_links(item)
        if not item.get("reference"):
            item["reference"] = _build_ioc_reference(item)
    return success_response({"results": results, "total": len(results), "query": query})


# ──────────────────────────────────────────────────────
#  CVE Lookup
# ──────────────────────────────────────────────────────

@threat_intel_bp.route("/api/cve/<cve_id>", methods=["GET"])
def lookup_cve(cve_id):
    """Look up a CVE by ID (NVD API with local cache)."""
    cve_id = cve_id.strip().upper()
    valid, err = validate_cve_id(cve_id)
    if not valid:
        return error_response(err, 400)

    # Check cache first
    cached = db.get_cached_cve(cve_id)
    if cached:
        if not cached.get("cvss_vector") or not cached.get("source"):
            try:
                from services.cve_service import fetch_cve
                refreshed = fetch_cve(cve_id)
                if refreshed:
                    db.cache_cve(cve_id, refreshed)
                    return success_response({"cve": refreshed, "source": "nvd-refresh"})
            except Exception as e:
                logger.warning(f"CVE cache refresh fallback failed for {cve_id}: {e}")
            cached["source"] = cached.get("source") or "NVD API"
        return success_response({"cve": cached, "source": "cache"})

    try:
        from services.cve_service import fetch_cve
        cve_data = fetch_cve(cve_id)
        if cve_data:
            db.cache_cve(cve_id, cve_data)
            return success_response({"cve": cve_data, "source": "nvd"})
        return error_response(f"CVE {cve_id} not found", 404)
    except Exception as e:
        logger.error(f"CVE lookup error: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/cve/search", methods=["GET"])
def search_cves():
    """Search CVEs by keyword."""
    keyword = request.args.get("q", "").strip()
    limit = min(max(int(request.args.get("limit", 100)), 1), 300)
    if not keyword:
        return error_response("Search query 'q' is required", 400)

    try:
        from services.cve_service import search_cves
        results = search_cves(keyword, limit=limit)
        return success_response({"cves": results, "total": len(results), "query": keyword}, meta={"limit": limit, "offset": 0, "total": len(results)})
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/intel/catalog", methods=["GET"])
def get_intel_catalog():
    """Aggregated threat-intel catalog: CISA KEV, OWASP Top10, SANS CWE Top25, MITRE links."""
    limit_kev = min(max(int(request.args.get("limit_kev", 50)), 1), 200)
    try:
        from services.intel_catalog_service import get_intel_catalog
        data = get_intel_catalog(limit_kev=limit_kev)
        return success_response(data, meta={"limit_kev": limit_kev})
    except Exception as e:
        logger.error(f"Intel catalog error: {e}")
        return error_response(str(e), 500)


# ──────────────────────────────────────────────────────
#  MITRE ATT&CK Mapping
# ──────────────────────────────────────────────────────

@threat_intel_bp.route("/api/mitre/techniques", methods=["GET"])
def list_mitre_techniques():
    """List MITRE ATT&CK techniques with optional filtering."""
    tactic = request.args.get("tactic")
    search = request.args.get("q")
    try:
        from services.mitre_service import get_techniques
        techniques = get_techniques(tactic=tactic, search=search)
        return success_response({"techniques": techniques, "total": len(techniques)})
    except Exception as e:
        logger.error(f"MITRE lookup error: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/mitre/technique/<technique_id>", methods=["GET"])
def get_mitre_technique(technique_id):
    """Get details for a specific MITRE ATT&CK technique."""
    try:
        from services.mitre_service import get_technique_detail
        detail = get_technique_detail(technique_id.upper())
        if detail:
            return success_response(detail)
        return error_response(f"Technique {technique_id} not found", 404)
    except Exception as e:
        return error_response(str(e), 500)


@threat_intel_bp.route("/api/mitre/tactics", methods=["GET"])
def list_mitre_tactics():
    """List all MITRE ATT&CK tactics."""
    try:
        from services.mitre_service import get_tactics
        return success_response({"tactics": get_tactics()})
    except Exception as e:
        return error_response(str(e), 500)
