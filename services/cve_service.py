"""
CVE Lookup Service
Queries NIST NVD API for vulnerability information.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
import requests
from typing import Optional, List, Dict
from config import get_config

logger = logging.getLogger(__name__)
cfg = get_config()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_HEADERS = {
    "User-Agent": "CyberRegis/2.0 (+https://localhost)",
    "Accept": "application/json",
}
if NVD_API_KEY:
    NVD_HEADERS["apiKey"] = NVD_API_KEY


def fetch_cve(cve_id: str) -> Optional[Dict]:
    """Fetch a single CVE from NVD."""
    try:
        resp = requests.get(
            f"{NVD_BASE}?cveId={cve_id}",
            timeout=20,
            headers=NVD_HEADERS,
            verify=cfg.SSL_VERIFY,
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return _parse_cve(vulns[0].get("cve", {}))
        elif resp.status_code == 404:
            return None
        elif resp.status_code == 403:
            logger.warning("NVD rate limit hit — consider using an API key")
            return None
        return None
    except Exception as e:
        logger.error(f"NVD fetch error for {cve_id}: {e}")
        return None


def search_cves(keyword: str, limit: int = 100) -> List[Dict]:
    """Search CVEs by keyword, prioritizing recent high-severity CVEs."""
    try:
        lowered = keyword.lower().strip()
        severity_aliases = {"critical", "high severity"}
        latest_aliases = {"recent", "latest"}

        if lowered in severity_aliases or lowered in latest_aliases:
            published_after = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
            published_before = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
            results = []
            seen_ids = set()

            severities = ("CRITICAL", "HIGH") if lowered in severity_aliases else (None,)
            for severity in severities:
                params = {
                    "pubStartDate": published_after,
                    "pubEndDate": published_before,
                    "resultsPerPage": min(limit * 5, 200),
                }
                if severity:
                    params["cvssV3Severity"] = severity

                resp = requests.get(
                    NVD_BASE,
                    params=params,
                    timeout=25,
                    headers=NVD_HEADERS,
                    verify=cfg.SSL_VERIFY,
                )
                if resp.status_code != 200:
                    label = (severity or "latest").lower()
                    logger.warning(f"NVD recent/{label} search failed: HTTP {resp.status_code}")
                    continue

                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    parsed = _parse_cve(v.get("cve", {}))
                    cve_id = (parsed or {}).get("cve_id")
                    if not (parsed and cve_id and cve_id not in seen_ids):
                        continue
                    if lowered in severity_aliases and (parsed.get("cvss_score") or 0) < 7.0:
                        continue
                    if lowered in latest_aliases and not parsed.get("published"):
                        continue
                    if parsed:
                        seen_ids.add(cve_id)
                        results.append(parsed)

            results.sort(
                key=lambda item: (
                    item.get("published") or "",
                    float(item.get("cvss_score") or 0),
                ),
                reverse=True,
            )
            if lowered in latest_aliases:
                current_year = str(datetime.now(timezone.utc).year)

                # Pull explicit current-year CVE IDs to satisfy "latest batch" visibility.
                try:
                    year_resp = requests.get(
                        NVD_BASE,
                        params={"keywordSearch": f"CVE-{current_year}", "resultsPerPage": min(limit * 5, 200)},
                        timeout=25,
                        headers=NVD_HEADERS,
                        verify=cfg.SSL_VERIFY,
                    )
                    if year_resp.status_code == 200:
                        year_data = year_resp.json()
                        for vuln in year_data.get("vulnerabilities", []):
                            parsed = _parse_cve(vuln.get("cve", {}))
                            cve_id = (parsed or {}).get("cve_id")
                            if parsed and cve_id and cve_id not in seen_ids:
                                seen_ids.add(cve_id)
                                results.append(parsed)
                except Exception:
                    pass

                results.sort(
                    key=lambda item: (
                        (item.get("cve_id") or "").startswith(f"CVE-{current_year}-"),
                        item.get("published") or "",
                        float(item.get("cvss_score") or 0),
                    ),
                    reverse=True,
                )
            return results[:limit]

        resp = requests.get(
            NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": min(limit, 200)},
            timeout=25,
            headers=NVD_HEADERS,
            verify=cfg.SSL_VERIFY,
        )
        if resp.status_code != 200:
            logger.warning(f"NVD search failed: HTTP {resp.status_code}")
            return []

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        results = []
        for v in vulns:
            parsed = _parse_cve(v.get("cve", {}))
            if parsed:
                results.append(parsed)
        results.sort(
            key=lambda item: (
                item.get("published") or "",
                float(item.get("cvss_score") or 0),
            ),
            reverse=True,
        )
        return results
    except Exception as e:
        logger.error(f"NVD search error: {e}")
        return []


def _parse_cve(cve: dict) -> Optional[Dict]:
    """Parse a CVE entry from NVD response."""
    if not cve:
        return None

    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS metrics
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    severity = "UNKNOWN"

    # Try CVSSv3.1 first, then v3.0, then v2.0
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            primary = metric_list[0]
            cvss_data = primary.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity") or primary.get("baseSeverity", "UNKNOWN")
            break

    # References
    refs = cve.get("references", [])
    references = [{"url": r.get("url", ""), "source": r.get("source", "")} for r in refs[:10]]

    # Affected configurations
    configurations = cve.get("configurations", [])
    affected = []
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    affected.append({
                        "criteria": criteria,
                        "vulnerable": match.get("vulnerable", True),
                        "version_start": match.get("versionStartIncluding"),
                        "version_end": match.get("versionEndExcluding"),
                    })

    # Weaknesses (CWE)
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value", ""))

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "source": "NVD API",
        "references": references,
        "affected": affected[:20],
        "weaknesses": weaknesses,
    }
