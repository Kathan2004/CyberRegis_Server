"""
Threat Feed Aggregation Service
Pulls IOCs from free threat intelligence feeds:
  - abuse.ch URLhaus (malicious URLs)
  - abuse.ch Feodo Tracker (botnet C2 servers)
  - abuse.ch ThreatFox (IOCs from malware)
  - AlienVault OTX (Open Threat Exchange)
"""
import logging
import re
import requests
from datetime import datetime
from html import unescape
from urllib.parse import urlparse
from typing import List, Dict
import database as db
from config import get_config

logger = logging.getLogger(__name__)
cfg = get_config()

DEFAULT_HEADERS = {
    "User-Agent": "CyberRegis/2.0 (+https://localhost)",
    "Accept": "application/json,text/plain,*/*",
}

_INSIGHTS_CACHE: Dict[str, object] = {
    "timestamp": 0.0,
    "data": None,
}


def _confidence_to_severity(confidence: int) -> str:
    if confidence >= 90:
        return "critical"
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    if confidence >= 25:
        return "low"
    return "info"


def _ingest_entries_as_iocs(feed_name: str, entries: List[Dict]) -> int:
    """Upsert feed entries into IOC table for cross-feature visibility."""
    ingested = 0
    for entry in entries:
        indicator = (entry.get("indicator") or "").strip()
        ioc_type = (entry.get("ioc_type") or "unknown").strip().lower()
        if not indicator or ioc_type not in ("ip", "domain", "url", "hash", "email"):
            continue

        confidence = int(entry.get("confidence") or 0)
        db.add_ioc(
            ioc_type=ioc_type,
            value=indicator,
            threat_type=entry.get("threat_type"),
            severity=_confidence_to_severity(confidence),
            source=feed_name,
            tags=[feed_name, "open-source-feed"],
            description=entry.get("description"),
            mitre_ids=[],
        )
        ingested += 1

        # Derive domain IOC from URL IOC for richer indicator coverage.
        if ioc_type == "url":
            try:
                host = (urlparse(indicator).hostname or "").strip().lower()
                if host:
                    db.add_ioc(
                        ioc_type="domain",
                        value=host,
                        threat_type=entry.get("threat_type") or "phishing",
                        severity=_confidence_to_severity(confidence),
                        source=f"{feed_name}:derived",
                        tags=[feed_name, "derived-from-url", "open-source-feed"],
                        description=f"Derived domain from URL indicator: {indicator[:160]}",
                        mitre_ids=[],
                    )
                    ingested += 1
            except Exception:
                pass
    return ingested


def refresh_all_feeds() -> dict:
    """Refresh all configured threat feeds. Returns summary of results."""
    results = {}

    feeds = [
        ("urlhaus", _fetch_urlhaus),
        ("feodotracker", _fetch_feodotracker),
        ("threatfox", _fetch_threatfox),
        ("openphish", _fetch_openphish),
        ("emergingthreats", _fetch_emergingthreats_compromised),
        ("ipsum", _fetch_ipsum),
        ("cinsscore", _fetch_cinsscore),
        ("neo23x0_hashes", _fetch_neo23x0_hashes),
        ("malwarebazaar", _fetch_malwarebazaar),
    ]

    # Add OTX if API key is configured
    if cfg.OTX_API_KEY:
        feeds.append(("otx", _fetch_otx))

    for name, fetcher in feeds:
        try:
            entries = fetcher()
            db.save_threat_feed_entries(name, entries)
            ioc_ingested = _ingest_entries_as_iocs(name, entries)
            status = "success" if entries else "empty"
            results[name] = {
                "status": status,
                "count": len(entries),
                "ioc_ingested": ioc_ingested,
            }
            logger.info(f"Refreshed {name}: {len(entries)} entries, {ioc_ingested} IOCs ingested")
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)}
            logger.error(f"Failed to refresh {name}: {e}")

    return results


def _fetch_urlhaus() -> List[Dict]:
    """Fetch recent malicious URLs from abuse.ch URLhaus."""
    resp = requests.get(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/",
            data={"query": "get_recent", "limit": 100},
            timeout=20,
            headers=DEFAULT_HEADERS,
            verify=cfg.SSL_VERIFY,
        )
    if resp.status_code != 200:
        raise RuntimeError(f"URLhaus HTTP {resp.status_code}")

    data = resp.json()
    urls = data.get("urls", [])
    entries = []
    for u in urls[:100]:
        entries.append({
            "indicator": u.get("url", ""),
            "ioc_type": "url",
            "threat_type": u.get("threat", "malware"),
            "confidence": 80,
            "description": f"URLhaus: {u.get('url_status', 'unknown')} - {u.get('threat', '')}",
            "reference": u.get("urlhaus_reference", ""),
        })
    return entries


def _fetch_openphish() -> List[Dict]:
    """Fetch recent phishing URLs from OpenPhish."""
    resp = requests.get(
        "https://openphish.com/feed.txt",
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"OpenPhish HTTP {resp.status_code}")

    entries = []
    for raw_url in resp.text.splitlines()[:100]:
        url = raw_url.strip()
        if not url:
            continue
        domain = urlparse(url).netloc
        entries.append({
            "indicator": url,
            "ioc_type": "url",
            "threat_type": "phishing",
            "confidence": 85,
            "description": f"OpenPhish URL - host {domain or 'unknown'}",
            "reference": "https://openphish.com/",
        })
    return entries


def _fetch_ipsum() -> List[Dict]:
    """Fetch frequently updated malicious IPs from the IPsum community feed."""
    resp = requests.get(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        timeout=25,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"IPsum HTTP {resp.status_code}")

    entries = []
    for line in resp.text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parts = value.split()
        if len(parts) < 2:
            continue
        ip_address = parts[0]
        try:
            blacklist_count = int(parts[1])
        except ValueError:
            continue
        if blacklist_count < 3:
            continue
        entries.append({
            "indicator": ip_address,
            "ioc_type": "ip",
            "threat_type": "suspicious-host",
            "confidence": min(95, 55 + blacklist_count * 3),
            "description": f"IPsum community feed — listed on {blacklist_count} blocklists",
            "reference": "https://github.com/stamparm/ipsum",
        })
        if len(entries) >= 100:
            break
    return entries


def _fetch_cinsscore() -> List[Dict]:
    """Fetch CINS Army bad IP feed."""
    resp = requests.get(
        "https://cinsscore.com/list/ci-badguys.txt",
        timeout=25,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"CINSscore HTTP {resp.status_code}")

    entries = []
    for line in resp.text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        entries.append({
            "indicator": value,
            "ioc_type": "ip",
            "threat_type": "malicious-host",
            "confidence": 82,
            "description": "CINSscore / CINS Army bad IP feed",
            "reference": "https://cinsscore.com/list/ci-badguys.txt",
        })
        if len(entries) >= 100:
            break
    return entries


def _fetch_emergingthreats_compromised() -> List[Dict]:
    """Fetch compromised IP indicators from Emerging Threats open feed."""
    resp = requests.get(
        "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"EmergingThreats HTTP {resp.status_code}")

    entries = []
    for line in resp.text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        entries.append({
            "indicator": value,
            "ioc_type": "ip",
            "threat_type": "compromised-host",
            "confidence": 80,
            "description": "Emerging Threats compromised IP feed",
            "reference": "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        })
        if len(entries) >= 100:
            break
    return entries


def _fetch_feodotracker() -> List[Dict]:
    """Fetch botnet C2 server IPs from abuse.ch Feodo Tracker."""
    resp = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"FeodoTracker HTTP {resp.status_code}")

    data = resp.json()
    entries = []
    for item in data[:100]:
        entries.append({
            "indicator": item.get("ip_address", ""),
            "ioc_type": "ip",
            "threat_type": "c2",
            "confidence": 90,
            "description": f"Feodo: {item.get('malware', 'unknown')} C2 - port {item.get('dst_port', 'N/A')}",
            "reference": f"https://feodotracker.abuse.ch/browse/host/{item.get('ip_address', '')}/",
        })
    return entries


def _fetch_threatfox() -> List[Dict]:
    """Fetch recent IOCs from abuse.ch ThreatFox."""
    resp = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": 3},
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"ThreatFox HTTP {resp.status_code}")
    data = resp.json()
    iocs = data.get("data", [])
    if not isinstance(iocs, list):
        message = data.get("message") or "unexpected response"
        raise RuntimeError(f"ThreatFox invalid payload: {message}")

    entries = []
    for item in iocs[:100]:
        ioc_value = item.get("ioc", "")
        ioc_type_raw = item.get("ioc_type", "")

        # Map ThreatFox types to our types
        if "ip:" in ioc_type_raw.lower() or ":" in ioc_value:
            ioc_type = "ip"
        elif "url" in ioc_type_raw.lower():
            ioc_type = "url"
        elif "domain" in ioc_type_raw.lower():
            ioc_type = "domain"
        elif "hash" in ioc_type_raw.lower() or "md5" in ioc_type_raw.lower() or "sha" in ioc_type_raw.lower():
            ioc_type = "hash"
        else:
            ioc_type = "unknown"

        entries.append({
            "indicator": ioc_value,
            "ioc_type": ioc_type,
            "threat_type": item.get("threat_type", "malware"),
            "confidence": item.get("confidence_level", 75),
            "description": f"ThreatFox: {item.get('malware', 'unknown')} - {item.get('tags', [])}",
            "reference": item.get("reference", ""),
        })
    return entries


def _fetch_neo23x0_hashes() -> List[Dict]:
    """Fetch open hash IOCs from Neo23x0 signature-base."""
    resp = requests.get(
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt",
        timeout=20,
        headers=DEFAULT_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"neo23x0_hashes HTTP {resp.status_code}")

    entries = []
    for line in resp.text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        hash_value = value.split(";", 1)[0].strip().lower()
        if len(hash_value) not in (32, 40, 64):
            continue
        entries.append({
            "indicator": hash_value,
            "ioc_type": "hash",
            "threat_type": "malware",
            "confidence": 70,
            "description": "Open hash IOC from Neo23x0 signature-base",
            "reference": "https://github.com/Neo23x0/signature-base",
        })
        if len(entries) >= 100:
            break
    return entries


def _fetch_malwarebazaar() -> List[Dict]:
    """Fetch recent malware hashes from MalwareBazaar."""
    headers = dict(DEFAULT_HEADERS)
    if cfg.MALWAREBAZAAR_API_KEY:
        headers["Auth-Key"] = cfg.MALWAREBAZAAR_API_KEY

    resp = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_recent", "selector": "time"},
        timeout=20,
        headers=headers,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code == 401:
        raise RuntimeError("MalwareBazaar requires MALWAREBAZAAR_API_KEY")
    if resp.status_code != 200:
        raise RuntimeError(f"MalwareBazaar HTTP {resp.status_code}")

    data = resp.json()
    samples = data.get("data", [])
    if not isinstance(samples, list):
        message = data.get("query_status") or "unexpected response"
        raise RuntimeError(f"MalwareBazaar invalid payload: {message}")

    entries = []
    for sample in samples[:100]:
        sha256 = (sample.get("sha256_hash") or "").strip()
        if not sha256:
            continue
        entries.append({
            "indicator": sha256,
            "ioc_type": "hash",
            "threat_type": "malware",
            "confidence": 90,
            "description": f"MalwareBazaar: {sample.get('signature') or sample.get('file_type') or 'malware sample'}",
            "reference": f"https://bazaar.abuse.ch/sample/{sha256}/",
        })
    return entries


def _fetch_otx() -> List[Dict]:
    """Fetch recent pulses from AlienVault OTX."""
    resp = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since=",
        headers={**DEFAULT_HEADERS, "X-OTX-API-KEY": cfg.OTX_API_KEY},
        timeout=20,
        verify=cfg.SSL_VERIFY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"OTX HTTP {resp.status_code}")
    data = resp.json()
    pulses = data.get("results", [])

    entries = []
    for pulse in pulses:
        indicators = pulse.get("indicators", [])
        for ind in indicators[:10]:
            ioc_type_map = {
                "IPv4": "ip", "IPv6": "ip",
                "domain": "domain", "hostname": "domain",
                "URL": "url",
                "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
                "email": "email",
            }
            entries.append({
                "indicator": ind.get("indicator", ""),
                "ioc_type": ioc_type_map.get(ind.get("type", ""), "unknown"),
                "threat_type": "apt",
                "confidence": 70,
                "description": f"OTX: {pulse.get('name', 'Unknown pulse')}",
                "reference": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            })
    return entries


def _extract_openphish_table(html_text: str, heading: str) -> List[Dict[str, str]]:
    pattern = rf"<h2[^>]*>\s*{re.escape(heading)}\s*</h2>\s*<table[^>]*>\s*<tbody>(.*?)</tbody>"
    match = re.search(pattern, html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return []

    rows = []
    for label, percentage in re.findall(
        r"<tr>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*</tr>",
        match.group(1),
        re.IGNORECASE | re.DOTALL,
    ):
        clean_label = re.sub(r"<[^>]+>", "", label)
        clean_percentage = re.sub(r"<[^>]+>", "", percentage)
        rows.append({
            "label": unescape(clean_label).strip(),
            "percentage": unescape(clean_percentage).strip(),
        })
    return rows[:10]


def _extract_openphish_metrics(html_text: str) -> Dict[str, str]:
    flattened = re.sub(r"<[^>]+>", " ", html_text)
    flattened = re.sub(r"\s+", " ", flattened)
    match = re.search(
        r"7-Day Phishing Trends\s+([\d,]+)\s+URLs Processed\s+([\d,]+)\s+New Phishing URLs\s+([\d,]+)\s+Brands Targeted",
        flattened,
        re.IGNORECASE,
    )
    if not match:
        return {}
    return {
        "urls_processed": match.group(1),
        "new_phishing_urls": match.group(2),
        "brands_targeted": match.group(3),
    }


def get_live_source_insights(force_refresh: bool = False, max_age_seconds: int = 300) -> Dict:
    """Return continuously refreshed public source insights for the dashboard."""
    cache_data = _INSIGHTS_CACHE.get("data")
    cache_timestamp = float(_INSIGHTS_CACHE.get("timestamp") or 0.0)
    if not force_refresh and cache_data and (datetime.utcnow().timestamp() - cache_timestamp) < max_age_seconds:
        return cache_data  # type: ignore[return-value]

    insights = {
        "fetched_at": datetime.utcnow().isoformat() + "Z",
        "openphish": {
            "status": "error",
            "homepage": "https://openphish.com/",
            "community_feed": "https://openphish.com/feed.txt",
            "caveat": "OpenPhish Community exposes URLs only. Brand, sector, ASN, IP, and SSL metadata are public as rolling homepage statistics but not per-IOC fields in the free feed.",
            "metrics": {},
            "top_brands": [],
            "top_sectors": [],
            "top_asns": [],
        },
    }

    try:
        resp = requests.get(
            "https://openphish.com/",
            timeout=20,
            headers=DEFAULT_HEADERS,
            verify=cfg.SSL_VERIFY,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OpenPhish HTTP {resp.status_code}")

        insights["openphish"] = {
            "status": "success",
            "homepage": "https://openphish.com/",
            "community_feed": "https://openphish.com/feed.txt",
            "caveat": "OpenPhish Community exposes URLs only. Brand, sector, ASN, IP, and SSL metadata are public as rolling homepage statistics but not per-IOC fields in the free feed.",
            "metrics": _extract_openphish_metrics(resp.text),
            "top_brands": _extract_openphish_table(resp.text, "Top 10 Targeted Brands"),
            "top_sectors": _extract_openphish_table(resp.text, "Top 10 Sectors"),
            "top_asns": _extract_openphish_table(resp.text, "Top 10 ASNs"),
        }
    except Exception as e:
        insights["openphish"]["error"] = str(e)

    _INSIGHTS_CACHE["timestamp"] = datetime.utcnow().timestamp()
    _INSIGHTS_CACHE["data"] = insights
    return insights
