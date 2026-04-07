"""
CyberRegis Database Layer
SQLite persistence for scan history, IOCs, and threat intelligence.
"""
import sqlite3
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from config import get_config

cfg = get_config()

DB_PATH = cfg.DB_PATH


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = _connect()
    cur = conn.cursor()

    cur.executescript("""
    -- Scan history (unified for all scan types)
    CREATE TABLE IF NOT EXISTS scan_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type   TEXT    NOT NULL,          -- domain | ip | url | pcap | port | vuln | headers | email | ssl
        target      TEXT    NOT NULL,
        status      TEXT    NOT NULL DEFAULT 'completed',
        risk_level  TEXT,
        score       REAL,
        result_json TEXT,                       -- full JSON blob
        summary     TEXT,
        created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
        duration_ms INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_history(scan_type);
    CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target);
    CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_history(created_at);

    -- Indicators of Compromise
    CREATE TABLE IF NOT EXISTS iocs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type    TEXT    NOT NULL,           -- ip | domain | url | hash | email
        value       TEXT    NOT NULL UNIQUE,
        threat_type TEXT,                       -- malware | phishing | c2 | spam | apt
        severity    TEXT    NOT NULL DEFAULT 'medium',  -- critical | high | medium | low | info
        source      TEXT,                       -- manual | otx | abuseipdb | virustotal | urlhaus
        tags        TEXT,                       -- JSON array of tags
        description TEXT,
        first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
        last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
        is_active   INTEGER NOT NULL DEFAULT 1,
        mitre_ids   TEXT                        -- JSON array of MITRE ATT&CK technique IDs
    );
    CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
    CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
    CREATE INDEX IF NOT EXISTS idx_ioc_severity ON iocs(severity);

    -- Threat feed entries (cached from external sources)
    CREATE TABLE IF NOT EXISTS threat_feeds (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        feed_name   TEXT    NOT NULL,           -- otx | urlhaus | feodotracker | threatfox
        indicator   TEXT    NOT NULL,
        ioc_type    TEXT    NOT NULL,
        threat_type TEXT,
        confidence  INTEGER,
        description TEXT,
        reference   TEXT,
        fetched_at  TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE(feed_name, indicator)
    );
    CREATE INDEX IF NOT EXISTS idx_feed_name ON threat_feeds(feed_name);
    CREATE INDEX IF NOT EXISTS idx_feed_indicator ON threat_feeds(indicator);

    -- CVE cache
    CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id      TEXT    PRIMARY KEY,
        description TEXT,
        severity    TEXT,
        cvss_score  REAL,
        published   TEXT,
        modified    TEXT,
        references_json TEXT,
        affected_json   TEXT,
        fetched_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    -- Dashboard analytics (pre-aggregated)
    CREATE TABLE IF NOT EXISTS analytics (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        metric_name TEXT    NOT NULL,
        metric_value REAL   NOT NULL,
        dimensions  TEXT,                       -- JSON object of dimensions
        period      TEXT    NOT NULL,           -- hourly | daily | weekly
        period_start TEXT   NOT NULL,
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_analytics_metric ON analytics(metric_name, period);

    -- Alert rules
    CREATE TABLE IF NOT EXISTS alert_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT    NOT NULL,
        rule_type   TEXT    NOT NULL,           -- threshold | match | anomaly
        config_json TEXT    NOT NULL,
        is_active   INTEGER NOT NULL DEFAULT 1,
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    """)

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────
#  Scan History
# ──────────────────────────────────────────────────────

def save_scan(scan_type: str, target: str, result: Dict, risk_level: str = None,
              score: float = None, summary: str = None, duration_ms: int = None) -> int:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_history (scan_type, target, status, risk_level, score, result_json, summary, duration_ms)
        VALUES (?, ?, 'completed', ?, ?, ?, ?, ?)
    """, (scan_type, target, risk_level, score, json.dumps(result), summary, duration_ms))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(scan_type: str = None, target: str = None,
                     limit: int = 50, offset: int = 0) -> List[Dict]:
    conn = _connect()
    query = "SELECT * FROM scan_history WHERE 1=1"
    params = []
    if scan_type:
        query += " AND scan_type = ?"
        params.append(scan_type)
    if target:
        query += " AND target LIKE ?"
        params.append(f"%{target}%")
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = []
    for row in rows:
        r = dict(row)
        if r.get("result_json"):
            try:
                r["result"] = json.loads(r["result_json"])
            except json.JSONDecodeError:
                r["result"] = None
            del r["result_json"]
        results.append(r)
    return results


def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    r = dict(row)
    if r.get("result_json"):
        try:
            r["result"] = json.loads(r["result_json"])
        except json.JSONDecodeError:
            r["result"] = None
        del r["result_json"]
    return r


def get_scan_stats() -> Dict:
    """Aggregate stats for the dashboard."""
    conn = _connect()
    stats = {}

    # Total scans
    stats["total_scans"] = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]

    # Scans by type
    rows = conn.execute(
        "SELECT scan_type, COUNT(*) as cnt FROM scan_history GROUP BY scan_type ORDER BY cnt DESC"
    ).fetchall()
    stats["by_type"] = {r["scan_type"]: r["cnt"] for r in rows}

    # Scans today
    today = datetime.utcnow().strftime("%Y-%m-%d")
    stats["today"] = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE created_at >= ?", (today,)
    ).fetchone()[0]

    # Risk distribution
    rows = conn.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM scan_history WHERE risk_level IS NOT NULL GROUP BY risk_level"
    ).fetchall()
    stats["risk_distribution"] = {r["risk_level"]: r["cnt"] for r in rows}

    # Recent 24h trend (hourly)
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    rows = conn.execute("""
        SELECT strftime('%H', created_at) as hour, COUNT(*) as cnt
        FROM scan_history WHERE created_at >= ?
        GROUP BY hour ORDER BY hour
    """, (since,)).fetchall()
    stats["hourly_trend"] = {r["hour"]: r["cnt"] for r in rows}

    # Top targets
    rows = conn.execute("""
        SELECT target, COUNT(*) as cnt FROM scan_history
        GROUP BY target ORDER BY cnt DESC LIMIT 10
    """).fetchall()
    stats["top_targets"] = [{"target": r["target"], "count": r["cnt"]} for r in rows]

    conn.close()
    return stats


# ──────────────────────────────────────────────────────
#  IOC Management
# ──────────────────────────────────────────────────────

def add_ioc(ioc_type: str, value: str, threat_type: str = None,
            severity: str = "medium", source: str = "manual",
            tags: List[str] = None, description: str = None,
            mitre_ids: List[str] = None) -> int:
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO iocs (ioc_type, value, threat_type, severity, source, tags, description, mitre_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ioc_type, value, threat_type, severity, source,
              json.dumps(tags or []), description, json.dumps(mitre_ids or [])))
        ioc_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        # Update last_seen
        cur.execute("UPDATE iocs SET last_seen = datetime('now') WHERE value = ?", (value,))
        conn.commit()
        ioc_id = cur.execute("SELECT id FROM iocs WHERE value = ?", (value,)).fetchone()["id"]
    conn.close()
    return ioc_id


def get_iocs(ioc_type: str = None, severity: str = None, source: str = None,
             search: str = None, active_only: bool = True,
             limit: int = 100, offset: int = 0) -> List[Dict]:
    conn = _connect()
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []
    if active_only:
        query += " AND is_active = 1"
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source:
        query += " AND source = ?"
        params.append(source)
    if search:
        query += " AND (value LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = []
    for row in rows:
        r = dict(row)
        r["tags"] = json.loads(r.get("tags") or "[]")
        r["mitre_ids"] = json.loads(r.get("mitre_ids") or "[]")
        results.append(r)
    return results


def get_ioc_stats() -> Dict:
    conn = _connect()
    stats = {}
    stats["total"] = conn.execute("SELECT COUNT(*) FROM iocs WHERE is_active = 1").fetchone()[0]
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM iocs WHERE is_active = 1 GROUP BY severity"
    ).fetchall()
    stats["by_severity"] = {r["severity"]: r["cnt"] for r in rows}
    rows = conn.execute(
        "SELECT ioc_type, COUNT(*) as cnt FROM iocs WHERE is_active = 1 GROUP BY ioc_type"
    ).fetchall()
    stats["by_type"] = {r["ioc_type"]: r["cnt"] for r in rows}
    rows = conn.execute(
        "SELECT source, COUNT(*) as cnt FROM iocs WHERE is_active = 1 GROUP BY source"
    ).fetchall()
    stats["by_source"] = {r["source"]: r["cnt"] for r in rows}
    conn.close()
    return stats


def delete_ioc(ioc_id: int) -> bool:
    conn = _connect()
    conn.execute("UPDATE iocs SET is_active = 0 WHERE id = ?", (ioc_id,))
    conn.commit()
    conn.close()
    return True


def check_ioc(value: str) -> Optional[Dict]:
    """Check if a value matches any known IOC."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM iocs WHERE value = ? AND is_active = 1", (value,)
    ).fetchone()
    conn.close()
    if row:
        r = dict(row)
        r["tags"] = json.loads(r.get("tags") or "[]")
        r["mitre_ids"] = json.loads(r.get("mitre_ids") or "[]")
        return r
    return None


# ──────────────────────────────────────────────────────
#  Threat Feeds
# ──────────────────────────────────────────────────────

def save_threat_feed_entries(feed_name: str, entries: List[Dict]):
    conn = _connect()
    cur = conn.cursor()
    for entry in entries:
        try:
            cur.execute("""
                INSERT OR REPLACE INTO threat_feeds
                (feed_name, indicator, ioc_type, threat_type, confidence, description, reference)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (feed_name, entry["indicator"], entry.get("ioc_type", "unknown"),
                  entry.get("threat_type"), entry.get("confidence"),
                  entry.get("description"), entry.get("reference")))
        except Exception:
            continue
    conn.commit()
    conn.close()


def _balance_rows(rows: List[sqlite3.Row], limit: int, offset: int = 0, group_key: str = "feed_name") -> List[Dict]:
    buckets = defaultdict(deque)
    order = []
    for row in rows:
        item = dict(row)
        key = item.get(group_key) or "unknown"
        if key not in buckets:
            order.append(key)
        buckets[key].append(item)

    balanced = []
    while any(buckets.values()):
        progressed = False
        for key in order:
            if buckets[key]:
                balanced.append(buckets[key].popleft())
                progressed = True
        if not progressed:
            break

    return balanced[offset: offset + limit]


def count_threat_feed_entries(feed_name: str = None) -> int:
    conn = _connect()
    if feed_name:
        total = conn.execute(
            "SELECT COUNT(*) FROM threat_feeds WHERE feed_name = ?",
            (feed_name,)
        ).fetchone()[0]
    else:
        total = conn.execute("SELECT COUNT(*) FROM threat_feeds").fetchone()[0]
    conn.close()
    return total


def get_threat_feed_entries(feed_name: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
    conn = _connect()
    if feed_name:
        rows = conn.execute(
            "SELECT * FROM threat_feeds WHERE feed_name = ? ORDER BY fetched_at DESC LIMIT ? OFFSET ?",
            (feed_name, limit, offset)
        ).fetchall()
        results = [dict(r) for r in rows]
    else:
        rows = conn.execute(
            "SELECT * FROM threat_feeds ORDER BY fetched_at DESC LIMIT ?",
            (max((limit + offset) * 6, 300),)
        ).fetchall()
    conn.close()
    if feed_name:
        return results
    return _balance_rows(rows, limit=limit, offset=offset, group_key="feed_name")


def search_threat_feeds(query: str) -> List[Dict]:
    conn = _connect()
    query = (query or "").strip()
    if query:
        rows = conn.execute(
            """
            SELECT id, feed_name, indicator, ioc_type, threat_type, confidence, description, reference, fetched_at
            FROM threat_feeds
            WHERE indicator LIKE ? OR description LIKE ? OR threat_type LIKE ?
            ORDER BY fetched_at DESC
            LIMIT 300
            """,
            (f"%{query}%", f"%{query}%", f"%{query}%")
        ).fetchall()
        ioc_rows = conn.execute(
            """
            SELECT id, source as feed_name, value as indicator, ioc_type, threat_type,
                   CASE severity
                        WHEN 'critical' THEN 95
                        WHEN 'high' THEN 85
                        WHEN 'medium' THEN 60
                        WHEN 'low' THEN 35
                        ELSE 15
                   END as confidence,
                   description, NULL as reference, last_seen as fetched_at
            FROM iocs
            WHERE is_active = 1 AND (value LIKE ? OR description LIKE ? OR threat_type LIKE ?)
            ORDER BY last_seen DESC
            LIMIT 100
            """,
            (f"%{query}%", f"%{query}%", f"%{query}%")
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, feed_name, indicator, ioc_type, threat_type, confidence, description, reference, fetched_at
            FROM threat_feeds
            ORDER BY fetched_at DESC
            LIMIT 400
            """
        ).fetchall()
        ioc_rows = conn.execute(
            """
            SELECT id, source as feed_name, value as indicator, ioc_type, threat_type,
                   CASE severity
                        WHEN 'critical' THEN 95
                        WHEN 'high' THEN 85
                        WHEN 'medium' THEN 60
                        WHEN 'low' THEN 35
                        ELSE 15
                   END as confidence,
                   description, NULL as reference, last_seen as fetched_at
            FROM iocs
            WHERE is_active = 1
            ORDER BY last_seen DESC
            LIMIT 100
            """
        ).fetchall()
    conn.close()
    merged = [dict(r) for r in rows] + [dict(r) for r in ioc_rows]
    merged.sort(key=lambda item: item.get("fetched_at") or "", reverse=True)

    deduped = []
    seen = set()
    for item in merged:
        key = (item.get("feed_name"), item.get("indicator"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return _balance_rows(deduped, limit=100, offset=0, group_key="feed_name")


# ──────────────────────────────────────────────────────
#  CVE Cache
# ──────────────────────────────────────────────────────

def cache_cve(cve_id: str, data: Dict):
    conn = _connect()
    conn.execute("""
        INSERT OR REPLACE INTO cve_cache
        (cve_id, description, severity, cvss_score, published, modified, references_json, affected_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (cve_id, data.get("description"), data.get("severity"),
          data.get("cvss_score"), data.get("published"), data.get("modified"),
          json.dumps(data.get("references", [])), json.dumps(data.get("affected", []))))
    conn.commit()
    conn.close()


def get_cached_cve(cve_id: str) -> Optional[Dict]:
    conn = _connect()
    row = conn.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)).fetchone()
    conn.close()
    if row:
        r = dict(row)
        r["references"] = json.loads(r.get("references_json") or "[]")
        r["affected"] = json.loads(r.get("affected_json") or "[]")
        del r["references_json"]
        del r["affected_json"]
        return r
    return None


# Initialize database on import
init_db()
