"""
Threat Intelligence Catalog Service
Aggregates relevant intel frameworks/sources for dashboard context.
"""
import re
from datetime import datetime
import requests
from typing import Dict, List
from config import get_config

cfg = get_config()

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

OWASP_TOP10_2021 = [
    {"id": "A01", "name": "Broken Access Control"},
    {"id": "A02", "name": "Cryptographic Failures"},
    {"id": "A03", "name": "Injection"},
    {"id": "A04", "name": "Insecure Design"},
    {"id": "A05", "name": "Security Misconfiguration"},
    {"id": "A06", "name": "Vulnerable and Outdated Components"},
    {"id": "A07", "name": "Identification and Authentication Failures"},
    {"id": "A08", "name": "Software and Data Integrity Failures"},
    {"id": "A09", "name": "Security Logging and Monitoring Failures"},
    {"id": "A10", "name": "Server-Side Request Forgery"},
]

HTTP_HEADERS = {"User-Agent": "CyberRegis/2.0 (+https://localhost)"}


def _fetch_text(url: str, timeout: int = 25) -> str:
    resp = requests.get(
        url,
        timeout=timeout,
        headers=HTTP_HEADERS,
        verify=cfg.SSL_VERIFY,
    )
    resp.raise_for_status()
    return resp.text


def _dedupe_items(items: List[Dict], cap: int = 10) -> List[Dict]:
    out = []
    seen = set()
    for item in items:
        key = (item.get("id"), item.get("name"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cap:
            break
    return out


def _extract_version_from_text(text: str, fallback: str = "") -> str:
    years = [int(y) for y in re.findall(r"\b(20\d{2})\b", text)]
    if not years:
        return fallback
    return str(max(years))


def _extract_tokenized_items(html_text: str, token_prefix: str) -> tuple[str, List[Dict]]:
    pattern = rf"({token_prefix}\d{{1,2}}:(\d{{4}}))\s*(?:[\-–:]\s*)?([^<\n]{{3,140}})"
    matches = re.findall(pattern, html_text, re.IGNORECASE)
    if not matches:
        return "", []

    year_counts: Dict[str, int] = {}
    for _, year, _ in matches:
        year_counts[year] = year_counts.get(year, 0) + 1
    version = sorted(year_counts.items(), key=lambda entry: (entry[1], entry[0]), reverse=True)[0][0]

    items = []
    for token, year, name in matches:
        if year != version:
            continue
        clean_name = re.sub(r"\s+", " ", name).strip(" -–:\t\r\n")
        if ">" in clean_name:
            clean_name = clean_name.split(">")[-1].strip()
        if clean_name.upper().startswith(token.upper()):
            clean_name = clean_name[len(token):].strip(" -–:\t")
        items.append({"id": token.upper(), "name": clean_name})
    return version, _dedupe_items(items, cap=10)


def _fetch_owasp_web_top10() -> Dict:
    project_page = "https://owasp.org/www-project-top-ten/"
    project_text = _fetch_text(project_page)
    year_matches = [int(y) for y in re.findall(r"https://owasp\.org/Top10/(20\d{2})/", project_text)]
    latest_year = str(max(year_matches)) if year_matches else "2025"
    source = f"https://owasp.org/Top10/{latest_year}/"
    text = _fetch_text(source)
    version, items = _extract_tokenized_items(text, "A")
    return {
        "key": "web_top10",
        "name": "OWASP Top 10 Web",
        "status": "success" if items else "empty",
        "version": version or latest_year,
        "source": source,
        "items": [{**item, "reference": source} for item in items],
        "total": len(items),
    }


def _fetch_owasp_api_top10() -> Dict:
    project_page = "https://owasp.org/API-Security/"
    project_text = _fetch_text(project_page)
    year_matches = [int(y) for y in re.findall(r"/API-Security/editions/(20\d{2})/", project_text)]
    latest_year = str(max(year_matches)) if year_matches else "2023"
    source = f"https://owasp.org/API-Security/editions/{latest_year}/en/0x11-t10/"
    text = _fetch_text(source)
    version, items = _extract_tokenized_items(text, "API")
    return {
        "key": "api_top10",
        "name": "OWASP API Security Top 10",
        "status": "success" if items else "empty",
        "version": version or latest_year,
        "source": source,
        "items": [{**item, "reference": source} for item in items],
        "total": len(items),
    }


def _fetch_owasp_llm_top10() -> Dict:
    source = "https://genai.owasp.org/llm-top-10/"
    text = _fetch_text(source, timeout=35)
    version, items = _extract_tokenized_items(text, "LLM")
    return {
        "key": "llm_top10",
        "name": "OWASP LLM Top 10",
        "status": "success" if items else "empty",
        "version": version or "unknown",
        "source": source,
        "items": [{**item, "reference": source} for item in items],
        "total": len(items),
    }


def _fetch_owasp_mobile_top10() -> Dict:
    source = "https://raw.githubusercontent.com/OWASP/www-project-mobile-top-10/master/index.md"
    text = _fetch_text(source)
    release_year = _extract_version_from_text(text, fallback="unknown")
    matches = re.findall(r"(\d{4}-risks)/(m\d{1,2})-([a-z0-9\-]+)\.md", text, re.IGNORECASE)
    items = []
    for folder, code, slug in matches:
        item_id = f"{code.upper()}:{folder.split('-', 1)[0]}"
        name = slug.replace("-", " ").title()
        ref = f"https://github.com/OWASP/www-project-mobile-top-10/blob/master/{folder}/{code.lower()}-{slug}.md"
        items.append({"id": item_id, "name": name, "reference": ref})
    return {
        "key": "mobile_top10",
        "name": "OWASP Mobile Top 10",
        "status": "success" if items else "empty",
        "version": release_year,
        "source": "https://owasp.org/www-project-mobile-top-10/",
        "items": _dedupe_items(items, cap=10),
        "total": len(_dedupe_items(items, cap=50)),
    }


def _fetch_owasp_ml_top10() -> Dict:
    source = "https://raw.githubusercontent.com/OWASP/www-project-machine-learning-security-top-10/master/index.md"
    text = _fetch_text(source)
    matches = re.findall(r"/docs/(ML\d{2})_(\d{4})-([A-Za-z0-9_\-]+)\.md", text)
    if not matches:
        return {
            "key": "ml_top10",
            "name": "OWASP Machine Learning Security Top 10",
            "status": "empty",
            "version": _extract_version_from_text(text, fallback="unknown"),
            "source": "https://owasp.org/www-project-machine-learning-security-top-10/",
            "items": [],
            "total": 0,
        }

    latest_year = max(int(y) for _, y, _ in matches)
    items = []
    for code, year, slug in matches:
        if int(year) != latest_year:
            continue
        name = slug.replace("_", " ").replace("-", " ").title()
        ref = f"https://github.com/OWASP/www-project-machine-learning-security-top-10/blob/master/docs/{code}_{year}-{slug}.md"
        items.append({"id": f"{code}:{year}", "name": name, "reference": ref})

    return {
        "key": "ml_top10",
        "name": "OWASP Machine Learning Security Top 10",
        "status": "success" if items else "empty",
        "version": str(latest_year),
        "source": "https://owasp.org/www-project-machine-learning-security-top-10/",
        "items": _dedupe_items(items, cap=10),
        "total": len(_dedupe_items(items, cap=50)),
    }


def _fetch_owasp_smart_contract_top10() -> Dict:
    source = "https://raw.githubusercontent.com/OWASP/www-project-smart-contract-top-10/main/index.md"
    text = _fetch_text(source)
    matches = re.findall(r"(\d{4})/en/src/(SC\d{2})-([a-z0-9\-]+)\.md", text, re.IGNORECASE)
    if not matches:
        return {
            "key": "smart_contract_top10",
            "name": "OWASP Smart Contract Top 10",
            "status": "empty",
            "version": _extract_version_from_text(text, fallback="unknown"),
            "source": "https://scs.owasp.org/sctop10/",
            "items": [],
            "total": 0,
        }

    latest_year = max(int(y) for y, _, _ in matches)
    items = []
    for year, code, slug in matches:
        if int(year) != latest_year:
            continue
        name = slug.replace("-", " ").title()
        ref = f"https://github.com/OWASP/www-project-smart-contract-top-10/blob/main/{year}/en/src/{code}-{slug}.md"
        items.append({"id": f"{code}:{year}", "name": name, "reference": ref})

    return {
        "key": "smart_contract_top10",
        "name": "OWASP Smart Contract Top 10",
        "status": "success" if items else "empty",
        "version": str(latest_year),
        "source": "https://scs.owasp.org/sctop10/",
        "items": _dedupe_items(items, cap=10),
        "total": len(_dedupe_items(items, cap=50)),
    }


def fetch_owasp_catalog() -> Dict:
    fetchers = [
        _fetch_owasp_web_top10,
        _fetch_owasp_api_top10,
        _fetch_owasp_llm_top10,
        _fetch_owasp_mobile_top10,
        _fetch_owasp_ml_top10,
        _fetch_owasp_smart_contract_top10,
    ]

    projects = []
    errors = []
    for fetcher in fetchers:
        try:
            projects.append(fetcher())
        except Exception as e:
            name = fetcher.__name__.replace("_fetch_", "")
            errors.append(f"{name}: {e}")

    ok_count = len([p for p in projects if p.get("status") == "success"])
    status = "success" if ok_count == len(fetchers) else ("partial" if ok_count > 0 else "error")
    return {
        "status": status,
        "fetched_at": datetime.utcnow().isoformat() + "Z",
        "total_projects": len(projects),
        "projects": projects,
        "errors": errors,
    }

SANS_CWE_TOP25 = [
    {"cwe": "CWE-787", "name": "Out-of-bounds Write"},
    {"cwe": "CWE-79", "name": "Cross-site Scripting"},
    {"cwe": "CWE-89", "name": "SQL Injection"},
    {"cwe": "CWE-20", "name": "Improper Input Validation"},
    {"cwe": "CWE-125", "name": "Out-of-bounds Read"},
    {"cwe": "CWE-78", "name": "OS Command Injection"},
    {"cwe": "CWE-416", "name": "Use After Free"},
    {"cwe": "CWE-22", "name": "Path Traversal"},
    {"cwe": "CWE-352", "name": "Cross-Site Request Forgery"},
    {"cwe": "CWE-434", "name": "Unrestricted File Upload"},
    {"cwe": "CWE-862", "name": "Missing Authorization"},
    {"cwe": "CWE-476", "name": "NULL Pointer Dereference"},
    {"cwe": "CWE-287", "name": "Improper Authentication"},
    {"cwe": "CWE-190", "name": "Integer Overflow"},
    {"cwe": "CWE-502", "name": "Deserialization of Untrusted Data"},
    {"cwe": "CWE-77", "name": "Command Injection"},
    {"cwe": "CWE-119", "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
    {"cwe": "CWE-798", "name": "Use of Hard-coded Credentials"},
    {"cwe": "CWE-918", "name": "Server-Side Request Forgery"},
    {"cwe": "CWE-400", "name": "Uncontrolled Resource Consumption"},
    {"cwe": "CWE-306", "name": "Missing Authentication for Critical Function"},
    {"cwe": "CWE-269", "name": "Improper Privilege Management"},
    {"cwe": "CWE-862", "name": "Missing Authorization"},
    {"cwe": "CWE-732", "name": "Incorrect Permission Assignment"},
    {"cwe": "CWE-94", "name": "Code Injection"},
]


def fetch_cisa_kev(limit: int = 50) -> Dict:
    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=25,
            headers={"User-Agent": "CyberRegis/2.0 (+https://localhost)"},
            verify=cfg.SSL_VERIFY,
        )
        if resp.status_code != 200:
            return {"status": "error", "error": f"HTTP {resp.status_code}", "vulnerabilities": [], "total": 0}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        sorted_vulns = sorted(vulns, key=lambda v: v.get("dateAdded") or "", reverse=True)
        simplified = [
            {
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
                "ransomware_status": (
                    "known"
                    if (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
                    else "not_disclosed"
                ),
                "notes": v.get("shortDescription"),
            }
            for v in sorted_vulns[:limit]
        ]
        return {
            "status": "success",
            "total": len(vulns),
            "catalog_version": data.get("catalogVersion"),
            "date_released": data.get("dateReleased"),
            "count_returned": len(simplified),
            "vulnerabilities": simplified,
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "vulnerabilities": [], "total": 0}


def get_intel_catalog(limit_kev: int = 50) -> Dict:
    kev = fetch_cisa_kev(limit=limit_kev)
    owasp_catalog = fetch_owasp_catalog()

    web_project = next((p for p in owasp_catalog.get("projects", []) if p.get("key") == "web_top10"), None)
    top10_compat_items = (web_project or {}).get("items") or OWASP_TOP10_2021

    mitre_summary = {
        "status": "available",
        "endpoints": {
            "tactics": "/api/mitre/tactics",
            "techniques": "/api/mitre/techniques",
        }
    }

    return {
        "cisa_kev": kev,
        "owasp_top10_2021": {
            "status": "available" if top10_compat_items else "empty",
            "total": len(top10_compat_items),
            "items": top10_compat_items,
        },
        "owasp_top10_catalog": owasp_catalog,
        "sans_cwe_top25": {
            "status": "available",
            "total": len(SANS_CWE_TOP25),
            "items": SANS_CWE_TOP25,
        },
        "mitre_attack": mitre_summary,
    }
