#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke tests for recent feature fixes.
Tests domain scoring, DKIM detection, CVE search, threat feeds, and IOC ingestion.
"""
import requests
import json
import os
os.environ['PYTHONIOENCODING'] = 'utf-8'

API = "http://localhost:5000"

def test_domain_risk():
    print("\n=== TEST: Domain Risk Score for example.com ===")
    r = requests.post(f"{API}/api/analyze-domain", json={"domain": "example.com"}, verify=False)
    if r.status_code == 200:
        data = r.json()
        risk = data.get("data", {}).get("risk_score", {})
        score = risk.get("score", "?")
        level = risk.get("level", "?")
        factors = risk.get("factors", [])[:2]
        print("[PASS] Score={}/100, Level={}".format(score, level))
        print("  Top factors: {}".format(factors))
        return True
    else:
        print("[FAIL] HTTP {}: {}".format(r.status_code, r.text[:100]))
        return False

def test_dkim():
    print("\n=== TEST: Email Security DKIM Detection ===")
    r = requests.post(f"{API}/api/email-security", json={"domain": "google.com"}, verify=False)
    if r.status_code == 200:
        data = r.json()
        es = data.get("data", {}).get("email_security", {})
        dkim = es.get("dkim", {})
        present = dkim.get("present", False)
        status = dkim.get("status", "unknown")
        score = dkim.get("score", 0)
        print("[PASS] google.com DKIM: present={}, status={}, score={}".format(present, status, score))
        return True
    else:
        print("[FAIL] HTTP {}: {}".format(r.status_code, r.text[:100]))
        return False

def test_cve_search():
    print("\n=== TEST: CVE Search (log4j) ===")
    r = requests.get(f"{API}/api/cve/search?q=log4j", verify=False)
    if r.status_code == 200:
        data = r.json()
        cves = data.get("data", {}).get("cves") or data.get("data", {}).get("results") or []
        total = data.get("data", {}).get("total", 0)
        print("[PASS] Found {} cves (total={})".format(len(cves), total))
        if cves:
            c = cves[0]
            cve_id = c.get("cve_id") or c.get("id")
            cvss = c.get("cvss_score", "N/A")
            print("  First: {} CVSS={}".format(cve_id, cvss))
        return True
    else:
        print("[FAIL] HTTP {}: {}".format(r.status_code, r.text[:100]))
        return False

def test_threat_feeds():
    print("\n=== TEST: Threat Feed Refresh & IOC Ingestion ===")
    r = requests.post(f"{API}/api/threat-feeds/refresh", json={}, verify=False)
    if r.status_code == 200:
        data = r.json()
        results = data.get("data", {})
        for feed, status in results.items():
            if isinstance(status, dict):
                count = status.get("count", 0)
                ioc_ingested = status.get("ioc_ingested", 0)
                print("[PASS] {}: {} entries, {} IOCs ingested".format(feed, count, ioc_ingested))
        return True
    else:
        print("[FAIL] HTTP {}: {}".format(r.status_code, r.text[:100]))
        return False

def test_ioc_list():
    print("\n=== TEST: IOC Listing (from feeds) ===")
    r = requests.get(f"{API}/api/iocs?limit=5", verify=False)
    if r.status_code == 200:
        data = r.json()
        iocs = data.get("data", {}).get("iocs", [])
        stats = data.get("data", {}).get("stats", {})
        total = stats.get("total", 0)
        print("[PASS] Showing {} of {} total IOCs".format(len(iocs), total))
        if iocs:
            ioc = iocs[0]
            ioc_type = ioc.get("ioc_type", "?")
            value = ioc.get("value", "?")[:30]
            source = ioc.get("source", "?")
            print("  Sample: {} {}... from {}".format(ioc_type, value, source))
        return True
    else:
        print("[FAIL] HTTP {}: {}".format(r.status_code, r.text[:100]))
        return False

if __name__ == "__main__":
    print("CyberRegis Feature Smoke Tests")
    print("=" * 60)
    
    results = [
        ("Domain Risk Scoring", test_domain_risk()),
        ("DKIM Detection", test_dkim()),
        ("CVE Search (NVD)", test_cve_search()),
        ("Threat Feed Refresh", test_threat_feeds()),
        ("IOC Listing", test_ioc_list()),
    ]
    
    print("\n" + "=" * 60)
    print("Summary:")
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print("  {}: {}".format(status, name))
    
    passed_count = sum(1 for p in [r[1] for r in results] if p)
    total_count = len(results)
    print("\nTotal: {}/{} tests passed".format(passed_count, total_count))
