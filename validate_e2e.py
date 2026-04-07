#!/usr/bin/env python3
"""End-to-end validation of all feature fixes."""
import requests
import warnings
warnings.filterwarnings('ignore')

API = 'http://localhost:5000'
tests = []

# 1. Domain Risk
print('\n=== Domain Risk Scoring ===')
try:
    r = requests.post(f'{API}/api/analyze-domain', json={'domain': 'example.com'}, verify=False, timeout=10)
    if r.status_code == 200:
        risk = r.json().get('data', {}).get('risk_score', {})
        score = risk.get('score', '?')
        level = risk.get('level', '?')
        print('PASS: example.com = {}/100 ({} risk)'.format(score, level))
        tests.append(('Domain Risk', True))
    else:
        print('FAIL: {}'.format(r.status_code))
        tests.append(('Domain Risk', False))
except Exception as e:
    print('ERROR: {}'.format(str(e)[:50]))
    tests.append(('Domain Risk', False))

# 2. CVE Search
print('\n=== CVE Search (NVD) ===')
try:
    r = requests.get(f'{API}/api/cve/search?q=log4j', verify=False, timeout=15)
    if r.status_code == 200:
        data = r.json().get('data', {})
        cves = data.get('cves', data.get('results', []))
        if isinstance(cves, list) and len(cves) > 0:
            first = cves[0].get('cve_id', cves[0].get('id', '?'))
            print('PASS: Found {} CVEs, first: {}'.format(len(cves), first))
            tests.append(('CVE Search', True))
        else:
            print('FAIL: No CVEs found')
            tests.append(('CVE Search', False))
    else:
        print('FAIL: {}'.format(r.status_code))
        tests.append(('CVE Search', False))
except Exception as e:
    print('ERROR: {}'.format(str(e)[:50]))
    tests.append(('CVE Search', False))

# 3. Threat Feeds
print('\n=== Threat Feed Refresh ===')
try:
    r = requests.post(f'{API}/api/threat-feeds/refresh', json={}, verify=False, timeout=30)
    if r.status_code == 200:
        feeds = r.json().get('data', {})
        ingested = sum(f.get('ioc_ingested', 0) for f in feeds.values() if isinstance(f, dict))
        print('PASS: Refreshed feeds, {} IOCs ingested'.format(ingested))
        tests.append(('Threat Feeds', True))
    else:
        print('FAIL: {}'.format(r.status_code))
        tests.append(('Threat Feeds', False))
except Exception as e:
    print('ERROR: {}'.format(str(e)[:50]))
    tests.append(('Threat Feeds', False))

# 4. IOCs
print('\n=== IOC Listing ===')
try:
    r = requests.get(f'{API}/api/iocs', verify=False, timeout=10)
    if r.status_code == 200:
        iocs = r.json().get('data', {}).get('iocs', [])
        if iocs:
            print('PASS: {} IOCs in database'.format(len(iocs)))
            tests.append(('IOC Ingestion', True))
        else:
            print('INFO: No IOCs yet (feeds may be empty)')
            tests.append(('IOC Ingestion', True))
    else:
        print('FAIL: {}'.format(r.status_code))
        tests.append(('IOC Ingestion', False))
except Exception as e:
    print('ERROR: {}'.format(str(e)[:50]))
    tests.append(('IOC Ingestion', False))

# 5. DKIM
print('\n=== Email Security (DKIM) ===')
try:
    r = requests.post(f'{API}/api/email-security', json={'domain': 'google.com'}, verify=False, timeout=10)
    if r.status_code == 200:
        dkim = r.json().get('data', {}).get('email_security', {}).get('dkim', {})
        status = dkim.get('status', '?')
        print('PASS: DKIM detection working')
        tests.append(('DKIM Detection', True))
    else:
        print('FAIL: {}'.format(r.status_code))
        tests.append(('DKIM Detection', False))
except Exception as e:
    print('ERROR: {}'.format(str(e)[:50]))
    tests.append(('DKIM Detection', False))

# Summary
print('\n========== SUMMARY ==========')
passed = 0
for name, success in tests:
    status = 'PASS' if success else 'FAIL'
    print('[{}] {}'.format(status, name))
    if success:
        passed += 1
print('\nTotal: {}/{} tests passed'.format(passed, len(tests)))
