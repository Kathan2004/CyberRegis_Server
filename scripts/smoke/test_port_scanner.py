#!/usr/bin/env python3
"""
Test script for CyberRegis Port Scanner
This script tests the port scanner without requiring root privileges
"""

import requests
import json
import sys

BASE_URL = "http://localhost:4000"

def test_port_scanner(target, description=""):
    """Test the port scanner endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing Port Scanner for: {target}")
    if description:
        print(f"Description: {description}")
    print(f"{'='*60}")
    
    test_data = {"target": target}
    
    try:
        print("1. Testing port scanner endpoint...")
        response = requests.post(f"{BASE_URL}/api/scan-ports", 
                               json=test_data, 
                               headers={"Content-Type": "application/json"}, 
                               timeout=60)
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ SUCCESS: Port scan completed")
            print(f"   🎯 Target: {data.get('target', 'Unknown')}")
            print(f"   🔍 Scan Type: {data.get('scan_type', 'Unknown')}")
            print(f"   📊 Total Ports Found: {data.get('total_ports', 0)}")
            
            if data.get('ports'):
                print(f"   🚪 Open Ports:")
                for port_info in data.get('ports', []):
                    print(f"      - Port {port_info.get('port')}: {port_info.get('service', 'unknown')} ({port_info.get('state', 'unknown')})")
            else:
                print(f"   🚪 No open ports found")
            
            if data.get('note'):
                print(f"   💡 Note: {data.get('note')}")
            
            return True
        else:
            error_data = response.json()
            print(f"   ❌ FAILED: {error_data.get('message', 'Unknown error')}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ❌ CONNECTION ERROR: Make sure your Flask server is running on port 4000")
        return False
    except requests.exceptions.Timeout:
        print("   ❌ TIMEOUT: Port scan took too long")
        return False
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False

def test_vulnerability_scanner(target, description=""):
    """Test the vulnerability scanner endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing Vulnerability Scanner for: {target}")
    if description:
        print(f"Description: {description}")
    print(f"{'='*60}")
    
    test_data = {"target": target}
    
    try:
        print("1. Testing vulnerability scanner endpoint...")
        response = requests.post(f"{BASE_URL}/api/vulnerability-scan", 
                               json=test_data, 
                               headers={"Content-Type": "application/json"}, 
                               timeout=60)
        
        print(f"   Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ SUCCESS: Vulnerability scan completed")
            print(f"   🎯 Target: {data.get('target', 'Unknown')}")
            print(f"   🔍 Scan Type: {data.get('scan_type', 'Unknown')}")
            print(f"   ⚠️  Vulnerabilities Found: {data.get('total_found', 0)}")
            
            if data.get('vulnerabilities'):
                print(f"   🚨 Vulnerabilities:")
                for vuln in data.get('vulnerabilities', []):
                    print(f"      - {vuln.get('service', 'Unknown')} on port {vuln.get('port')}: {vuln.get('severity', 'Unknown')}")
                    if vuln.get('potential_issues'):
                        for issue in vuln.get('potential_issues', []):
                            print(f"        * {issue}")
            else:
                print(f"   ✅ No vulnerabilities detected")
            
            if data.get('note'):
                print(f"   💡 Note: {data.get('note')}")
            
            return True
        else:
            error_data = response.json()
            print(f"   ❌ FAILED: {error_data.get('message', 'Unknown error')}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ❌ CONNECTION ERROR: Make sure your Flask server is running on port 4000")
        return False
    except requests.exceptions.Timeout:
        print("   ❌ TIMEOUT: Vulnerability scan took too long")
        return False
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False

def main():
    print("🚀 CyberRegis Port Scanner & Vulnerability Scanner Tester")
    print(f"Testing endpoints at: {BASE_URL}")
    print("This script tests scanning WITHOUT requiring root privileges")
    
    # Test cases with different targets
    test_cases = [
        ("127.0.0.1", "Localhost (should work without root)"),
        ("8.8.8.8", "Google DNS (public IP)"),
        ("1.1.1.1", "Cloudflare DNS (public IP)"),
        ("192.168.1.1", "Common local network gateway"),
        ("10.0.0.1", "Common local network gateway")
    ]
    
    port_scan_success = 0
    vuln_scan_success = 0
    total_count = len(test_cases)
    
    for target, description in test_cases:
        # Test port scanner
        if test_port_scanner(target, description):
            port_scan_success += 1
        
        # Test vulnerability scanner
        if test_vulnerability_scanner(target, description):
            vuln_scan_success += 1
    
    print(f"\n{'='*60}")
    print("🎯 Testing Complete!")
    print(f"✅ Port Scanner Success: {port_scan_success}/{total_count}")
    print(f"✅ Vulnerability Scanner Success: {vuln_scan_success}/{total_count}")
    
    if port_scan_success == total_count and vuln_scan_success == total_count:
        print("🎉 All tests passed! Your scanners are working without root privileges.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    print(f"\n💡 Tips:")
    print("- The scanners now use TCP Connect (-sT) instead of SYN scans (-sS)")
    print("- TCP Connect scans don't require root privileges")
    print("- If nmap fails, the system falls back to basic socket scanning")
    print("- Check your Flask server console for detailed scan logs")

if __name__ == "__main__":
    main()
