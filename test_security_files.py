#!/usr/bin/env python3
"""
Test script for CyberRegis Security File Content endpoints
This script specifically tests robots.txt and security.txt fetching
"""

import requests
import json
import sys

BASE_URL = "http://localhost:4000"

def test_security_file_endpoint(file_type, domain, description=""):
    """Test the security file content endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing Security File: {file_type}.txt for {domain}")
    if description:
        print(f"Description: {description}")
    print(f"{'='*60}")
    
    # Test the test endpoint first
    test_data = {"file_type": file_type, "domain": domain}
    try:
        print("1. Testing connectivity and file accessibility...")
        response = requests.post(f"{BASE_URL}/api/test-security-file", 
                               json=test_data, 
                               headers={"Content-Type": "application/json"}, 
                               timeout=30)
        
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Connectivity Test: {data.get('connectivity', 'Unknown')}")
            print(f"   ✅ File Status: {data.get('file_status', 'Unknown')}")
            if data.get('file_content_preview') and data.get('file_content_preview') != "Not accessible":
                print(f"   📄 Content Preview: {data.get('file_content_preview', 'None')}")
        else:
            print(f"   ❌ Test endpoint failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Test endpoint error: {e}")
        return False
    
    # Now test the actual security file content endpoint
    try:
        print("\n2. Testing actual file content fetch...")
        response = requests.post(f"{BASE_URL}/api/security-file-content", 
                               json=test_data, 
                               headers={"Content-Type": "application/json"}, 
                               timeout=30)
        
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ SUCCESS: File content retrieved")
            print(f"   📄 Content Length: {data.get('file_info', {}).get('content_length', 'Unknown')}")
            print(f"   🔗 URL: {data.get('file_info', {}).get('url', 'Unknown')}")
            content = data.get('file_info', {}).get('content', '')
            if content:
                preview = content[:200] + "..." if len(content) > 200 else content
                print(f"   📝 Content Preview: {preview}")
            return True
        else:
            error_data = response.json()
            print(f"   ❌ FAILED: {error_data.get('message', 'Unknown error')}")
            if 'http_status' in error_data:
                print(f"   📊 HTTP Status: {error_data.get('http_status')}")
            if 'note' in error_data:
                print(f"   💡 Note: {error_data.get('note')}")
            return False
            
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False

def main():
    print("🔒 CyberRegis Security File Content Tester")
    print(f"Testing endpoints at: {BASE_URL}")
    
    # Test cases with different domains
    test_cases = [
        ("robots", "google.com", "Well-known domain with robots.txt"),
        ("robots", "github.com", "Popular site with robots.txt"),
        ("robots", "spiderman.com", "Domain that was causing 503 errors"),
        ("security", "google.com", "Well-known domain with security.txt"),
        ("security", "github.com", "Popular site with security.txt"),
        ("robots", "nonexistent-domain-12345.com", "Non-existent domain test"),
        ("robots", "httpbin.org", "Test domain with known good responses")
    ]
    
    success_count = 0
    total_count = len(test_cases)
    
    for file_type, domain, description in test_cases:
        if test_security_file_endpoint(file_type, domain, description):
            success_count += 1
    
    print(f"\n{'='*60}")
    print("🎯 Testing Complete!")
    print(f"✅ Successful: {success_count}/{total_count}")
    print(f"❌ Failed: {total_count - success_count}/{total_count}")
    
    if success_count == total_count:
        print("🎉 All tests passed! Your security file endpoints are working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        print("💡 This is normal for domains that don't have the requested files.")
    
    print(f"\n💡 Tips:")
    print("- 404 errors are normal for domains without robots.txt or security.txt")
    print("- 503 errors indicate the target server is down or overloaded")
    print("- Connection timeouts suggest network issues or firewall blocks")
    print("- Check your Flask server console for detailed error logs")

if __name__ == "__main__":
    main()
