#!/usr/bin/env python3
"""
Debug script to test CyberRegis endpoints
Run this to identify issues with your API endpoints
"""

import requests
import json
import sys

BASE_URL = "http://localhost:4000"

def test_endpoint(endpoint, method="GET", data=None, description=""):
    """Test an endpoint and report results"""
    print(f"\n{'='*60}")
    print(f"Testing: {method} {endpoint}")
    if description:
        print(f"Description: {description}")
    print(f"{'='*60}")
    
    try:
        if method == "GET":
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=10)
        elif method == "POST":
            headers = {"Content-Type": "application/json"}
            response = requests.post(f"{BASE_URL}{endpoint}", 
                                  json=data, 
                                  headers=headers, 
                                  timeout=10)
        else:
            print(f"Unsupported method: {method}")
            return False
            
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                print(f"Response Data: {json.dumps(response_data, indent=2)}")
                print("✅ SUCCESS")
                return True
            except json.JSONDecodeError:
                print(f"Response Text: {response.text}")
                print("⚠️  SUCCESS but not JSON")
                return True
        else:
            print(f"Response Text: {response.text}")
            print("❌ FAILED")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Make sure your Flask server is running on port 4000")
        return False
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: Request took too long")
        return False
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return False

def main():
    print("🚀 CyberRegis Endpoint Debugger")
    print(f"Testing endpoints at: {BASE_URL}")
    
    # Test basic endpoints
    test_endpoint("/api/health", "GET", description="Health check endpoint")
    test_endpoint("/api/status", "GET", description="System status endpoint")
    test_endpoint("/api/monitoring-results", "GET", description="Monitoring results endpoint")
    
    # Test CORS
    test_endpoint("/api/test", "GET", description="CORS test endpoint")
    
    # Test URL validation
    test_data = {"url": "https://example.com"}
    test_endpoint("/api/test-url", "POST", data=test_data, description="URL validation test")
    
    # Test main URL check endpoint
    test_data = {"url": "https://google.com"}
    test_endpoint("/api/check-url", "POST", data=test_data, description="Main URL security check")
    
    # Test security file content endpoint
    test_data = {"file_type": "robots", "domain": "google.com"}
    test_endpoint("/api/security-file-content", "POST", data=test_data, description="Security file content fetch")
    
    # Test security file test endpoint
    test_data = {"file_type": "robots", "domain": "google.com"}
    test_endpoint("/api/test-security-file", "POST", data=test_data, description="Security file connectivity test")
    
    # Test with invalid data
    test_data = {"url": ""}
    test_endpoint("/api/check-url", "POST", data=test_data, description="URL check with empty URL")
    
    test_data = {"invalid": "data"}
    test_endpoint("/api/check-url", "POST", data=test_data, description="URL check with invalid data")
    
    print(f"\n{'='*60}")
    print("🎯 Debugging Complete!")
    print("Check the output above for any errors or issues.")
    print("If you see connection errors, make sure your Flask server is running.")
    print("If you see 500 errors, check your server logs for the actual error.")

if __name__ == "__main__":
    main()
