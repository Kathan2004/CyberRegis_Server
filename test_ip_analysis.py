#!/usr/bin/env python3
"""
Comprehensive test script for enhanced IP analysis backend
Tests all components: geolocation, risk assessment, VirusTotal integration, etc.
"""

import os
import sys
import json
import requests
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ip_analysis_endpoint():
    """Test the enhanced IP analysis endpoint"""
    print("🧪 Testing Enhanced IP Analysis Endpoint")
    print("=" * 50)
    
    # Test data
    test_ips = [
        "8.8.8.8",      # Google DNS (should be clean)
        "1.1.1.1",      # Cloudflare DNS (should be clean)
        "192.168.1.1",  # Private IP (should be rejected)
        "invalid_ip",   # Invalid format (should be rejected)
    ]
    
    base_url = "http://localhost:4000"
    
    for ip in test_ips:
        print(f"\n🔍 Testing IP: {ip}")
        print("-" * 30)
        
        try:
            # Test the endpoint
            response = requests.post(
                f"{base_url}/api/check-ip",
                json={"ip": ip},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Success - Status: {data.get('status')}")
                
                # Validate response structure
                validate_response_structure(data, ip)
                
            else:
                print(f"❌ Error Response:")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data.get('error', 'Unknown error')}")
                    print(f"   Message: {error_data.get('message', 'No message')}")
                except:
                    print(f"   Raw response: {response.text}")
                    
        except requests.exceptions.ConnectionError:
            print("❌ Connection Error: Make sure the Flask server is running on port 4000")
            break
        except requests.exceptions.Timeout:
            print("❌ Timeout: Request took too long")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

def validate_response_structure(data, ip):
    """Validate the response structure matches requirements"""
    print("🔍 Validating Response Structure...")
    
    required_fields = [
        "status", "timestamp", "data"
    ]
    
    data_fields = [
        "ip_details", "risk_assessment", "technical_details", 
        "virustotal", "virustotal_summary", "recommendations"
    ]
    
    ip_details_fields = [
        "address", "domain", "isp", "location"
    ]
    
    location_fields = [
        "city", "region", "country", "country_code"
    ]
    
    risk_assessment_fields = [
        "risk_level", "confidence_score", "total_reports", 
        "last_reported", "categories"
    ]
    
    technical_fields = [
        "as_name", "asn", "is_public", "is_tor", 
        "usage_type", "organization"
    ]
    
    virustotal_fields = [
        "risk_assessment", "metadata", "data"
    ]
    
    # Check top-level fields
    for field in required_fields:
        if field not in data:
            print(f"   ❌ Missing top-level field: {field}")
            return False
        else:
            print(f"   ✅ {field}: {data[field]}")
    
    # Check data section
    if "data" not in data:
        print("   ❌ Missing 'data' section")
        return False
    
    data_section = data["data"]
    
    # Check data fields
    for field in data_fields:
        if field not in data_section:
            print(f"   ❌ Missing data field: {field}")
            return False
        else:
            print(f"   ✅ {field}: Present")
    
    # Validate IP details
    ip_details = data_section.get("ip_details", {})
    for field in ip_details_fields:
        if field not in ip_details:
            print(f"   ❌ Missing ip_details field: {field}")
        else:
            print(f"   ✅ ip_details.{field}: {ip_details[field]}")
    
    # Validate location
    location = ip_details.get("location", {})
    for field in location_fields:
        if field not in location:
            print(f"   ❌ Missing location field: {field}")
        else:
            print(f"   ✅ location.{field}: {location[field]}")
    
    # Validate risk assessment
    risk_assessment = data_section.get("risk_assessment", {})
    for field in risk_assessment_fields:
        if field not in risk_assessment:
            print(f"   ❌ Missing risk_assessment field: {field}")
        else:
            print(f"   ✅ risk_assessment.{field}: {risk_assessment[field]}")
    
    # Validate technical details
    technical = data_section.get("technical_details", {})
    for field in technical_fields:
        if field not in technical:
            print(f"   ❌ Missing technical_details field: {field}")
        else:
            print(f"   ✅ technical_details.{field}: {technical[field]}")
    
    # Validate VirusTotal data
    virustotal = data_section.get("virustotal", {})
    for field in virustotal_fields:
        if field not in virustotal:
            print(f"   ❌ Missing virustotal field: {field}")
        else:
            print(f"   ✅ virustotal.{field}: Present")
    
    # Check VirusTotal risk assessment
    vt_risk = virustotal.get("risk_assessment", {})
    if vt_risk:
        vt_risk_fields = ["risk_score", "risk_level", "malicious_count", "suspicious_count", "detection_ratio", "total_engines"]
        for field in vt_risk_fields:
            if field not in vt_risk:
                print(f"   ❌ Missing virustotal.risk_assessment field: {field}")
            else:
                print(f"   ✅ virustotal.risk_assessment.{field}: {vt_risk[field]}")
    
    # Check summary and recommendations
    summary = data_section.get("virustotal_summary", "")
    recommendations = data_section.get("recommendations", [])
    
    print(f"   ✅ virustotal_summary: {summary[:100]}...")
    print(f"   ✅ recommendations: {len(recommendations)} items")
    
    print("   🎯 Response structure validation completed!")
    return True

def test_error_handling():
    """Test error handling scenarios"""
    print("\n🧪 Testing Error Handling")
    print("=" * 30)
    
    base_url = "http://localhost:4000"
    
    # Test cases
    test_cases = [
        {"name": "Empty request", "data": {}, "expected_status": 400},
        {"name": "Missing IP", "data": {"other_field": "value"}, "expected_status": 400},
        {"name": "Empty IP", "data": {"ip": ""}, "expected_status": 400},
        {"name": "Invalid IP format", "data": {"ip": "not_an_ip"}, "expected_status": 400},
        {"name": "Private IP", "data": {"ip": "192.168.1.1"}, "expected_status": 400},
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Testing: {test_case['name']}")
        
        try:
            response = requests.post(
                f"{base_url}/api/check-ip",
                json=test_case["data"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Status Code: {response.status_code} (Expected: {test_case['expected_status']})")
            
            if response.status_code == test_case['expected_status']:
                print("   ✅ Correct error status returned")
            else:
                print("   ❌ Unexpected status code")
            
            # Check error response structure
            try:
                error_data = response.json()
                if "error" in error_data:
                    print(f"   ✅ Error field present: {error_data['error']}")
                if "message" in error_data:
                    print(f"   ✅ Message field present: {error_data['message']}")
            except:
                print("   ⚠️ Response is not JSON")
                
        except requests.exceptions.ConnectionError:
            print("   ❌ Connection Error: Server not running")
            break
        except Exception as e:
            print(f"   ❌ Test failed: {e}")

def test_performance():
    """Test performance and response times"""
    print("\n🧪 Testing Performance")
    print("=" * 30)
    
    base_url = "http://localhost:4000"
    test_ip = "8.8.8.8"
    
    print(f"Testing response time for IP: {test_ip}")
    
    try:
        start_time = datetime.now()
        
        response = requests.post(
            f"{base_url}/api/check-ip",
            json={"ip": test_ip},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        
        print(f"Response Time: {response_time:.2f} seconds")
        
        if response_time < 5:
            print("✅ Response time is within acceptable limits (< 5 seconds)")
        else:
            print("⚠️ Response time is slower than expected (> 5 seconds)")
            
        if response.status_code == 200:
            print("✅ Request completed successfully")
        else:
            print(f"❌ Request failed with status: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Server not running")
    except Exception as e:
        print(f"❌ Performance test failed: {e}")

def main():
    """Main test function"""
    print("🚀 Starting Comprehensive IP Analysis Tests\n")
    
    # Test 1: Endpoint functionality
    test_ip_analysis_endpoint()
    
    # Test 2: Error handling
    test_error_handling()
    
    # Test 3: Performance
    test_performance()
    
    print("\n" + "=" * 50)
    print("📊 IP Analysis Testing Completed")
    print("=" * 50)
    print("\nNext steps:")
    print("1. Check the response structure matches your requirements")
    print("2. Verify VirusTotal integration is working")
    print("3. Test with your frontend application")
    print("4. Monitor server logs for any errors")

if __name__ == "__main__":
    main()
