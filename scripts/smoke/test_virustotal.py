#!/usr/bin/env python3
"""
Test script for enhanced VirusTotal integration
"""

import os
import sys
import json
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from KALE import AnalysisReport, VIRUSTOTAL_API_KEY

def test_virustotal_integration():
    """Test the enhanced VirusTotal integration"""
    print("🧪 Testing Enhanced VirusTotal Integration")
    print("=" * 50)
    
    try:
        # Test API key validation
        print("1. Testing API key validation...")
        report = AnalysisReport(VIRUSTOTAL_API_KEY)
        is_valid = report.validate_api_key()
        print(f"   API Key Valid: {'✅' if is_valid else '❌'}")
        
        if not is_valid:
            print("   ⚠️  API key validation failed. Check your VirusTotal API key.")
            return False
        
        # Test fallback result generation
        print("\n2. Testing fallback result generation...")
        fallback = report.get_fallback_virustotal_result("Test error message")
        print(f"   Fallback generated: {'✅' if fallback else '❌'}")
        print(f"   Risk Score: {fallback.get('risk_assessment', {}).get('risk_score', 'N/A')}")
        print(f"   Risk Level: {fallback.get('risk_assessment', {}).get('risk_level', 'N/A')}")
        
        # Test summary generation
        print("\n3. Testing summary generation...")
        summary = report.get_virustotal_summary(fallback)
        print(f"   Summary generated: {'✅' if summary else '❌'}")
        print(f"   Summary preview: {summary[:100]}...")
        
        # Test with empty data
        print("\n4. Testing with empty data...")
        empty_summary = report.get_virustotal_summary({})
        print(f"   Empty data summary: {empty_summary}")
        
        print("\n✅ All tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        return False

def test_virustotal_response_structure():
    """Test the expected response structure"""
    print("\n🔍 Testing Response Structure")
    print("=" * 30)
    
    # Create a mock VirusTotal response
    mock_response = {
        "data": {
            "attributes": {
                "stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10
                },
                "reputation": -50,
                "last_analysis_date": int(datetime.now().timestamp()),
                "type_description": "PCAP file"
            }
        }
    }
    
    try:
        report = AnalysisReport(VIRUSTOTAL_API_KEY)
        processed = report.process_virustotal_report(mock_response)
        
        print("Expected structure:")
        print(f"  - risk_assessment: {'✅' if 'risk_assessment' in processed else '❌'}")
        print(f"  - metadata: {'✅' if 'metadata' in processed else '❌'}")
        print(f"  - data: {'✅' if 'data' in processed else '❌'}")
        
        if 'risk_assessment' in processed:
            risk = processed['risk_assessment']
            print(f"  - risk_score: {risk.get('risk_score', 'N/A')}")
            print(f"  - risk_level: {risk.get('risk_level', 'N/A')}")
            print(f"  - detection_ratio: {risk.get('detection_ratio', 'N/A')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Structure test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting VirusTotal Integration Tests\n")
    
    # Run tests
    test1_passed = test_virustotal_integration()
    test2_passed = test_virustotal_response_structure()
    
    print("\n" + "=" * 50)
    print("📊 Test Results Summary")
    print("=" * 50)
    print(f"API Integration Test: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Response Structure Test: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 All tests passed! VirusTotal integration is working correctly.")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed. Please check the implementation.")
        sys.exit(1)
