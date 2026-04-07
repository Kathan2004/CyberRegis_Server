import matplotlib
matplotlib.use('Agg')
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import requests
import os
import sys
import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Union
from urllib.parse import urlparse
import html
import logging
from cachetools import TTLCache
import whois
import time
import socket
import threading
import pyshark
import matplotlib.pyplot as plt
import io
import base64
import traceback
import urllib3
from all_functions import all_functions

# Disable SSL verification warnings for corporate proxy environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.environ['PYTHONHTTPSVERIFY'] = '0'

# Patch requests to skip SSL verification globally (corporate proxy workaround)
_original_request = requests.Session.request
def _patched_request(self, *args, **kwargs):
    kwargs.setdefault('verify', False)
    return _original_request(self, *args, **kwargs)
requests.Session.request = _patched_request
# Also patch module-level convenience functions
_orig_get = requests.get
_orig_post = requests.post
def _patched_get(*args, **kwargs):
    kwargs.setdefault('verify', False)
    return _orig_get(*args, **kwargs)
def _patched_post(*args, **kwargs):
    kwargs.setdefault('verify', False)
    return _orig_post(*args, **kwargs)
requests.get = _patched_get
requests.post = _patched_post

app = Flask(__name__)
CORS(app, 
     origins=[r"http://localhost:\d+", r"http://127\.0\.0\.1:\d+", "https://yourdomain.com"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Preflight handler for CORS
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        origin = request.headers.get("Origin", "*")
        response.headers.add("Access-Control-Allow-Origin", origin)
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per minute"],
    storage_uri="memory://"
)

# Cache Configuration (TTL = 1 hour)
cache = TTLCache(maxsize=1000, ttl=3600)

# Logging Configuration
logging.basicConfig(
    filename="security_checker.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Constants with API Keys
SAFE_BROWSING_KEY = "AIzaSyD8D-zbxJiKQC9l9WvIzrkuLpPu-AUhq_8"
ABUSEIPDB_API_KEY = "7188aa797ac3fddbd72c4f0251fa214cb6ff49859dae1c97b0cdb8f5d76ecce0816a65ac3667b240"
TELEGRAM_BOT_TOKEN = "7631413879:AAH1eDKDIKYGepmKZRplMXnAVyRFljHjEQo"
TELEGRAM_CHAT_ID = "945134518"
GEMINI_API_KEY = "AIzaSyA_gC96TBtWH-UDjp5UZBJ-ZYZFrvqtfFg"
VIRUSTOTAL_API_KEY = "5a9219f6d9b2761fcb99552cd745603e1ffd8a0c265a468a61d1ab8a4fb5fa99"

# Gemini API Configuration
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# Custom JSON Response Formatter
class PrettyJSONResponse:
    @staticmethod
    def format(data: Dict) -> Dict:
        """Format JSON response with pretty-printed HTML and metadata."""
        formatted_json = json.dumps(data, indent=2, sort_keys=True)
        return {
            "data": data,
            "formatted": f"<pre style='color: #22c55e; background: black; padding: 0;'>{html.escape(formatted_json)}</pre>",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "success" if "error" not in data else "error"
        }

# AnalysisReport Class for PCAP Analysis
class AnalysisReport:
    def __init__(self, api_key):
        self.api_key = api_key
        if not api_key or len(api_key) < 10:
            raise ValueError("Invalid VirusTotal API key provided")
        self.headers = {"x-apikey": self.api_key}

    def validate_api_key(self):
        """Validate VirusTotal API key by making a test request"""
        try:
            test_url = "https://www.virustotal.com/api/v3/users/current"
            response = requests.get(test_url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logger.warning(f"VirusTotal API key validation failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error validating VirusTotal API key: {e}")
            return False

    def analyze_file(self, file_path):
        file_info = {}
        try:
            working_directory = os.path.dirname(file_path)
            os.makedirs(working_directory, exist_ok=True)
            os.chdir(working_directory)

            file_info['metadata'] = self.get_metadata(file_path)
            file_info['virustotal'] = self.analyze_with_virustotal(file_path)

            if file_path.endswith('.pcap'):
                file_info['pcap_analysis'] = self.analyze_pcap(file_path)
                file_info['chart_base64'] = self.generate_pcap_chart(file_info['pcap_analysis'], file_path)

            return file_info
        except Exception as e:
            logger.error(f"Error during file analysis: {e}")
            return {"error": str(e)}

    def get_metadata(self, file_path):
        metadata = {
            "Filename": os.path.basename(file_path),
            "Size (bytes)": os.path.getsize(file_path),
            "File Type": self.get_file_type(file_path)
        }
        return metadata

    def get_file_type(self, file_path):
        return file_path.split('.')[-1]

    def analyze_with_virustotal(self, file_path):
        url = "https://www.virustotal.com/api/v3/files"
        try:
            # Check if API key is valid
            if not self.validate_api_key():
                return self.get_fallback_virustotal_result("Invalid or expired API key")
            
            with open(file_path, "rb") as file:
                response = requests.post(url, headers=self.headers, files={"file": file})
                if response.status_code == 200:
                    file_id = response.json().get("data", {}).get("id")
                    return self.get_virustotal_report(file_id)
                elif response.status_code == 429:
                    return self.get_fallback_virustotal_result("Rate limit exceeded - please try again later")
                elif response.status_code == 401:
                    return self.get_fallback_virustotal_result("Unauthorized - check your API key")
                else:
                    raise Exception(f"VirusTotal API error: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error during VirusTotal analysis: {e}")
            return self.get_fallback_virustotal_result(str(e))

    def get_fallback_virustotal_result(self, error_message):
        """Provide fallback result when VirusTotal analysis fails"""
        return {
            "error": f"VirusTotal analysis failed: {error_message}",
            "risk_assessment": {
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "detection_ratio": "0/0",
                "status": "FAILED"
            },
            "metadata": {
                "reputation": 0,
                "analysis_date": None,
                "file_type": "Unknown",
                "error_details": error_message
            }
        }

    def get_virustotal_summary(self, virustotal_data):
        """Generate a human-readable summary of VirusTotal analysis"""
        if not virustotal_data or 'risk_assessment' not in virustotal_data:
            return "No VirusTotal data available"
        
        risk_assessment = virustotal_data['risk_assessment']
        metadata = virustotal_data.get('metadata', {})
        
        summary = f"Risk Score: {risk_assessment.get('risk_score', 0)}/100\n"
        summary += f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n"
        summary += f"Detection: {risk_assessment.get('detection_ratio', '0/0')}\n"
        summary += f"Malicious: {risk_assessment.get('malicious_count', 0)}\n"
        summary += f"Suspicious: {risk_assessment.get('suspicious_count', 0)}\n"
        
        if metadata.get('reputation'):
            summary += f"Reputation: {metadata.get('reputation')}\n"
        if metadata.get('file_type'):
            summary += f"File Type: {metadata.get('file_type')}\n"
        
        return summary

    def get_virustotal_report(self, file_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        try:
            for _ in range(5):  # Retry up to 5 times
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    report = response.json()
                    if report.get('data', {}).get('attributes', {}).get('status') == 'completed':
                        return self.process_virustotal_report(report)
                    elif report.get('data', {}).get('attributes', {}).get('status') == 'queued':
                        logger.info(f"VirusTotal analysis queued for file {file_id}, waiting...")
                        time.sleep(5)  # Wait before retrying
                    else:
                        logger.warning(f"VirusTotal analysis status: {report.get('data', {}).get('attributes', {}).get('status')}")
                        time.sleep(5)  # Wait before retrying
                else:
                    raise Exception(f"Failed to fetch report: {response.status_code} - {response.text}")
            
            # If we get here, the analysis didn't complete in time
            logger.warning(f"VirusTotal analysis for file {file_id} did not complete within timeout period")
            return self.get_fallback_virustotal_result("Analysis timeout - please check manually on VirusTotal")
            
        except Exception as e:
            logger.error(f"Error fetching VirusTotal report: {e}")
            return self.get_fallback_virustotal_result(str(e))

    def process_virustotal_report(self, report):
        """Process VirusTotal report and calculate risk score"""
        try:
            attributes = report.get('data', {}).get('attributes', {})
            stats = attributes.get('stats', {})
            
            # Extract counts
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total_engines = sum(stats.values()) if stats else 0
            
            # Calculate risk score (0-100)
            if total_engines == 0:
                risk_score = 0
            else:
                # Weight malicious detections more heavily
                risk_score = min(100, int((malicious * 3 + suspicious * 2) / total_engines * 100))
            
            # Determine risk level
            if risk_score >= 75:
                risk_level = "HIGH"
            elif risk_score >= 50:
                risk_level = "MEDIUM"
            elif risk_score >= 25:
                risk_level = "LOW"
            else:
                risk_level = "VERY_LOW"
            
            # Get additional metadata
            file_info = attributes.get('last_analysis_stats', {})
            reputation = attributes.get('reputation', 0)
            
            return {
                "data": report.get('data', {}),
                "risk_assessment": {
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "undetected_count": undetected,
                    "total_engines": total_engines,
                    "detection_ratio": f"{malicious + suspicious}/{total_engines}" if total_engines > 0 else "0/0"
                },
                "metadata": {
                    "reputation": reputation,
                    "analysis_date": attributes.get('last_analysis_date'),
                    "file_type": attributes.get('type_description', 'Unknown')
                }
            }
        except Exception as e:
            logger.error(f"Error processing VirusTotal report: {e}")
            return {
                "error": f"Failed to process VirusTotal report: {str(e)}",
                "risk_assessment": {
                    "risk_score": 0,
                    "risk_level": "UNKNOWN",
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "harmless_count": 0,
                    "undetected_count": 0,
                    "total_engines": 0,
                    "detection_ratio": "0/0"
                }
            }

    def analyze_pcap(self, file_path):
        capture = pyshark.FileCapture(file_path)
        protocol_counts = {}

        for packet in capture:
            protocol = packet.highest_layer
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        capture.close()
        return protocol_counts

    def generate_pcap_chart(self, protocol_counts, file_path):
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(protocols, counts, color='blue')
        plt.xlabel('Protocols')
        plt.ylabel('Counts')
        plt.title('PCAP Protocol Analysis')
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Save chart to a bytes buffer and encode as base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        chart_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()
        buffer.close()

        return chart_base64

# Telegram Notification Function
def send_telegram_notification(check_type: str, subject: str, result: Dict) -> bool:
    try:
        if check_type == "url":
            is_malicious = result.get("data", {}).get("threat_analysis", {}).get("is_malicious", False)
            risk_level = result.get("data", {}).get("additional_checks", {}).get("domain_analysis", {}).get("risk_level", "unknown")
            message = f"🔍 *URL Security Check*\n\n"
            message += f"URL: `{subject}`\n"
            message += f"Status: {'⚠️ MALICIOUS' if is_malicious else '✅ SAFE'}\n"
            message += f"Risk Level: {risk_level.upper()}\n"
            recommendations = result.get("data", {}).get("recommendations", [])
            if recommendations:
                message += "\n*Recommendations:*\n"
                for i, rec in enumerate(recommendations[:3], 1):
                    message += f"{i}. {rec}\n"
        elif check_type == "ip":
            # Enhanced IP analysis with VirusTotal integration
            ip_data = result.get("data", {})
            risk_assessment = ip_data.get("risk_assessment", {})
            ip_details = ip_data.get("ip_details", {})
            virustotal_data = ip_data.get("virustotal", {})
            
            message = f"🖥️ *IP Security Analysis*\n\n"
            message += f"IP Address: `{subject}`\n"
            message += f"Risk Level: {risk_assessment.get('risk_level', 'Unknown').upper()}\n"
            message += f"Confidence Score: {risk_assessment.get('confidence_score', 0)}/100\n"
            message += f"Total Reports: {risk_assessment.get('total_reports', 0)}\n"
            message += f"Country: {ip_details.get('location', {}).get('country', 'Unknown')}\n"
            message += f"ISP: {ip_details.get('isp', 'Unknown')}\n"
            
            # VirusTotal information
            if virustotal_data and 'risk_assessment' in virustotal_data:
                vt_risk = virustotal_data['risk_assessment']
                message += f"\n🦠 *VirusTotal:*\n"
                message += f"Risk Score: {vt_risk.get('risk_score', 0)}/100\n"
                message += f"Risk Level: {vt_risk.get('risk_level', 'UNKNOWN')}\n"
                message += f"Detection: {vt_risk.get('detection_ratio', '0/0')}\n"
            
            # Categories
            categories = risk_assessment.get('categories', [])
            if categories and categories != ['clean']:
                message += f"\n⚠️ Categories: {', '.join(categories)}\n"
        elif check_type == "chat":
            message = f"💬 *Chat Interaction*\n\n"
            message += f"User Query: `{subject}`\n"
            message += f"Response: {result.get('data', {}).get('response', 'No response')[:200]}...\n"
            message += f"\n🕒 *{result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}*"
        elif check_type == "pcap":
            message = f"📊 *PCAP Analysis*\n\n"
            message += f"File: `{subject}`\n"
            
            # Enhanced VirusTotal information
            virustotal_data = result.get('data', {}).get('virustotal', {})
            if virustotal_data and 'risk_assessment' in virustotal_data:
                risk_assessment = virustotal_data['risk_assessment']
                message += f"🦠 *VirusTotal Analysis:*\n"
                message += f"Risk Score: {risk_assessment.get('risk_score', 0)}/100\n"
                message += f"Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}\n"
                message += f"Malicious: {risk_assessment.get('malicious_count', 0)}\n"
                message += f"Suspicious: {risk_assessment.get('suspicious_count', 0)}\n"
                message += f"Detection Ratio: {risk_assessment.get('detection_ratio', '0/0')}\n"
            else:
                message += f"🦠 *VirusTotal Analysis:* No data available\n"
            
            message += f"Protocols Analyzed: {len(result.get('data', {}).get('pcap_analysis', {}))}\n"
            message += f"\n🕒 *{result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}*"
        else:
            message = f"⚙️ *Security Check*\n\n"
            message += f"Type: {check_type}\n"
            message += f"Subject: {subject}\n"
            message += f"Status: {result.get('status', 'Unknown')}\n"
        message += f"\n🕒 *{result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}*"
        api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Telegram notification sent for {check_type} check: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")
        return False

# Validation Functions
def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

def is_valid_ip(ip: str) -> bool:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

# URL Analysis Functions
def get_url_details(url: str) -> Dict:
    parsed_url = urlparse(url)
    return {
        "scheme": parsed_url.scheme,
        "domain": parsed_url.netloc,
        "path": parsed_url.path,
        "query_params": dict(urllib.parse.parse_qsl(parsed_url.query)),
        "fragment": parsed_url.fragment
    }

def check_suspicious_keywords(url: str) -> Dict:
    suspicious_words = [
        'login', 'signin', 'account', 'bank', 'verify', 'secure', 'update',
        'payment', 'password', 'credential', 'wallet', 'bitcoin', 'crypto'
    ]
    url_lower = url.lower()
    found_keywords = [word for word in suspicious_words if word in url_lower]
    return {
        "found": bool(found_keywords),
        "matches": found_keywords,
        "risk_level": "high" if len(found_keywords) > 2 else "medium" if found_keywords else "low"
    }

def check_ssl_certificate(url: str) -> Dict:
    """Check if SSL certificate is present by connecting on port 443."""
    import ssl as _ssl
    try:
        domain = urlparse(url).netloc
        # Connect directly via SSL socket to check cert (bypasses proxy issues with requests)
        context = _ssl._create_unverified_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    return {
                        "valid": True,
                        "status_code": 200
                    }
                return {
                    "valid": False,
                    "error": "No certificate returned"
                }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }

def get_whois_data(domain: str) -> Dict:
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": w.get("name_servers"),
            "status": w.get("status")
        }
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return {"error": "Failed to retrieve WHOIS data"}

def analyze_domain_security(domain: str) -> Dict:
    suspicious_patterns = {
        "number_substitution": bool(re.search(r'\d+', domain)),
        "special_chars": bool(re.search(r'[^a-zA-Z0-9\-\.]', domain)),
        "suspicious_tld": domain.split('.')[-1] in ['xyz', 'tk', 'ml', 'ga', 'cf'],
        "length": len(domain),
        "subdomains": len(domain.split('.')) - 1
    }
    risk_score = 0
    risk_factors = []
    if suspicious_patterns["number_substitution"]:
        risk_score += 1
        risk_factors.append("Contains number substitution")
    if suspicious_patterns["suspicious_tld"]:
        risk_score += 2
        risk_factors.append("Uses suspicious TLD")
    if suspicious_patterns["length"] > 30:
        risk_score += 1
        risk_factors.append("Unusually long domain name")
    if suspicious_patterns["subdomains"] > 2:
        risk_score += 1
        risk_factors.append("Multiple subdomains")
    return {
        "analysis": suspicious_patterns,
        "risk_score": risk_score,
        "risk_level": "high" if risk_score > 3 else "medium" if risk_score > 1 else "low",
        "risk_factors": risk_factors,
        "whois": get_whois_data(domain)
    }

# Main Security Check Functions
def check_url_safety(url: str) -> Dict:
    if not is_valid_url(url):
        return PrettyJSONResponse.format({
            "error": "Invalid URL format",
            "suggestions": [
                "Ensure the URL starts with http:// or https://",
                "Check for correct domain formatting",
                "Avoid special characters unless properly encoded"
            ]
        })
    cache_key = f"url:{url}"
    if cache_key in cache:
        logger.info(f"Cache hit for URL: {url}")
        return cache[cache_key]
    try:
        # Check if API key is available
        if not SAFE_BROWSING_KEY or SAFE_BROWSING_KEY == "":
            print("Warning: Google Safe Browsing API key not configured")
            # Fallback to basic checks without Google API
            results = {
                "url_analysis": {
                    "input_url": url,
                    "parsed_details": get_url_details(url),
                    "security_check_time": datetime.now().isoformat()
                },
                "threat_analysis": {
                    "is_malicious": False,
                    "threats_found": 0,
                    "threat_details": [],
                    "google_safe_browsing": {
                        "status": "not_configured",
                        "note": "API key not configured"
                    }
                },
                "additional_checks": {
                    "ssl_security": check_ssl_certificate(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"},
                    "suspicious_patterns": check_suspicious_keywords(url),
                    "domain_analysis": analyze_domain_security(urlparse(url).netloc)
                },
                "recommendations": []
            }
            
            # Add recommendations based on basic checks
            if results["additional_checks"]["suspicious_patterns"]["risk_level"] == "high":
                results["recommendations"].extend([
                    "Proceed with caution",
                    "Verify the website's authenticity",
                    "Avoid entering sensitive information"
                ])
            
            formatted_response = PrettyJSONResponse.format(results)
            cache[cache_key] = formatted_response
            return formatted_response
        
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "security-checker", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        print(f"Calling Google Safe Browsing API for: {url}")
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"Google Safe Browsing API response: {data}")
        results = {
            "url_analysis": {
                "input_url": url,
                "parsed_details": get_url_details(url),
                "security_check_time": datetime.now().isoformat()
            },
            "threat_analysis": {
                "is_malicious": bool(data.get("matches", [])),
                "threats_found": len(data.get("matches", [])),
                "threat_details": data.get("matches", []),
                "google_safe_browsing": {
                    "status": "checked",
                    "response_code": response.status_code
                }
            },
            "additional_checks": {
                "ssl_security": check_ssl_certificate(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"},
                "suspicious_patterns": check_suspicious_keywords(url),
                "domain_analysis": analyze_domain_security(urlparse(url).netloc)
            },
            "recommendations": []
        }
        if results["threat_analysis"]["is_malicious"]:
            results["recommendations"].extend([
                "Avoid visiting this website",
                "Scan your device for malware",
                "Report the URL to your IT department"
            ])
        elif results["additional_checks"]["suspicious_patterns"]["risk_level"] == "high":
            results["recommendations"].extend([
                "Proceed with caution",
                "Verify the website's authenticity",
                "Avoid entering sensitive information"
            ])
        formatted_response = PrettyJSONResponse.format(results)
        cache[cache_key] = formatted_response
        send_telegram_notification("url", url, formatted_response)
        return formatted_response
    except requests.Timeout:
        logger.error(f"Timeout checking URL: {url}")
        return PrettyJSONResponse.format({
            "error": "Request timeout",
            "message": "The security check took too long. Please try again."
        })
    except requests.RequestException as e:
        logger.error(f"Error checking URL {url}: {e}")
        return PrettyJSONResponse.format({
            "error": "API error",
            "message": str(e)
        })

def analyze_ip_address(ip_address: str) -> Dict:
    """
    Comprehensive IP address analysis with VirusTotal integration
    Returns the exact structure required by the frontend
    """
    if not is_valid_ip(ip_address):
        return {
            "status": "error",
            "error": "Invalid IP address format",
            "message": "Please provide a valid IPv4 address"
        }
    
    try:
        # Get current timestamp in ISO format
        timestamp = datetime.now().isoformat() + "Z"
        
        # Perform all analysis components
        ip_details = get_ip_geolocation(ip_address)
        risk_assessment = get_ip_risk_assessment(ip_address)
        technical_details = get_technical_details(ip_address)
        virustotal_data = get_virustotal_analysis(ip_address)
        recommendations = generate_recommendations({
            "ip_details": ip_details,
            "risk_assessment": risk_assessment,
            "virustotal": virustotal_data
        })
        
        # Generate summary
        virustotal_summary = generate_virustotal_summary(virustotal_data, ip_address)
        
        # Construct the exact response structure required
        result = {
            "status": "success",
            "timestamp": timestamp,
            "data": {
                "ip_details": ip_details,
                "risk_assessment": risk_assessment,
                "technical_details": technical_details,
                "virustotal": virustotal_data,
                "virustotal_summary": virustotal_summary,
                "recommendations": recommendations
            }
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error in comprehensive IP analysis for {ip_address}: {e}")
        return {
            "status": "error",
            "error": "Analysis failed",
            "message": str(e),
            "timestamp": datetime.now().isoformat() + "Z"
        }

def get_ip_geolocation(ip_address: str) -> Dict:
    """Get IP geolocation information using multiple sources"""
    try:
        # Primary source: AbuseIPDB (already integrated)
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        # Fallback geolocation using ipapi.co (free tier)
        fallback_data = {}
        try:
            fallback_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if fallback_response.status_code == 200:
                fallback_data = fallback_response.json()
        except:
            pass
        
        return {
            "address": ip_address,
            "domain": data.get("domain") or fallback_data.get("reverse", ""),
            "isp": data.get("isp") or fallback_data.get("isp", "Unknown"),
            "location": {
                "city": data.get("city") or fallback_data.get("city", "Unknown"),
                "region": data.get("region") or fallback_data.get("regionName", "Unknown"),
                "country": data.get("countryName") or fallback_data.get("country", "Unknown"),
                "country_code": data.get("countryCode") or fallback_data.get("countryCode", "Unknown")
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting geolocation for {ip_address}: {e}")
        return {
            "address": ip_address,
            "domain": "Unknown",
            "isp": "Unknown",
            "location": {
                "city": "Unknown",
                "region": "Unknown",
                "country": "Unknown",
                "country_code": "Unknown"
            }
        }

def get_ip_risk_assessment(ip_address: str) -> Dict:
    """Calculate IP risk assessment using multiple threat intelligence sources"""
    try:
        # Primary source: AbuseIPDB
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        # Calculate risk level
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        
        if abuse_score > 75 or total_reports > 50:
            risk_level = "High"
        elif abuse_score > 50 or total_reports > 20:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Determine categories based on reports
        categories = []
        if abuse_score > 75:
            categories.extend(["malware", "phishing"])
        if total_reports > 30:
            categories.append("botnet")
        if data.get("isTor", False):
            categories.append("tor_exit_node")
        if data.get("isPublic", False) and abuse_score > 25:
            categories.append("public_proxy")
        
        if not categories:
            categories = ["clean"]
        
        return {
            "risk_level": risk_level,
            "confidence_score": abuse_score,
            "total_reports": total_reports,
            "last_reported": data.get("lastReportedAt") or datetime.now().isoformat() + "Z",
            "categories": categories
        }
        
    except Exception as e:
        logger.error(f"Error getting risk assessment for {ip_address}: {e}")
        return {
            "risk_level": "Unknown",
            "confidence_score": 0,
            "total_reports": 0,
            "last_reported": datetime.now().isoformat() + "Z",
            "categories": ["unknown"]
        }

def get_technical_details(ip_address: str) -> Dict:
    """Get technical details about the IP address"""
    try:
        # Get ASN and technical information
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        # Check if it's a TOR exit node
        is_tor = data.get("isTor", False)
        
        # Check if it's a public IP
        is_public = data.get("isPublic", True)  # Most IPs are public
        
        # Determine usage type
        usage_type = data.get("usageType", "Unknown")
        if not usage_type or usage_type == "Unknown":
            if is_tor:
                usage_type = "TOR Exit Node"
            elif data.get("abuseConfidenceScore", 0) > 75:
                usage_type = "Malicious"
            else:
                usage_type = "ISP"
        
        return {
            "as_name": data.get("asnName", "Unknown"),
            "asn": data.get("asn", "Unknown"),
            "is_public": is_public,
            "is_tor": is_tor,
            "usage_type": usage_type,
            "organization": data.get("isp", "Unknown")
        }
        
    except Exception as e:
        logger.error(f"Error getting technical details for {ip_address}: {e}")
        return {
            "as_name": "Unknown",
            "asn": "Unknown",
            "is_public": True,
            "is_tor": False,
            "usage_type": "Unknown",
            "organization": "Unknown"
        }

def get_virustotal_analysis(ip_address: str) -> Dict:
    """Get VirusTotal analysis for IP address"""
    try:
        # Check if API key is valid
        if not VIRUSTOTAL_API_KEY or len(VIRUSTOTAL_API_KEY) < 10:
            return get_fallback_virustotal_result("Invalid VirusTotal API key")
        
        # VirusTotal IP endpoint
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return process_virustotal_ip_report(data)
        elif response.status_code == 429:
            return get_fallback_virustotal_result("Rate limit exceeded - please try again later")
        elif response.status_code == 401:
            return get_fallback_virustotal_result("Unauthorized - check your VirusTotal API key")
        elif response.status_code == 404:
            return get_fallback_virustotal_result("IP address not found in VirusTotal database")
        else:
            return get_fallback_virustotal_result(f"VirusTotal API error: {response.status_code}")
            
    except requests.exceptions.Timeout:
        return get_fallback_virustotal_result("VirusTotal API timeout")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting VirusTotal analysis for IP {ip_address}: {e}")
        return get_fallback_virustotal_result(f"Network error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in VirusTotal IP analysis: {e}")
        return get_fallback_virustotal_result(f"Unexpected error: {str(e)}")

def process_virustotal_ip_report(report: Dict) -> Dict:
    """Process VirusTotal IP report and calculate risk score"""
    try:
        attributes = report.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        # Extract counts
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total_engines = sum(stats.values()) if stats else 0
        
        # Calculate risk score (0-100)
        if total_engines == 0:
            risk_score = 0
        else:
            # Weight malicious detections more heavily
            risk_score = min(100, int((malicious * 3 + suspicious * 2) / total_engines * 100))
        
        # Determine risk level
        if risk_score >= 75:
            risk_level = "HIGH"
        elif risk_score >= 50:
            risk_level = "MEDIUM"
        elif risk_score >= 25:
            risk_level = "LOW"
        else:
            risk_level = "VERY_LOW"
        
        # Get additional metadata
        reputation = attributes.get('reputation', 0)
        analysis_date = attributes.get('last_analysis_date')
        
        return {
            "risk_assessment": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "detection_ratio": f"{malicious + suspicious}/{total_engines}" if total_engines > 0 else "0/0",
                "total_engines": total_engines
            },
            "metadata": {
                "reputation": reputation,
                "file_type": "IP Address",
                "analysis_date": analysis_date
            },
            "data": {
                "attributes": {
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "total": total_engines
                    },
                    "results": attributes.get('last_analysis_results', {})
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Error processing VirusTotal IP report: {e}")
        return get_fallback_virustotal_result(f"Failed to process VirusTotal report: {str(e)}")

def generate_virustotal_summary(virustotal_data: Dict, ip_address: str) -> str:
    """Generate human-readable summary of VirusTotal analysis"""
    try:
        if not virustotal_data or 'risk_assessment' not in virustotal_data:
            return f"No VirusTotal data available for IP {ip_address}"
        
        risk_assessment = virustotal_data['risk_assessment']
        malicious_count = risk_assessment.get('malicious_count', 0)
        total_engines = risk_assessment.get('total_engines', 0)
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        
        if total_engines == 0:
            return f"IP {ip_address} has not been analyzed by any security engines."
        
        if malicious_count == 0:
            return f"IP {ip_address} has been analyzed by {total_engines} security engines and appears to be clean."
        else:
            detection_ratio = risk_assessment.get('detection_ratio', '0/0')
            return f"IP {ip_address} has been flagged by {detection_ratio} security engines as potentially malicious (Risk Level: {risk_level})."
            
    except Exception as e:
        logger.error(f"Error generating VirusTotal summary: {e}")
        return f"Unable to generate summary for IP {ip_address}"

def generate_recommendations(data: Dict) -> List[str]:
    """Generate security recommendations based on analysis results"""
    recommendations = []
    
    try:
        risk_level = data.get("risk_assessment", {}).get("risk_level", "Unknown")
        virustotal_risk = data.get("virustotal", {}).get("risk_assessment", {}).get("risk_level", "UNKNOWN")
        
        # High risk recommendations
        if risk_level == "High" or virustotal_risk == "HIGH":
            recommendations.extend([
                "Block this IP address immediately in your firewall",
                "Investigate recent connections from this IP address",
                "Report this IP to your security team for further analysis",
                "Monitor network traffic for suspicious activity patterns",
                "Check if any systems have been compromised"
            ])
        # Medium risk recommendations
        elif risk_level == "Medium" or virustotal_risk == "MEDIUM":
            recommendations.extend([
                "Monitor this IP address for further suspicious activity",
                "Consider adding this IP to your watchlist",
                "Verify if this IP is associated with legitimate services you use",
                "Implement additional monitoring for connections from this IP"
            ])
        # Low risk recommendations
        elif risk_level == "Low" or virustotal_risk == "LOW":
            recommendations.extend([
                "Continue monitoring this IP address for any changes in behavior",
                "Consider this IP as potentially safe but maintain vigilance"
            ])
        else:
            recommendations.append("Unable to determine risk level - proceed with caution")
        
        # Add specific recommendations based on categories
        categories = data.get("risk_assessment", {}).get("categories", [])
        if "tor_exit_node" in categories:
            recommendations.append("This IP is a TOR exit node - consider blocking if not needed for legitimate purposes")
        if "public_proxy" in categories:
            recommendations.append("This IP appears to be a public proxy - verify legitimacy before allowing access")
        if "botnet" in categories:
            recommendations.append("This IP is associated with botnet activity - immediate blocking recommended")
        
        # Add VirusTotal specific recommendations
        if virustotal_risk == "HIGH":
            recommendations.append("IP flagged by multiple security engines - high confidence in malicious nature")
        elif virustotal_risk == "MEDIUM":
            recommendations.append("IP shows suspicious behavior patterns - monitor closely")
        
        # Ensure we have at least some recommendations
        if not recommendations:
            recommendations = [
                "Continue monitoring this IP address",
                "Verify legitimacy if this IP is associated with your network"
            ]
        
        return recommendations[:5]  # Limit to 5 recommendations
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        return [
            "Unable to generate specific recommendations",
            "Proceed with caution and monitor for suspicious activity"
        ]

def get_fallback_virustotal_result(error_message: str) -> Dict:
    """Provide fallback result when VirusTotal analysis fails"""
    return {
        "risk_assessment": {
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "malicious_count": 0,
            "suspicious_count": 0,
            "detection_ratio": "0/0",
            "total_engines": 0
        },
        "metadata": {
            "reputation": 0,
            "file_type": "IP Address",
            "analysis_date": None
        },
        "data": {
            "attributes": {
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "total": 0
                },
                "results": {}
            }
        },
        "error": error_message
    }

# PCAP Analysis Endpoint
@app.route("/api/analyze-pcap", methods=["POST"])
@limiter.limit("5 per minute")
def analyze_pcap():
    try:
        if 'file' not in request.files:
            return jsonify(PrettyJSONResponse.format({
                "error": "No file provided",
                "message": "Please upload a PCAP file"
            })), 400

        file = request.files['file']
        if not file.filename or not file.filename.endswith(('.pcap', '.cap', '.pcapng')):
            return jsonify(PrettyJSONResponse.format({
                "error": "Invalid file type",
                "message": "Only .pcap, .cap, or .pcapng files are supported"
            })), 400

        upload_dir = os.path.join(os.getcwd(), "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, file.filename)
        file.save(file_path)

        report = AnalysisReport(VIRUSTOTAL_API_KEY)
        file_info = report.analyze_file(file_path)

        if "error" in file_info:
            return jsonify(PrettyJSONResponse.format({
                "error": "Analysis failed",
                "message": file_info["error"]
            })), 500

        # Generate VirusTotal summary
        virustotal_summary = report.get_virustotal_summary(file_info.get("virustotal", {}))
        
        result = {
            "metadata": file_info.get("metadata", {}),
            "virustotal": file_info.get("virustotal", {}),
            "virustotal_summary": virustotal_summary,
            "pcap_analysis": file_info.get("pcap_analysis", {}),
            "chart_base64": file_info.get("chart_base64", "")
        }
        formatted_response = PrettyJSONResponse.format(result)
        send_telegram_notification("pcap", file.filename, formatted_response)
        return jsonify(formatted_response)
    except Exception as e:
        logger.error(f"Error in PCAP analysis: {e}")
        return jsonify(PrettyJSONResponse.format({
            "error": "Server error",
            "message": str(e)
        })), 500

# Chat Endpoint
@app.route("/api/chat", methods=["POST"])
@limiter.limit("10 per minute")
def api_chat():
    try:
        data = request.get_json()
        message = data.get("message", "").strip()
        if not message:
            return jsonify(PrettyJSONResponse.format({"error": "Message is required"})), 400
        
        logger.info(f"Processing chat message: {message}")
        
        # Prepare the prompt with system instructions
        system_instruction = "You are CyberRegis Assistant, a cybersecurity expert. Provide accurate, concise, and well-structured answers about cyber threats, scan results, or security best practices. Use simple Markdown for formatting: use bullet points (`-`) for lists, avoid excessive bolding (`**`), and use headings (`##`) sparingly."
        full_prompt = f"{system_instruction}\n\nUser question: {message}"
        
        # Call Gemini API
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": GEMINI_API_KEY
        }
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": full_prompt
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 512
            }
        }
        
        response = requests.post(GEMINI_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        
        response_data = response.json()
        
        # Extract the response text from Gemini API response
        if "candidates" in response_data and len(response_data["candidates"]) > 0:
            ai_response = response_data["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            raise Exception("No response from Gemini API")
        
        result = {"response": ai_response}
        formatted_response = PrettyJSONResponse.format(result)
        send_telegram_notification("chat", message, formatted_response)
        return jsonify(formatted_response)
    except requests.RequestException as e:
        logger.error(f"Error in chat endpoint (API request): {e}")
        error_message = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                error_message = error_detail.get("error", {}).get("message", str(e))
            except:
                error_message = e.response.text if hasattr(e.response, 'text') else str(e)
        return jsonify(PrettyJSONResponse.format({
            "error": "Chat processing failed",
            "message": error_message
        })), 500
    except Exception as e:
        logger.error(f"Error in chat endpoint: {e}")
        return jsonify(PrettyJSONResponse.format({
            "error": "Chat processing failed",
            "message": str(e)
        })), 500

# URL Check Endpoint
@app.route("/api/check-url", methods=["POST"])
@limiter.limit("20 per minute")
def api_check_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400
            
        url = data.get("url", "").strip()
        if not url:
            return jsonify({
                "status": "error",
                "message": "URL is required"
            }), 400
            
        print(f"Processing URL check for: {url}")
        
        try:
            result = check_url_safety(url)
            print(f"URL check completed successfully for: {url}")
            return jsonify(result)
        except Exception as url_error:
            print(f"Error in check_url_safety: {url_error}")
            print(f"Traceback: {traceback.format_exc()}")
            return jsonify({
                "status": "error",
                "message": f"URL safety check failed: {str(url_error)}"
            }), 500
            
    except Exception as e:
        print(f"Error in check-url endpoint: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "status": "error",
            "message": f"URL check failed: {str(e)}"
        }), 500

# IP Check Endpoint
@app.route("/api/check-ip", methods=["POST"])
@limiter.limit("20 per minute")
def api_check_ip():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "error": "No data provided",
                "message": "Please provide IP address data"
            }), 400
            
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({
                "status": "error",
                "error": "IP address required",
                "message": "Please provide an IP address to analyze"
            }), 400
        
        # Validate IP format
        if not is_valid_ip(ip):
            return jsonify({
                "status": "error",
                "error": "Invalid IP format",
                "message": "Please provide a valid IPv4 address (e.g., 192.168.1.1)"
            }), 400
        
        logger.info(f"Starting comprehensive IP analysis for: {ip}")
        
        # Perform comprehensive analysis
        result = analyze_ip_address(ip)
        
        # Check if analysis was successful
        if result.get("status") == "error":
            logger.error(f"IP analysis failed for {ip}: {result.get('error')}")
            return jsonify(result), 500
        
        # Send Telegram notification
        try:
            send_telegram_notification("ip", ip, result)
        except Exception as telegram_error:
            logger.warning(f"Failed to send Telegram notification: {telegram_error}")
        
        logger.info(f"IP analysis completed successfully for: {ip}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in check-ip endpoint: {e}")
        return jsonify({
            "status": "error",
            "error": "Internal server error",
            "message": "IP analysis failed due to server error",
            "timestamp": datetime.now().isoformat() + "Z"
        }), 500

# Domain Analysis Endpoint
@app.route('/api/analyze-domain', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_domain():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({
                'status': 'error',
                'message': 'Domain is required'
            }), 400
        
        # Initialize the reconnaissance class
        recon = all_functions()
        
        # Collect all domain information
        domain_info = {
            'domain': domain,
            'whois': {},
            'dns_records': {},
            'ssl_info': {},
            'security_features': {},
            'subdomains': [],
            'geolocation': {}
        }
        
        recommendations = []
        
        # WHOIS Information
        try:
            whois_data = recon.perform_whois_lookup(domain)
            if whois_data and isinstance(whois_data, list):
                whois_info = {}
                for item in whois_data:
                    field = item.get('Field', '').lower()
                    value = item.get('Value', '')
                    if 'registrar' in field:
                        whois_info['registrar'] = value
                    elif 'created' in field or 'creation' in field:
                        whois_info['creation_date'] = value
                    elif 'expires' in field or 'expiration' in field:
                        whois_info['expiration_date'] = value
                    elif 'registrant' in field:
                        whois_info['registrant'] = value
                    elif 'country' in field:
                        whois_info['country'] = value
                    elif 'name servers' in field:
                        whois_info['name_servers'] = value.split(', ')
                domain_info['whois'] = whois_info
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")
        
        # DNS Records
        try:
            dns_data = recon.get_dns_records(domain)
            if dns_data and isinstance(dns_data, list):
                dns_records = {}
                for item in dns_data:
                    record_type = item.get('Field', '')
                    value = item.get('Value', '')
                    if value and 'No records found' not in value and 'Error' not in value:
                        dns_records[record_type] = value.split(', ')
                domain_info['dns_records'] = dns_records
        except Exception as e:
            print(f"DNS lookup failed: {e}")
        
        # TXT Records (separate call)
        try:
            txt_data = recon.get_txt_records(domain)
            if txt_data and isinstance(txt_data, list):
                txt_records = []
                for item in txt_data:
                    if item.get('Field') == 'TXT Records':
                        txt_records.append(item.get('Value', ''))
                if txt_records:
                    domain_info['dns_records']['TXT'] = txt_records
        except Exception as e:
            print(f"TXT records lookup failed: {e}")
        
        # SSL Certificate Information
        try:
            ssl_data = recon.get_ssl_chain_details(domain)
            if ssl_data and isinstance(ssl_data, list):
                ssl_info = {}
                for item in ssl_data:
                    field = item.get('Field', '').lower()
                    value = item.get('Value', '')
                    if 'issuer' in field:
                        ssl_info['issuer'] = value
                    elif 'subject' in field:
                        ssl_info['subject'] = value
                    elif 'valid from' in field:
                        ssl_info['valid_from'] = value
                    elif 'valid until' in field:
                        ssl_info['valid_until'] = value
                    elif 'days until expiry' in field:
                        try:
                            ssl_info['days_until_expiry'] = int(value)
                        except:
                            ssl_info['days_until_expiry'] = value
                ssl_info['valid'] = 'true' if ssl_info else 'false'
                domain_info['ssl_info'] = ssl_info
        except Exception as e:
            print(f"SSL certificate lookup failed: {e}")
            domain_info['ssl_info'] = {'valid': 'false'}
        
        # SSL Labs Grade
        try:
            ssl_labs_data = recon.fetch_ssl_labs_report_table(domain)
            if ssl_labs_data and isinstance(ssl_labs_data, list):
                for item in ssl_labs_data:
                    if item.get('Field') == 'Grade':
                        domain_info['ssl_info']['grade'] = item.get('Value', 'N/A')
                        break
        except Exception as e:
            print(f"SSL Labs lookup failed: {e}")
        
        # Security Features
        security_features = {}
        
        # DNSSEC
        try:
            dnssec_data = recon.check_dnssec(domain)
            dnssec_enabled = False
            if dnssec_data and isinstance(dnssec_data, list):
                for item in dnssec_data:
                    if 'keys found' in item.get('Value', '').lower():
                        dnssec_enabled = True
                        break
            security_features['dnssec'] = dnssec_enabled
        except Exception as e:
            security_features['dnssec'] = False
        
        # DMARC
        try:
            dmarc_data = recon.get_dmarc_record(domain)
            dmarc_record = None
            if dmarc_data and isinstance(dmarc_data, list):
                for item in dmarc_data:
                    if item.get('Field') == 'DMARC Record' and 'No DMARC' not in item.get('Value', ''):
                        dmarc_record = item.get('Value', '')
                        break
            security_features['dmarc'] = dmarc_record or 'Not configured'
        except Exception as e:
            security_features['dmarc'] = 'Not configured'
        
        # WAF Detection
        try:
            waf_data = recon.detect_waf(domain)
            waf_detected = 'None'
            if waf_data and isinstance(waf_data, list):
                for item in waf_data:
                    value = item.get('Value', '')
                    if 'No WAF found' not in value:
                        waf_detected = value
                        break
            security_features['waf_detected'] = waf_detected
        except Exception as e:
            security_features['waf_detected'] = 'Unknown'
        
        # robots.txt
        try:
            robots_data = recon.check_robots_txt(domain)
            robots_present = False
            robots_url = None
            if robots_data and isinstance(robots_data, list):
                for item in robots_data:
                    if (item.get('Field') != 'Error' and item.get('Field') != 'Not Found'
                            and item.get('Value') != 'Not Found'):
                        robots_present = True
                        robots_url = f"http://{domain}/robots.txt"
                        break
            security_features['robots_txt'] = {
                'present': robots_present,
                'url': robots_url
            }
        except Exception as e:
            security_features['robots_txt'] = {
                'present': False,
                'url': None
            }
        
        # security.txt
        try:
            security_txt_data = recon.check_security_txt(domain)
            security_txt_present = False
            security_txt_url = None
            if security_txt_data and isinstance(security_txt_data, list):
                for item in security_txt_data:
                    if (item.get('Field') != 'Error' and item.get('Field') != 'Not Found'
                            and item.get('Value') != 'Not Found'):
                        security_txt_present = True
                        # Check both common locations for security.txt
                        try:
                            response = requests.get(f'http://{domain}/.well-known/security.txt', timeout=5)
                            if response.status_code == 200:
                                security_txt_url = f"http://{domain}/.well-known/security.txt"
                            else:
                                response = requests.get(f'http://{domain}/security.txt', timeout=5)
                                if response.status_code == 200:
                                    security_txt_url = f"http://{domain}/security.txt"
                        except:
                            # If we can't determine the exact URL, provide both options
                            security_txt_url = f"http://{domain}/.well-known/security.txt"
                        break
            security_features['security_txt'] = {
                'present': security_txt_present,
                'url': security_txt_url
            }
        except Exception as e:
            security_features['security_txt'] = {
                'present': False,
                'url': None
            }
        
        domain_info['security_features'] = security_features
        
        # Subdomains
        try:
            subdomain_data = recon.fetch_subdomains(domain)
            subdomains = []
            if subdomain_data and isinstance(subdomain_data, list):
                for item in subdomain_data:
                    if item.get('Field') == 'Subdomain':
                        subdomain = item.get('Value', '')
                        if subdomain and subdomain not in subdomains:
                            subdomains.append(subdomain)
            domain_info['subdomains'] = subdomains[:50]  # Limit to 50 subdomains
        except Exception as e:
            print(f"Subdomain lookup failed: {e}")
            domain_info['subdomains'] = []
        
        # Geolocation (from A record)
        try:
            geo_data = recon.get_ip_info_from_a_record(domain)
            if geo_data and isinstance(geo_data, list):
                geo_info = {}
                for item in geo_data:
                    field = item.get('Field', '').lower()
                    value = item.get('Value', '')
                    if 'ip address' in field:
                        geo_info['ip'] = value
                    elif 'country' in field:
                        geo_info['country'] = value
                    elif 'city' in field:
                        geo_info['city'] = value
                    elif 'isp' in field:
                        geo_info['isp'] = value
                    elif 'organization' in field:
                        geo_info['organization'] = value
                domain_info['geolocation'] = geo_info
        except Exception as e:
            print(f"Geolocation lookup failed: {e}")
        
        # Generate recommendations
        if not security_features.get('dnssec', False):
            recommendations.append("Enable DNSSEC for enhanced DNS security")
        
        if security_features.get('dmarc') == 'Not configured':
            recommendations.append("Configure DMARC policy for email security")
        
        days_until_expiry = domain_info['ssl_info'].get('days_until_expiry', 0)
        try:
            days_until_expiry = int(days_until_expiry)
        except (ValueError, TypeError):
            days_until_expiry = 0
        if days_until_expiry < 30:
            recommendations.append("SSL certificate expires soon - plan for renewal")
        
        if not security_features.get('security_txt', {}).get('present', False):
            recommendations.append("Consider adding security.txt for vulnerability disclosure")
        else:
            recommendations.append(f"security.txt is present - review at: {security_features['security_txt']['url']}")
        
        if not security_features.get('robots_txt', {}).get('present', False):
            recommendations.append("Consider adding robots.txt for web crawler guidance")
        else:
            recommendations.append(f"robots.txt is present - review at: {security_features['robots_txt']['url']}")
        
        if security_features.get('waf_detected') == 'None':
            recommendations.append("Consider implementing a Web Application Firewall (WAF)")
        
        response_data = {
            'status': 'success',
            'domain_info': domain_info,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Domain analysis error: {e}")
        print(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': f'Domain analysis failed: {str(e)}'
        }), 500

# Security File Content Endpoint
@app.route('/api/security-file-content', methods=['POST'])
@limiter.limit("20 per minute")
def get_security_file_content():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
            
        file_type = data.get('file_type', '').strip()  # 'robots' or 'security'
        domain = data.get('domain', '').strip()
        
        if not file_type or not domain:
            return jsonify({
                'status': 'error',
                'message': 'Both file_type and domain are required'
            }), 400
        
        if file_type not in ['robots', 'security']:
            return jsonify({
                'status': 'error',
                'message': 'file_type must be either "robots" or "security"'
            }), 400
        
        print(f"Fetching {file_type}.txt for domain: {domain}")
        
        try:
            if file_type == 'robots':
                url = f"http://{domain}/robots.txt"
                print(f"Attempting to fetch robots.txt from: {url}")
                
                # Try to fetch robots.txt
                try:
                    response = requests.get(url, timeout=15, allow_redirects=True)
                    print(f"Robots.txt response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        file_content = response.text
                        content_type = response.headers.get('content-type', '').lower()
                        
                        # Verify it's actual robots.txt content, not an HTML error page
                        if 'text/html' in content_type and not any(
                            kw in file_content.lower() for kw in ['user-agent:', 'disallow:', 'allow:', 'sitemap:']
                        ):
                            return jsonify({
                                'status': 'error',
                                'message': f'robots.txt not found at {url} (server returned HTML instead)',
                                'http_status': 404,
                                'domain': domain
                            }), 404
                        
                        file_info = {
                            'domain': domain,
                            'file_type': file_type,
                            'url': url,
                            'content': file_content,
                            'content_length': len(file_content),
                            'last_modified': response.headers.get('last-modified', 'Unknown'),
                            'content_type': response.headers.get('content-type', 'text/plain')
                        }
                        
                        return jsonify({
                            'status': 'success',
                            'file_info': file_info,
                            'timestamp': datetime.now().isoformat()
                        })
                    else:
                        # Return specific error for different status codes
                        if response.status_code == 404:
                            return jsonify({
                                'status': 'error',
                                'message': f'robots.txt not found at {url}',
                                'http_status': 404,
                                'domain': domain
                            }), 404
                        elif response.status_code == 503:
                            return jsonify({
                                'status': 'error',
                                'message': f'Service temporarily unavailable for {domain}',
                                'http_status': 503,
                                'domain': domain,
                                'note': 'The server may be down or overloaded'
                            }), 503
                        else:
                            return jsonify({
                                'status': 'error',
                                'message': f'HTTP {response.status_code} when fetching robots.txt',
                                'http_status': response.status_code,
                                'domain': domain
                            }), 400
                            
                except requests.exceptions.Timeout:
                    return jsonify({
                        'status': 'error',
                        'message': f'Timeout while fetching robots.txt from {domain}',
                        'domain': domain,
                        'note': 'The server took too long to respond'
                    }), 408
                except requests.exceptions.ConnectionError:
                    return jsonify({
                        'status': 'error',
                        'message': f'Connection error while fetching robots.txt from {domain}',
                        'domain': domain,
                        'note': 'The server may be unreachable'
                    }), 503
                except requests.exceptions.RequestException as e:
                    return jsonify({
                        'status': 'error',
                        'message': f'Request failed: {str(e)}',
                        'domain': domain
                    }), 500
                    
            else:  # security.txt
                print(f"Attempting to fetch security.txt for domain: {domain}")
                
                # Try .well-known first, then root
                urls_to_try = [
                    f'http://{domain}/.well-known/security.txt',
                    f'http://{domain}/security.txt'
                ]
                
                for url in urls_to_try:
                    try:
                        print(f"Trying: {url}")
                        response = requests.get(url, timeout=15, allow_redirects=True)
                        print(f"Security.txt response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            file_content = response.text
                            file_info = {
                                'domain': domain,
                                'file_type': file_type,
                                'url': url,
                                'content': file_content,
                                'content_length': len(file_content),
                                'last_modified': response.headers.get('last-modified', 'Unknown'),
                                'content_type': response.headers.get('content-type', 'text/plain')
                            }
                            
                            return jsonify({
                                'status': 'success',
                                'file_info': file_info,
                                'timestamp': datetime.now().isoformat()
                            })
                        elif response.status_code == 404:
                            print(f"404 for {url}, trying next location...")
                            continue
                        else:
                            print(f"HTTP {response.status_code} for {url}")
                            continue
                            
                    except requests.exceptions.Timeout:
                        print(f"Timeout for {url}")
                        continue
                    except requests.exceptions.ConnectionError:
                        print(f"Connection error for {url}")
                        continue
                    except requests.exceptions.RequestException as e:
                        print(f"Request error for {url}: {e}")
                        continue
                
                # If we get here, security.txt wasn't found
                return jsonify({
                    'status': 'error',
                    'message': 'security.txt not found in common locations',
                    'domain': domain,
                    'locations_tried': urls_to_try
                }), 404
            
        except Exception as e:
            print(f"Unexpected error in file fetching: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            return jsonify({
                'status': 'error',
                'message': f'Unexpected error while fetching {file_type}.txt: {str(e)}',
                'domain': domain
            }), 500
            
    except Exception as e:
        print(f"Security file content endpoint error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'status': 'error',
            'message': f'Security file content retrieval failed: {str(e)}'
        }), 500

# Port Scanner Endpoint
@app.route('/api/scan-ports', methods=['POST'])
def scan_ports():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({
                'status': 'error',
                'message': 'Target is required'
            }), 400
        
        # Initialize the reconnaissance class
        recon = all_functions()
        
        # Use the enhanced port scanner
        result = recon.scan_ports_detailed(target)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Port scan error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Port scan failed: {str(e)}'
        }), 500

# Vulnerability Scanner Endpoint
@app.route('/api/vulnerability-scan', methods=['POST'])
def vulnerability_scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({
                'status': 'error',
                'message': 'Target is required'
            }), 400
        
        recon = all_functions()
        result = recon.vulnerability_scan(target)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Vulnerability scan error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Vulnerability scan failed: {str(e)}'
        }), 500

# SSL/TLS Analyzer Endpoint
@app.route('/api/ssl-analysis', methods=['POST'])
def ssl_analysis():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({
                'status': 'error',
                'message': 'Domain is required'
            }), 400
        
        recon = all_functions()
        result = recon.ssl_detailed_analysis(domain)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"SSL analysis error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'SSL analysis failed: {str(e)}'
        }), 500

# Security Headers Scanner Endpoint
@app.route('/api/security-headers', methods=['POST'])
def security_headers():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        recon = all_functions()
        result = recon.security_headers_scan(url)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Security headers scan error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Security headers scan failed: {str(e)}'
        }), 500

# Email Security Scanner Endpoint
@app.route('/api/email-security', methods=['POST'])
def email_security():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({
                'status': 'error',
                'message': 'Domain is required'
            }), 400
        
        recon = all_functions()
        result = recon.email_security_deep_scan(domain)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Email security scan error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Email security scan failed: {str(e)}'
        }), 500

# Monitoring Results Endpoint
@app.route('/api/monitoring-results', methods=['GET'])
def get_monitoring_results():
    try:
        # Get current system status and recent activity
        monitoring_data = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "server_status": "running",
            "uptime": "active",
            "recent_scans": [],
            "system_info": {
                "python_version": "3.x",
                "flask_version": "2.x",
                "active_endpoints": [
                    "/api/check-url",
                    "/api/check-ip", 
                    "/api/analyze-domain",
                    "/api/scan-ports",
                    "/api/vulnerability-scan",
                    "/api/ssl-analysis",
                    "/api/security-headers",
                    "/api/email-security",
                    "/api/analyze-pcap",
                    "/api/chat"
                ]
            }
        }
        
        return jsonify(monitoring_data)
        
    except Exception as e:
        print(f"Monitoring results error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get monitoring results: {str(e)}'
        }), 500

# Health Check Endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "CyberRegis Security Scanner",
            "version": "1.0.0"
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

# Test Endpoint for CORS verification
@app.route('/api/test', methods=['GET', 'POST', 'OPTIONS'])
def test_endpoint():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        return response
    
    return jsonify({
        "status": "success",
        "message": "CORS test successful",
        "method": request.method,
        "timestamp": datetime.now().isoformat()
    })

# Simple URL Test Endpoint
@app.route('/api/test-url', methods=['POST'])
def test_url_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
            
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"status": "error", "message": "URL is required"}), 400
        
        # Basic URL validation test
        if not is_valid_url(url):
            return jsonify({
                "status": "error", 
                "message": "Invalid URL format",
                "url": url
            }), 400
        
        return jsonify({
            "status": "success",
            "message": "URL validation successful",
            "url": url,
            "parsed": get_url_details(url),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Test URL endpoint error: {e}")
        return jsonify({
            "status": "error",
            "message": f"Test failed: {str(e)}"
        }), 500

# Test Security File Content Endpoint
@app.route('/api/test-security-file', methods=['POST'])
def test_security_file_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
            
        file_type = data.get('file_type', '').strip()
        domain = data.get('domain', '').strip()
        
        if not file_type or not domain:
            return jsonify({"status": "error", "message": "Both file_type and domain are required"}), 400
        
        if file_type not in ['robots', 'security']:
            return jsonify({"status": "error", "message": "file_type must be 'robots' or 'security'"}), 400
        
        print(f"Testing {file_type}.txt fetch for domain: {domain}")
        
        # Test basic connectivity first
        try:
            test_response = requests.get(f"http://{domain}", timeout=5)
            connectivity_status = f"Domain reachable (HTTP {test_response.status_code})"
        except requests.exceptions.Timeout:
            connectivity_status = "Domain timeout"
        except requests.exceptions.ConnectionError:
            connectivity_status = "Domain connection failed"
        except Exception as e:
            connectivity_status = f"Domain test error: {str(e)}"
        
        # Test the specific file
        if file_type == 'robots':
            test_url = f"http://{domain}/robots.txt"
        else:
            test_url = f"http://{domain}/.well-known/security.txt"
        
        try:
            file_response = requests.get(test_url, timeout=10)
            file_status = f"File accessible (HTTP {file_response.status_code})"
            if file_response.status_code == 200:
                file_content_preview = file_response.text[:100] + "..." if len(file_response.text) > 100 else file_response.text
            else:
                file_content_preview = "Not accessible"
        except Exception as e:
            file_status = f"File test error: {str(e)}"
            file_content_preview = "Error occurred"
        
        return jsonify({
            "status": "success",
            "message": "Security file test completed",
            "domain": domain,
            "file_type": file_type,
            "connectivity": connectivity_status,
            "file_status": file_status,
            "file_content_preview": file_content_preview,
            "test_url": test_url,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Test security file endpoint error: {e}")
        return jsonify({
            "status": "error",
            "message": f"Test failed: {str(e)}"
        }), 500

# System Status Endpoint
@app.route('/api/status', methods=['GET'])
def system_status():
    try:
        import psutil
        import os
        
        # Get system information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        status_data = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "system": {
                "cpu_usage": f"{cpu_percent}%",
                "memory_usage": f"{memory.percent}%",
                "memory_available": f"{memory.available // (1024**3):.1f} GB",
                "disk_usage": f"{disk.percent}%",
                "disk_free": f"{disk.free // (1024**3):.1f} GB"
            },
            "process": {
                "pid": os.getpid(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            }
        }
        
        return jsonify(status_data)
        
    except ImportError:
        # psutil not available, return basic status
        return jsonify({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "message": "Basic status available. Install psutil for detailed system metrics.",
            "system": "psutil not available"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Status check failed: {str(e)}"
        }), 500
    
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))  # Use Railway's dynamic port if available
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)