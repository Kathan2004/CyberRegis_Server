import matplotlib
matplotlib.use('Agg')
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import requests
import os
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
from all_functions import all_functions

app = Flask(__name__)
CORS(app, 
     origins=["http://localhost:3000", "http://127.0.0.1:3000", "https://yourdomain.com"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Preflight handler for CORS
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
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
        self.headers = {"x-apikey": self.api_key}

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
            with open(file_path, "rb") as file:
                response = requests.post(url, headers=self.headers, files={"file": file})
                if response.status_code == 200:
                    file_id = response.json().get("data", {}).get("id")
                    return self.get_virustotal_report(file_id)
                else:
                    raise Exception(f"VirusTotal API error: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error during VirusTotal analysis: {e}")
            return {}

    def get_virustotal_report(self, file_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        try:
            for _ in range(5):  # Retry up to 5 times
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    report = response.json()
                    if report.get('data', {}).get('attributes', {}).get('status') == 'completed':
                        return report
                    time.sleep(5)  # Wait before retrying
                else:
                    raise Exception(f"Failed to fetch report: {response.status_code} - {response.text}")
            raise Exception("VirusTotal analysis not completed in time")
        except Exception as e:
            logger.error(f"Error fetching VirusTotal report: {e}")
            return {}

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
            risk_score = result.get("data", {}).get("risk_assessment", {}).get("confidence_score", 0)
            risk_level = result.get("data", {}).get("risk_assessment", {}).get("risk_level", "Unknown")
            country = result.get("data", {}).get("ip_details", {}).get("location", {}).get("country", "Unknown")
            message = f"🖥️ *IP Reputation Check*\n\n"
            message += f"IP Address: `{subject}`\n"
            message += f"Risk Level: {risk_level.upper()}\n"
            message += f"Confidence Score: {risk_score}/100\n"
            message += f"Country: {country}\n"
        elif check_type == "chat":
            message = f"💬 *Chat Interaction*\n\n"
            message += f"User Query: `{subject}`\n"
            message += f"Response: {result.get('data', {}).get('response', 'No response')[:200]}...\n"
            message += f"\n🕒 *{result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}*"
        elif check_type == "pcap":
            message = f"📊 *PCAP Analysis*\n\n"
            message += f"File: `{subject}`\n"
            stats = result.get('data', {}).get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {})
            message += f"Malicious: {stats.get('malicious', 0)}\n"
            message += f"Suspicious: {stats.get('suspicious', 0)}\n"
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
    try:
        response = requests.get(url, verify=True, timeout=5)
        return {
            "valid": True,
            "status_code": response.status_code
        }
    except requests.exceptions.SSLError:
        return {
            "valid": False,
            "error": "SSL certificate validation failed"
        }
    except requests.RequestException as e:
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

def check_ip_reputation(ip: str) -> Dict:
    if not is_valid_ip(ip):
        return PrettyJSONResponse.format({
            "error": "Invalid IP address format",
            "suggestions": [
                "Enter a valid IPv4 address (e.g., 192.168.1.1)",
                "Ensure each segment is between 0 and 255",
                "Avoid extra spaces or special characters"
            ]
        })
    cache_key = f"ip:{ip}"
    if cache_key in cache:
        logger.info(f"Cache hit for IP: {ip}")
        return cache[cache_key]
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        risk_level = "Low"
        if data.get("abuseConfidenceScore", 0) > 75:
            risk_level = "High"
        elif data.get("abuseConfidenceScore", 0) > 50:
            risk_level = "Medium"
        result = {
            "ip_details": {
                "address": data.get("ipAddress"),
                "location": {
                    "country": data.get("countryName"),
                    "country_code": data.get("countryCode"),
                    "city": data.get("city"),
                    "region": data.get("region")
                },
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "hostname": data.get("hostnames", [])
            },
            "risk_assessment": {
                "confidence_score": data.get("abuseConfidenceScore", 0),
                "risk_level": risk_level,
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "whitelisted": data.get("isWhitelisted", False)
            },
            "technical_details": {
                "usage_type": data.get("usageType"),
                "asn": data.get("asn"),
                "as_name": data.get("asnName"),
                "is_public": data.get("isPublic"),
                "is_tor": data.get("isTor", False)
            },
            "recommendations": []
        }
        if result["risk_assessment"]["risk_level"] == "High":
            result["recommendations"].extend([
                "Block this IP in your firewall",
                "Monitor network traffic for suspicious activity",
                "Report to your security team"
            ])
        elif result["risk_assessment"]["risk_level"] == "Medium":
            result["recommendations"].extend([
                "Monitor this IP for further activity",
                "Consider adding to watchlist",
                "Verify legitimacy if associated with your network"
            ])
        formatted_response = PrettyJSONResponse.format(result)
        cache[cache_key] = formatted_response
        send_telegram_notification("ip", ip, formatted_response)
        return formatted_response
    except requests.RequestException as e:
        logger.error(f"Error checking IP {ip}: {e}")
        return PrettyJSONResponse.format({
            "error": "API error",
            "message": str(e)
        })

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
        if not file.filename.endswith(('.pcap', '.cap', '.pcapng')):
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

        result = {
            "metadata": file_info.get("metadata", {}),
            "virustotal": file_info.get("virustotal", {}),
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
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify(PrettyJSONResponse.format({"error": "IP address is required"})), 400
        result = check_ip_reputation(ip)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in check-ip endpoint: {e}")
        return jsonify(PrettyJSONResponse.format({
            "error": "IP check failed",
            "message": str(e)
        })), 500

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
                ssl_info['valid'] = True if ssl_info else False
                domain_info['ssl_info'] = ssl_info
        except Exception as e:
            print(f"SSL certificate lookup failed: {e}")
            domain_info['ssl_info'] = {'valid': False}
        
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
                    if item.get('Field') != 'Error' and item.get('Field') != 'Not Found':
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
                    if item.get('Field') != 'Error' and item.get('Field') != 'Not Found':
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
        
        if domain_info['ssl_info'].get('days_until_expiry', 0) < 30:
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
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
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
    port = int(os.environ.get('PORT', 4000))  # Use Railway's dynamic port if available
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)