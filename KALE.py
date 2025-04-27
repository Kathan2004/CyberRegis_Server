import matplotlib
matplotlib.use('Agg')
from flask import Flask, request, jsonify
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
from together import Together
import pyshark
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
CORS(app)

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
TOGETHER_API_KEY = "25a657eebe965da06d4f4bf87722ed90dffa5e80c835db643c6c20e8d4d095ec"
VIRUSTOTAL_API_KEY = "5a9219f6d9b2761fcb99552cd745603e1ffd8a0c265a468a61d1ab8a4fb5fa99"

# Initialize Together AI client
together_client = Together(api_key=TOGETHER_API_KEY)

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

def analyze_domain(domain: str) -> Dict:
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
    if suspicious_patterns["special_chars"]:
        risk_score += 2
        risk_factors.append("Contains special characters")
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
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
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
                "domain_analysis": analyze_domain(urlparse(url).netloc)
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
        
        response = together_client.chat.completions.create(
            model="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            messages=[
                {
                    "role": "system",
                    "content": "You are CyberRegis Assistant, a cybersecurity expert. Provide accurate, concise, and well-structured answers about cyber threats, scan results, or security best practices. Use simple Markdown for formatting: use bullet points (`-`) for lists, avoid excessive bolding (`**`), and use headings (`##`) sparingly."
                },
                {"role": "user", "content": message}
            ],
            max_tokens=512,
            temperature=0.7
        )
        
        ai_response = response.choices[0].message.content.strip()
        result = {"response": ai_response}
        formatted_response = PrettyJSONResponse.format(result)
        send_telegram_notification("chat", message, formatted_response)
        return jsonify(formatted_response)
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
        url = data.get("url", "").strip()
        if not url:
            return jsonify(PrettyJSONResponse.format({"error": "URL is required"})), 400
        result = check_url_safety(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in check-url endpoint: {e}")
        return jsonify(PrettyJSONResponse.format({
            "error": "URL check failed",
            "message": str(e)
        })), 500

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


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 4000))  # Use Railway's dynamic port if available
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)