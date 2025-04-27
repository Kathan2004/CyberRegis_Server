
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
        logger.error(f"Failed to send Telegram notification: {str(e)}")
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
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
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
        return formatted_response
    except requests.Timeout:
        logger.error(f"Timeout checking URL: {url}")
        return PrettyJSONResponse.format({
            "error": "Request timeout",
            "message": "The security check took too long. Please try again."
        })
    except requests.RequestException as e:
        logger.error(f"Error checking URL {url}: {str(e)}")
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
        return formatted_response
    except requests.RequestException as e:
        logger.error(f"Error checking IP {ip}: {str(e)}")
        return PrettyJSONResponse.format({
            "error": "API error",
            "message": str(e)
        })

# New Chat Endpoint with Preprocessing
@app.route("/api/chat", methods=["POST"])
@limiter.limit("10 per minute")
def api_chat():
    try:
        data = request.get_json()
        message = data.get("message", "").strip()
        if not message:
            return jsonify(PrettyJSONResponse.format({"error": "Message is required"})), 400
        
        logger.info(f"Processing chat message: {message}")
        
        # Call Together AI API
        response = together_client.chat.completions.create(
            model="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            messages=[
                {
                    "role": "system",
                    "content": "You are CyberRegis Assistant, a cybersecurity expert. Provide accurate and concise answers about cyber threats, scan results, or security best practices. Use minimal Markdown formatting, avoid excessive bolding, and structure responses clearly with bullet points or paragraphs for readability."
                },
                {"role": "user", "content": message}
            ],
            max_tokens=500,
            temperature=0.7
        )
        
        bot_response = response.choices[0].message.content
        
        # Optional preprocessing to clean up response
        # Remove excessive Markdown bolding and normalize lists
        bot_response = re.sub(r'\*\*(.*?)\*\*', r'\1', bot_response)  # Remove **bold**
        bot_response = re.sub(r'^\d+\.\s*', '• ', bot_response, flags=re.MULTILINE)  # Convert numbered lists to bullets
        
        result = PrettyJSONResponse.format({
            "message": message,
            "response": bot_response,
            "timestamp": datetime.now().isoformat()
        })
        
        # Send Telegram notification for chat interaction
        send_telegram_notification("chat", message, result)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Chat error: {str(e)}")
        return jsonify(PrettyJSONResponse.format({"error": "Internal server error", "message": str(e)})), 500

# API Endpoints
@app.route("/api/status", methods=["GET"])
@limiter.limit("10 per minute")
def api_status():
    status = {
        "google_safe_browsing": False,
        "abuseipdb": False,
        "telegram": False,
        "together_ai": False
    }
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "security-checker", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "https://example.com"}]
            }
        }
        response = requests.post(api_url, json=payload, timeout=5)
        status["google_safe_browsing"] = response.status_code == 200
    except Exception as e:
        logger.error(f"Google Safe Browsing API test failed: {str(e)}")
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=5)
        status["abuseipdb"] = response.status_code == 200
    except Exception as e:
        logger.error(f"AbuseIPDB API test failed: {str(e)}")
    try:
        api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe"
        response = requests.get(api_url, timeout=5)
        status["telegram"] = response.status_code == 200
    except Exception as e:
        logger.error(f"Telegram API test failed: {str(e)}")
    try:
        # Test Together AI API with a simple request
        response = together_client.chat.completions.create(
            model="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            messages=[{"role": "user", "content": "Test"}],
            max_tokens=10
        )
        status["together_ai"] = bool(response.choices)
    except Exception as e:
        logger.error(f"Together AI API test failed: {str(e)}")
    return jsonify(PrettyJSONResponse.format({
        "status": "operational" if all(status.values()) else "partial",
        "apis": status,
        "timestamp": datetime.now().isoformat()
    }))

@app.route("/api/check-url", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_url():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        if not url:
            return jsonify(PrettyJSONResponse.format({"error": "URL is required"})), 400
        logger.info(f"Checking URL: {url}")
        result = check_url_safety(url)
        send_telegram_notification("url", url, result)
        return jsonify(result)
    except Exception as e:
        logger.error(f"URL check error: {str(e)}")
        return jsonify(PrettyJSONResponse.format({"error": "Internal server error", "message": str(e)})), 500

@app.route("/api/check-ip", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_ip():
    try:
        data = request.get_json()
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify(PrettyJSONResponse.format({"error": "IP address is required"})), 400
        logger.info(f"Checking IP: {ip}")
        result = check_ip_reputation(ip)
        send_telegram_notification("ip", ip, result)
        return jsonify(result)
    except Exception as e:
        logger.error(f"IP check error: {str(e)}")
        return jsonify(PrettyJSONResponse.format({"error": "Internal server error", "message": str(e)})), 500

# Function to Check if Port is Available
def is_port_available(host: str = "127.0.0.1", port: int = 4000) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result != 0  # Port is available if connection fails
    except Exception as e:
        logger.error(f"Error checking port availability: {str(e)}")
        return False

# Function to Check if Server is Running
def is_server_running(host: str = "127.0.0.1", port: int = 4000) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

# Function to Check API Status with Retry
def check_api_status(max_retries: int = 5, delay: float = 1.0) -> Dict:
    for attempt in range(max_retries):
        if is_server_running():
            try:
                response = requests.get("http://127.0.0.1:4000/api/status", timeout=5)
                response.raise_for_status()
                json_data = response.json()
                logger.info(f"API status check successful: {json_data}")
                return json_data
            except requests.exceptions.RequestException as e:
                logger.error(f"API status check failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if 'response' in locals():
                    logger.error(f"Response content: {response.text}")
        else:
            logger.warning(f"Server not running (attempt {attempt + 1}/{max_retries})")
        if attempt < max_retries - 1:
            time.sleep(delay)
    logger.error("Failed to connect to server after multiple attempts")
    return {"status": "error", "message": "Failed to connect to server"}

if __name__ == "__main__":
    logger.info("Starting Security Checker API...")
    # Check if port is available
    if not is_port_available():
        logger.error("Port 4000 is already in use. Please free the port or use a different one.")
        exit(1)
    # Start Flask server in a background thread
    def run_server():
        app.run(host="127.0.0.1", port=4000, debug=False)  # Debug=False to ensure JSON responses
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    # Wait briefly for server to start
    time.sleep(1)
    logger.info("Verifying API keys...")
    api_status = check_api_status()
    if api_status.get("status") != "operational":
        logger.warning("Some APIs are not responding correctly:")
        for api, status in api_status.get("data", {}).get("apis", {}).items():
            logger.warning(f"- {api}: {'OK' if status else 'Failed'}")
    else:
        logger.info("All APIs verified successfully!")
    logger.info("Server is running on http://127.0.0.1:4000")
    # Keep the main thread alive to allow the server to run
    try:
        server_thread.join()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
```

### Updated Frontend Code (Home.tsx)

<xaiArtifact artifact_id="5da9fa54-3bd5-4979-92ba-267ac4b00ea4" artifact_version_id="d648e8fa-28de-4bc2-84aa-9f71fb2adb78" title="Home.tsx" contentType="text/typescript">
```tsx
"use client";

import { useState, useEffect, useRef } from "react";
import { Shield, Globe, Network, AlertTriangle, Eye, Activity, FileText, BarChart4, Upload, FileUp, MessageSquare } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// Define interface for API responses from KALE.py
interface ScanResult {
  data?: {
    url_analysis?: { input_url: string };
    threat_analysis?: { is_malicious: boolean };
    additional_checks?: {
      domain_analysis?: { risk_level: string };
      ssl_security?: { valid: boolean };
      suspicious_patterns?: { risk_level: string };
    };
    protocols?: {
      [protocol: string]: number;
    };
    metadata?: {
      [key: string]: string | number;
    };
    suspicious_ips?: string[];
    potential_threats?: { type: string; severity: string; source?: string; domain?: string }[];
    recommendations?: string[];
    message?: string; // For chat
    response?: string; // For chat
  };
  formatted?: string;
  status: "success" | "error";
  timestamp?: string;
  message?: string; // For errors
}

// Interface for chatbot messages
interface ChatMessage {
  id: number;
  text: string;
  isUser: boolean;
  timestamp: string;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [ip, setIp] = useState("");
  const [urlResults, setUrlResults] = useState<ScanResult | null>(null);
  const [ipResults, setIpResults] = useState<ScanResult | null>(null);
  const [logResults, setLogResults] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const checkUrl = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:4000/api/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setUrlResults(data);
    } catch (error) {
      setUrlResults({
        status: "error",
        message: "Failed to check URL. Please try again.",
      });
      console.error("Error checking URL:", error);
    }
    setLoading(false);
  };

  const checkIp = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:4000/api/check-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      const data = await response.json();
      setIpResults(data);
    } catch (error) {
      setIpResults({
        status: "error",
        message: "Failed to check IP. Please try again.",
      });
      console.error("Error checking IP:", error);
    }
    setLoading(false);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleFileUploadClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const analyzeNetworkLog = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!selectedFile) {
      setLogResults({
        status: "error",
        message: "Please select a file to analyze.",
      });
      return;
    }

    setLoading(true);
    try {
      // Simulated response since KALE.py doesn't have /api/analyze-pcap
      setTimeout(() => {
        setLogResults({
          status: "success",
          message: `Analysis completed for ${selectedFile.name}`,
          data: {
            metadata: {
              Filename: selectedFile.name,
              "Size (bytes)": selectedFile.size,
              "File Type": selectedFile.name.split(".").pop() || "",
            },
            protocols: {
              TCP: 156,
              UDP: 42,
              HTTP: 78,
              DNS: 23,
              TLS: 45,
            },
            suspicious_ips: ["192.168.1.5", "10.0.0.12"],
            potential_threats: [
              { type: "Port Scan", severity: "Medium", source: "192.168.1.5" },
              { type: "Unusual DNS Query", severity: "Low", domain: "suspicious-domain.com" },
            ],
          },
        });
        setLoading(false);
      }, 2000);
    } catch (error) {
      setLogResults({
        status: "error",
        message: "Failed to analyze network log. Please try again.",
      });
      console.error("Error analyzing network log:", error);
      setLoading(false);
    }
  };

  const formatResults = (results: ScanResult | null): JSX.Element => {
    if (!results) return <></>;
    if (results.status === "error") {
      return <p>{results.message || "An error occurred."}</p>;
    }
    if (results.formatted) {
      return (
        <div>
          {results.data && (
            <div className="mb-4">
              <p>
                <strong>Status:</strong>{" "}
                {results.data.threat_analysis?.is_malicious ? "Malicious" : "Safe"}
              </p>
              <p>
                <strong>Risk Level:</strong>{" "}
                {results.data.additional_checks?.domain_analysis?.risk_level || "Unknown"}
              </p>
              {results.data.recommendations?.length ? (
                <div>
                  <strong>Recommendations:</strong>
                  <ul className="list-disc pl-5">
                    {results.data.recommendations.map((rec, index) => (
                      <li key={index}>{rec}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          )}
          <details>
            <summary className="cursor-pointer text-primary">View Full Details</summary>
            <div className="bg-black p-4 rounded-md">
              <style jsx>{`
                .bg-black pre {
                  background: transparent !important;
                  color: #4ade80;
                  padding: 0;
                  border-radius: 0;
                }
              `}</style>
              <div dangerouslySetInnerHTML={{ __html: results.formatted }} />
            </div>
          </details>
        </div>
      );
    }
    return <pre>{JSON.stringify(results, null, 2)}</pre>;
  };

  const handleChatSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const newUserMessage: ChatMessage = {
      id: chatMessages.length + 1,
      text: chatInput,
      isUser: true,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatMessages((prev) => [...prev, newUserMessage]);
    setChatInput("");
    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:4000/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: chatInput }),
      });
      const data = await response.json();

      if (data.status === "error") {
        throw new Error(data.message || "Failed to get response");
      }

      const botResponse: ChatMessage = {
        id: chatMessages.length + 2,
        text: data.data.response || "No response received.",
        isUser: false,
        timestamp: new Date().toLocaleTimeString(),
      };

      setChatMessages((prev) => [...prev, botResponse]);
    } catch (error) {
      const errorMessage: ChatMessage = {
        id: chatMessages.length + 2,
        text: "Sorry, I couldn't process your request. Please try again.",
        isUser: false,
        timestamp: new Date().toLocaleTimeString(),
      };
      setChatMessages((prev) => [...prev, errorMessage]);
      console.error("Error in chat:", error);
    } finally {
      setLoading(false);
    }
  };

  // Auto-scroll to bottom of chat
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages]);

  return (
    <div
      className="min-h-screen bg-background"
      style={{
        backgroundImage: "radial-gradient(circle at 50% 50%, hsl(var(--background)) 0%, hsl(var(--card)) 100%)",
      }}
    >
      <header className="border-b border-border/40 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <div className="relative">
                <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full"></div>
                <Shield className="w-8 h-8 text-primary relative z-10" />
              </div>
              <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
                CyberRegis
              </span>
            </div>
            <nav className="flex items-center space-x-6">
              <Link href="/" className="text-primary transition-colors">
                Dashboard
              </Link>
              <Link href="/resources" className="text-foreground hover:text-primary transition-colors">
                Resources
              </Link>
              <div className="flex items-center space-x-1">
                <Activity className="w-4 h-4 text-green-500 animate-pulse" />
                <span className="text-sm text-muted-foreground">Active</span>
              </div>
            </nav>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto p-8">
        <div className="flex items-center justify-between mb-12">
          <div>
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
              CyberRegis
            </h1>
            <p className="text-muted-foreground">Advanced Threat Detection System</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          <Card className="p-6 border-primary/20 bg-card/50 backdrop-blur-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Eye className="w-5 h-5 text-primary" />
              <h3 className="text-lg font-semibold">Security Status</h3>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Threat Level</span>
                <Badge variant="secondary" className="bg-green-500/20 text-green-500">
                  Low
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Active Scans</span>
                <span className="text-sm">{loading ? "1" : "0"}</span>
              </div>
            </div>
          </Card>
        </div>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <Tabs defaultValue="url" className="p-6">
            <TabsList className="grid w-full grid-cols-3 lg:w-[400px] mb-6">
              <TabsTrigger value="url" className="data-[state=active]:bg-primary/20">
                <Globe className="w-4 h-4 mr-2" />
                URL
              </TabsTrigger>
              <TabsTrigger value="ip" className="data-[state=active]:bg-primary/20">
                <Network className="w-4 h-4 mr-2" />
                IP
              </TabsTrigger>
              <TabsTrigger value="network" className="data-[state=active]:bg-primary/20">
                <BarChart4 className="w-4 h-4 mr-2" />
                Network Log
              </TabsTrigger>
            </TabsList>

            <TabsContent value="url" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Phishing URL Scanner</h2>
                <p className="text-sm text-muted-foreground">Analyze URLs for potential phishing threats</p>
              </div>
              <Separator />
              <form onSubmit={checkUrl} className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    type="url"
                    placeholder="Enter website URL"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                    className="bg-background/50"
                  />
                  <Button
                    type="submit"
                    disabled={loading}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>
                {urlResults && (
                  <Alert
                    className={`bg-${
                      urlResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${urlResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>{formatResults(urlResults)}</AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="ip" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">IP Reputation Scanner</h2>
                <p className="text-sm text-muted-foreground">Check IP addresses for malicious activity</p>
              </div>
              <Separator />
              <form onSubmit={checkIp} className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    type="text"
                    placeholder="Enter IP address"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    required
                    pattern="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    className="bg-background/50"
                  />
                  <Button
                    type="submit"
                    disabled={loading}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>
                {ipResults && (
                  <Alert
                    className={`bg-${
                      ipResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${ipResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>{formatResults(ipResults)}</AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="network" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Network Log Analysis</h2>
                <p className="text-sm text-muted-foreground">
                  Upload PCAP files for comprehensive network traffic analysis
                </p>
              </div>
              <Separator />
              <form onSubmit={analyzeNetworkLog} className="space-y-4">
                <div className="border-2 border-dashed border-border/50 rounded-lg p-8 text-center bg-background/30">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    accept=".pcap,.cap,.pcapng"
                    className="hidden"
                  />
                  <div className="space-y-4">
                    <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                      <FileUp className="w-6 h-6 text-primary" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="text-lg font-medium">Upload PCAP File</h3>
                      <p className="text-sm text-muted-foreground">
                        Drag and drop your PCAP file here, or click to browse
                      </p>
                    </div>
                    {selectedFile ? (
                      <div className="bg-primary/5 p-3 rounded-md inline-flex items-center space-x-2">
                        <FileText className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">{selectedFile.name}</span>
                        <Badge variant="outline" className="bg-primary/10 text-xs">
                          {(selectedFile.size / 1024).toFixed(1)} KB
                        </Badge>
                      </div>
                    ) : null}
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleFileUploadClick}
                      className="bg-secondary/50"
                    >
                      Select File
                    </Button>
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    disabled={loading || !selectedFile}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Analyzing..." : "Analyze Network Log"}
                  </Button>
                </div>
                {logResults && (
                  <Alert
                    className={`bg-${
                      logResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${logResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-2">
                        <p
                          className={`text-${
                            logResults.status === "error" ? "destructive" : "primary"
                          }`}
                        >
                          {logResults.message}
                        </p>
                        {logResults.data && (
                          <div className="mt-4 space-y-4">
                            {logResults.data.metadata && (
                              <div className="space-y-1">
                                <h4 className="text-sm font-semibold">File Information</h4>
                                <div className="text-xs space-y-1">
                                  {Object.entries(logResults.data.metadata).map(([key, value]) => (
                                    <div key={key} className="flex justify-between">
                                      <span className="text-muted-foreground">{key}:</span>
                                      <span>{String(value)}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {logResults.data.protocols && (
                              <div className="space-y-1">
                                <h4 className="text-sm font-semibold">Protocol Distribution</h4>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  {Object.entries(logResults.data.protocols).map(
                                    ([protocol, count]) => (
                                      <div key={protocol} className="flex justify-between">
                                        <span className="text-muted-foreground">{protocol}:</span>
                                        <span>{String(count)}</span>
                                      </div>
                                    )
                                  )}
                                </div>
                              </div>
                            )}
                            {logResults.data.potential_threats && (
                              <div className="space-y-1">
                                <h4 className="text-sm font-semibold">Potential Threats</h4>
                                <div className="space-y-2">
                                  {logResults.data.potential_threats.map((threat: any, index: number) => (
                                    <div key={index} className="bg-card/80 p-2 rounded-md text-xs">
                                      <div className="flex items-center justify-between">
                                        <span className="font-medium">{threat.type}</span>
                                        <Badge
                                          className={
                                            threat.severity === "High"
                                              ? "bg-red-500/10 text-red-500"
                                              : threat.severity === "Medium"
                                              ? "bg-orange-500/10 text-orange-500"
                                              : "bg-yellow-500/10 text-yellow-500"
                                          }
                                        >
                                          {threat.severity}
                                        </Badge>
                                      </div>
                                      <div className="mt-1 text-muted-foreground">
                                        {threat.source && <div>Source: {threat.source}</div>}
                                        {threat.domain && <div>Domain: {threat.domain}</div>}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>
          </Tabs>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm p-6">
          <div className="space-y-6">
            <div className="space-y-2">
              <h2 className="text-2xl font-semibold flex items-center">
                <MessageSquare className="w-6 h-6 text-primary mr-2" />
                CyberRegis Assistant
              </h2>
              <p className="text-sm text-muted-foreground">
                # Ask questions about cyber threats, scan results, or security best practices
              </p>
            </div>
            <Separator />
          </div>
            <ScrollArea className="h-[300px] w-full rounded-md bg-background/30 p-4" ref={chatScrollRef}>
              {chatMessages.length === 0 ? (
                <div className="text-center text-muted-foreground text-sm">
                  Start a conversation with the CyberRegis Assistant
                </div>
              ) : (
                chatMessages.map((message) => (
                  <div
                    key={message.id}
                    className={`mb-4 flex ${message.isUser ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[70%] rounded-lg p-3 ${
                        message.isUser
                          ? "bg-primary/20 text-primary-foreground"
                          : "bg-secondary/50 text-foreground"
                      }`}
                    >
                      {message.isUser ? (
                        <p className="text-sm">{message.text}</p>
                      ) : (
                        <ReactMarkdown
                          remarkPlugins={[remarkGfm]}
                          className="text-sm prose prose-invert max-w-none"
                          components={{
                            h1: ({ node, ...props }) => <h1 className="text-lg font-semibold mt-2 mb-1" {...props} />,
                            h2: ({ node, ...props }) => <h2 className="text-base font-semibold mt-2 mb-1" {...props} />,
                            h3: ({ node, ...props }) => <h3 className="text-sm font-semibold mt-2 mb-1" {...props} />,
                            p: ({ node, ...props }) => <p className="mb-2" {...props} />,
                            ul: ({ node, ...props }) => <ul className="list-disc pl-4 mb-2" {...props} />,
                            ol: ({ node, ...props }) => <ol className="list-decimal pl-4 mb-2" {...props} />,
                            li: ({ node, ...props }) => <li className="mb-1" {...props} />,
                            strong: ({ node, ...props }) => <strong className="font-medium" {...props} />,
                          }}
                        >
                          {message.text}
                        </ReactMarkdown>
                      )}
                      <span className="text-xs text-muted-foreground mt-1 block">
                        {message.timestamp}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </ScrollArea>
            <form onSubmit={handleChatSubmit} className="flex space-x-2">
              <Input
                type="text"
                placeholder="Ask a question..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                className="bg-background/50"
              />
              <Button
                type="submit"
                disabled={loading || !chatInput.trim()}
                className="bg-primary hover:bg-primary/90"
              >
                {loading ? "Processing..." : "Send"}
              </Button>
            </form>
          </div>
        </Card>
      </div>
    </div>
  );
}