"""
URL Security Service
"""
import re
import urllib.parse
import requests
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse
import whois

from app.config import Config
from app.utils.validators import is_valid_url
from app.utils.logger import setup_logger
from app.models.response_formatter import PrettyJSONResponse

logger = setup_logger()


class URLService:
    """Service for URL security checks"""
    
    def __init__(self, cache=None):
        self.api_key = Config.SAFE_BROWSING_KEY
        self.cache = cache
    
    def check_url_safety(self, url: str) -> Dict:
        """Check URL safety using Google Safe Browsing API and additional checks"""
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
        if self.cache and cache_key in self.cache:
            logger.info(f"Cache hit for URL: {url}")
            return self.cache[cache_key]
        
        try:
            if not self.api_key or self.api_key == "":
                logger.warning("Google Safe Browsing API key not configured")
                results = self._basic_url_check(url)
            else:
                results = self._full_url_check(url)
            
            formatted_response = PrettyJSONResponse.format(results)
            if self.cache:
                self.cache[cache_key] = formatted_response
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
    
    def _basic_url_check(self, url: str) -> Dict:
        """Perform basic URL check without Google Safe Browsing API"""
        results = {
            "url_analysis": {
                "input_url": url,
                "parsed_details": self._get_url_details(url),
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
                "ssl_security": self._check_ssl_certificate(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"},
                "suspicious_patterns": self._check_suspicious_keywords(url),
                "domain_analysis": self._analyze_domain_security(urlparse(url).netloc)
            },
            "recommendations": []
        }
        
        if results["additional_checks"]["suspicious_patterns"]["risk_level"] == "high":
            results["recommendations"].extend([
                "Proceed with caution",
                "Verify the website's authenticity",
                "Avoid entering sensitive information"
            ])
        
        return results
    
    def _full_url_check(self, url: str) -> Dict:
        """Perform full URL check with Google Safe Browsing API"""
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
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
        
        logger.info(f"Calling Google Safe Browsing API for: {url}")
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        results = {
            "url_analysis": {
                "input_url": url,
                "parsed_details": self._get_url_details(url),
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
                "ssl_security": self._check_ssl_certificate(url) if url.startswith("https://") else {"valid": False, "error": "Not HTTPS"},
                "suspicious_patterns": self._check_suspicious_keywords(url),
                "domain_analysis": self._analyze_domain_security(urlparse(url).netloc)
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
        
        return results
    
    def _get_url_details(self, url: str) -> Dict:
        """Get URL parsing details"""
        parsed_url = urlparse(url)
        return {
            "scheme": parsed_url.scheme,
            "domain": parsed_url.netloc,
            "path": parsed_url.path,
            "query_params": dict(urllib.parse.parse_qsl(parsed_url.query)),
            "fragment": parsed_url.fragment
        }
    
    def _check_suspicious_keywords(self, url: str) -> Dict:
        """Check for suspicious keywords in URL"""
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
    
    def _check_ssl_certificate(self, url: str) -> Dict:
        """Check SSL certificate validity"""
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
    
    def _get_whois_data(self, domain: str) -> Dict:
        """Get WHOIS data for domain"""
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
    
    def _analyze_domain_security(self, domain: str) -> Dict:
        """Analyze domain security patterns"""
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
            "whois": self._get_whois_data(domain)
        }

