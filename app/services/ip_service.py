"""
IP Reputation Service
"""
import requests
from typing import Dict

from app.config import Config
from app.utils.validators import is_valid_ip
from app.utils.logger import setup_logger
from app.models.response_formatter import PrettyJSONResponse

logger = setup_logger()


class IPService:
    """Service for IP reputation checks"""
    
    def __init__(self, cache=None):
        self.api_key = Config.ABUSEIPDB_API_KEY
        self.cache = cache
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation using AbuseIPDB API"""
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
        if self.cache and cache_key in self.cache:
            logger.info(f"Cache hit for IP: {ip}")
            return self.cache[cache_key]
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.api_key,
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
            if self.cache:
                self.cache[cache_key] = formatted_response
            return formatted_response
            
        except requests.RequestException as e:
            logger.error(f"Error checking IP {ip}: {e}")
            return PrettyJSONResponse.format({
                "error": "API error",
                "message": str(e)
            })

