"""
Telegram Notification Service
"""
import requests
from datetime import datetime
from typing import Dict
from app.config import Config
from app.utils.logger import setup_logger

logger = setup_logger()


class TelegramService:
    """Service for sending Telegram notifications"""
    
    def __init__(self):
        self.bot_token = Config.TELEGRAM_BOT_TOKEN
        self.chat_id = Config.TELEGRAM_CHAT_ID
    
    def send_notification(self, check_type: str, subject: str, result: Dict, force: bool = False) -> bool:
        """
        Send notification to Telegram (only for important events)
        
        Args:
            check_type: Type of check (url, ip, chat, pcap)
            subject: Subject of the notification
            result: Result data dictionary
            force: Force send even if not critical (default: False)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Only send notifications for important events
            if not force and not self._should_notify(check_type, result):
                return False
            
            message = self._format_message(check_type, subject, result)
            
            api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
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
    
    def _should_notify(self, check_type: str, result: Dict) -> bool:
        """Determine if notification should be sent based on severity"""
        if check_type == "url":
            # Only notify for malicious URLs or high-risk
            is_malicious = result.get("data", {}).get("threat_analysis", {}).get("is_malicious", False)
            risk_level = result.get("data", {}).get("additional_checks", {}).get("domain_analysis", {}).get("risk_level", "low")
            return is_malicious or risk_level in ["high", "medium"]
        
        elif check_type == "ip":
            # Only notify for high/medium risk IPs
            risk_level = result.get("data", {}).get("risk_assessment", {}).get("risk_level", "Low")
            confidence_score = result.get("data", {}).get("risk_assessment", {}).get("confidence_score", 0)
            return risk_level in ["High", "Medium"] or confidence_score > 50
        
        elif check_type == "pcap":
            # Only notify if malicious files found
            stats = result.get('data', {}).get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return malicious > 0 or suspicious > 0
        
        elif check_type == "chat":
            # Don't notify for chat interactions (too frequent)
            return False
        
        return False
    
    def _format_message(self, check_type: str, subject: str, result: Dict) -> str:
        """Format concise message based on check type"""
        timestamp = result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        if check_type == "url":
            is_malicious = result.get("data", {}).get("threat_analysis", {}).get("is_malicious", False)
            risk_level = result.get("data", {}).get("additional_checks", {}).get("domain_analysis", {}).get("risk_level", "unknown")
            threats_found = result.get("data", {}).get("threat_analysis", {}).get("threats_found", 0)
            
            message = f"🔍 *Threat Detected*\n\n" if is_malicious else f"⚠️ *High Risk URL*\n\n"
            message += f"`{subject[:50]}{'...' if len(subject) > 50 else ''}`\n"
            message += f"Risk: *{risk_level.upper()}*\n"
            if is_malicious:
                message += f"Threats: *{threats_found}*\n"
            message += f"\n_{timestamp}_"
                    
        elif check_type == "ip":
            risk_score = result.get("data", {}).get("risk_assessment", {}).get("confidence_score", 0)
            risk_level = result.get("data", {}).get("risk_assessment", {}).get("risk_level", "Unknown")
            country = result.get("data", {}).get("ip_details", {}).get("location", {}).get("country", "Unknown")
            total_reports = result.get("data", {}).get("risk_assessment", {}).get("total_reports", 0)
            
            message = f"🖥️ *Suspicious IP*\n\n"
            message += f"`{subject}`\n"
            message += f"Risk: *{risk_level}* ({risk_score}%)\n"
            message += f"Reports: {total_reports} | {country}\n"
            message += f"\n_{timestamp}_"
            
        elif check_type == "pcap":
            stats = result.get('data', {}).get('virustotal', {}).get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            message = f"📊 *Malware Detected*\n\n" if malicious > 0 else f"⚠️ *Suspicious File*\n\n"
            message += f"File: `{subject[:40]}{'...' if len(subject) > 40 else ''}`\n"
            if malicious > 0:
                message += f"🚨 *{malicious} malicious* detections\n"
            if suspicious > 0:
                message += f"⚠️ {suspicious} suspicious\n"
            message += f"\n_{timestamp}_"
            
        else:
            message = f"⚙️ *Security Alert*\n\n"
            message += f"Type: {check_type}\n"
            message += f"`{subject[:50]}`\n"
            message += f"\n_{timestamp}_"
        
        return message

