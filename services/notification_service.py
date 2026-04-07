"""
Notification Service
Multi-channel notifications: Telegram, webhooks, logging.
"""
import logging
import requests
from datetime import datetime
from typing import Dict
from config import get_config

logger = logging.getLogger(__name__)
cfg = get_config()


def notify(check_type: str, subject: str, result: Dict) -> bool:
    """Send notification through configured channels."""
    success = True

    # Telegram
    if cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_ID:
        try:
            _send_telegram(check_type, subject, result)
        except Exception as e:
            logger.warning(f"Telegram notification failed: {e}")
            success = False

    return success


def _send_telegram(check_type: str, subject: str, result: Dict) -> bool:
    """Format and send a Telegram notification."""
    try:
        message = _format_telegram_message(check_type, subject, result)
        api_url = f"https://api.telegram.org/bot{cfg.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": cfg.TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown",
        }
        resp = requests.post(api_url, json=payload, timeout=5)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Telegram send error: {e}")
        return False


def _format_telegram_message(check_type: str, subject: str, result: Dict) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if check_type == "url":
        data = result.get("data", {})
        is_malicious = data.get("threat_analysis", {}).get("is_malicious", False)
        risk = data.get("additional_checks", {}).get("domain_analysis", {}).get("risk_level", "unknown")
        msg = f"🔍 *URL Security Check*\n\n"
        msg += f"URL: `{subject}`\n"
        msg += f"Status: {'⚠️ MALICIOUS' if is_malicious else '✅ SAFE'}\n"
        msg += f"Risk Level: {risk.upper()}\n"

    elif check_type == "ip":
        data = result.get("data", {})
        risk = data.get("risk_assessment", {})
        vt = data.get("virustotal", {}).get("risk_assessment", {})
        msg = f"🖥️ *IP Intelligence Analysis*\n\n"
        msg += f"IP: `{subject}`\n"
        msg += f"Risk Level: {risk.get('risk_level', 'Unknown')}\n"
        msg += f"Confidence: {risk.get('confidence_score', 0)}/100\n"
        msg += f"Reports: {risk.get('total_reports', 0)}\n"
        if vt.get("risk_score", 0) > 0:
            msg += f"VT Score: {vt.get('risk_score')}/100\n"

    elif check_type == "chat":
        data = result.get("data", {})
        msg = f"💬 *AI Chat*\n\n"
        msg += f"Query: `{subject[:100]}`\n"
        response_text = data.get("response", "")[:200]
        msg += f"Response: {response_text}...\n"

    elif check_type == "pcap":
        msg = f"📊 *Network Analysis*\n\n"
        msg += f"File: `{subject}`\n"
        vt = result.get("virustotal", {}).get("risk_assessment", {})
        msg += f"VT Risk: {vt.get('risk_level', 'UNKNOWN')}\n"

    else:
        msg = f"⚙️ *Security Scan*\n\n"
        msg += f"Type: {check_type}\n"
        msg += f"Target: `{subject}`\n"

    msg += f"\n🕒 _{ts}_"
    return msg
