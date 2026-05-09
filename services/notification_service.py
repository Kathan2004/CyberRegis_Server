"""
Notification Service
Multi-channel notifications: Telegram with rich formatting + bot command handler.
"""
import logging
import threading
import requests
from datetime import datetime
from typing import Dict
from config import get_config

logger = logging.getLogger(__name__)
cfg = get_config()

# ──────────────────────────────────────────────────────
#  Outbound notifications (scan results → Telegram)
# ──────────────────────────────────────────────────────

def notify(check_type: str, subject: str, result: Dict) -> bool:
    """Send notification through configured channels."""
    success = True
    if cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_ID:
        try:
            _send_telegram(check_type, subject, result)
        except Exception as e:
            logger.warning(f"Telegram notification failed: {e}")
            success = False
    return success


def _send_telegram(check_type: str, subject: str, result: Dict) -> bool:
    try:
        message = _format_telegram_message(check_type, subject, result)
        _telegram_send(cfg.TELEGRAM_CHAT_ID, message)
        return True
    except Exception as e:
        logger.error(f"Telegram send error: {e}")
        return False


def _telegram_send(chat_id: str, text: str, parse_mode: str = "Markdown") -> dict:
    """Low-level Telegram sendMessage call. Splits long messages automatically."""
    api_url = f"https://api.telegram.org/bot{cfg.TELEGRAM_BOT_TOKEN}/sendMessage"
    # Telegram max message length is 4096 chars
    chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
    last = {}
    for chunk in chunks:
        payload = {"chat_id": chat_id, "text": chunk, "parse_mode": parse_mode}
        resp = requests.post(api_url, json=payload, timeout=10)
        resp.raise_for_status()
        last = resp.json()
    return last


def _risk_emoji(level: str) -> str:
    level = (level or "").lower()
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(level, "⚪")


def _format_telegram_message(check_type: str, subject: str, result: Dict) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if check_type == "url":
        data = result.get("data", {})
        threat = data.get("threat_analysis", {})
        ssl = data.get("additional_checks", {}).get("ssl_security", {})
        domain_a = data.get("additional_checks", {}).get("domain_analysis", {})
        risk_summary = data.get("risk_summary", {})
        http = data.get("additional_checks", {}).get("http_behavior", {})
        patterns = data.get("additional_checks", {}).get("suspicious_patterns", {})
        recs = data.get("recommendations", [])

        is_malicious = threat.get("is_malicious", False)
        overall_risk = risk_summary.get("overall_risk_level", domain_a.get("risk_level", "unknown"))
        overall_score = risk_summary.get("overall_risk_score", 0)
        emoji = _risk_emoji(overall_risk)

        msg = f"🔍 *URL Security Report*\n"
        msg += f"{'─' * 30}\n"
        msg += f"🌐 URL: `{subject}`\n"
        msg += f"{'⚠️ MALICIOUS' if is_malicious else '✅ SAFE'} — {emoji} Risk: *{overall_risk.upper()}* ({overall_score}/100)\n\n"

        msg += f"*🛡️ Threat Analysis*\n"
        msg += f"• Google Safe Browsing: {'🚨 Flagged' if is_malicious else '✅ Clean'}\n"
        threats = threat.get("threat_details", [])
        if threats:
            for t in threats[:3]:
                msg += f"  ↳ {t.get('threatType', '')} on {t.get('platformType', '')}\n"

        msg += f"\n*🔒 TLS / SSL*\n"
        msg += f"• Valid: {'✅ Yes' if ssl.get('valid') else '❌ No'}\n"
        if ssl.get("tls_version"):
            msg += f"• Version: {ssl.get('tls_version')}\n"
        if ssl.get("issuer"):
            msg += f"• Issuer: {ssl.get('issuer')}\n"
        if ssl.get("expires_in_days") is not None:
            msg += f"• Expires in: {ssl.get('expires_in_days')} days\n"

        msg += f"\n*🌍 Domain Analysis*\n"
        msg += f"• Risk Level: {_risk_emoji(domain_a.get('risk_level'))} {(domain_a.get('risk_level') or 'unknown').upper()}\n"
        flags = domain_a.get("analysis", {})
        if flags.get("suspicious_tld"):
            msg += f"• ⚠️ Suspicious TLD detected\n"
        if flags.get("has_ip_host"):
            msg += f"• ⚠️ IP address used as host\n"
        if patterns.get("matches"):
            msg += f"• ⚠️ Suspicious keywords: {', '.join(patterns['matches'][:5])}\n"

        msg += f"\n*🌐 HTTP Behavior*\n"
        msg += f"• Status: {http.get('status_code', 'N/A')}\n"
        if http.get("redirect_count", 0) > 0:
            msg += f"• Redirects: {http.get('redirect_count')}\n"
        if http.get("server"):
            msg += f"• Server: {http.get('server')}\n"
        msg += f"• HSTS: {'✅' if http.get('hsts_present') else '❌'}\n"

        if recs:
            msg += f"\n*💡 Recommendations*\n"
            for r in recs[:4]:
                text_r = r.get("text", r) if isinstance(r, dict) else str(r)
                sev = r.get("severity", "") if isinstance(r, dict) else ""
                sev_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(sev, "•")
                msg += f"{sev_emoji} {text_r}\n"

        if risk_summary.get("factors"):
            msg += f"\n*⚠️ Risk Factors*\n"
            for f in risk_summary["factors"][:4]:
                msg += f"• {f}\n"

    elif check_type == "ip":
        data = result.get("data", {})
        risk = data.get("risk_assessment", {})
        vt = data.get("virustotal", {}).get("risk_assessment", {})
        abuse = data.get("abuseipdb", {})
        tech = data.get("technical_details", {})
        ip_details = data.get("ip_details", {})
        shodan = data.get("shodan", {})
        recs = data.get("recommendations", [])

        risk_level = risk.get("risk_level", "Unknown")
        emoji = _risk_emoji(risk_level)

        msg = f"🖥️ *IP Intelligence Report*\n"
        msg += f"{'─' * 30}\n"
        msg += f"📍 IP: `{subject}`\n"
        msg += f"{emoji} Risk Level: *{risk_level}* | Confidence: {risk.get('confidence_score', 0)}/100\n\n"

        loc = ip_details.get("location", {})
        msg += f"*🌍 Geolocation*\n"
        msg += f"• Country: {loc.get('country', 'Unknown')} ({loc.get('country_code', '?')})\n"
        msg += f"• City: {loc.get('city', 'Unknown')}, {loc.get('region', '')}\n"
        msg += f"• ISP: {ip_details.get('isp', 'Unknown')}\n"
        msg += f"• ASN: {tech.get('asn', 'Unknown')} — {tech.get('as_name', '')}\n"
        msg += f"• Org: {tech.get('organization', 'Unknown')}\n"

        msg += f"\n*📊 AbuseIPDB*\n"
        msg += f"• Abuse Score: {abuse.get('abuse_confidence_score', 0)}/100\n"
        msg += f"• Total Reports: {abuse.get('total_reports', 0)}\n"
        msg += f"• Distinct Reporters: {abuse.get('num_distinct_users', 0)}\n"
        if abuse.get("last_reported_at"):
            msg += f"• Last Reported: {str(abuse.get('last_reported_at'))[:10]}\n"
        msg += f"• TOR Exit Node: {'⚠️ Yes' if abuse.get('is_tor') else '✅ No'}\n"

        msg += f"\n*🔬 VirusTotal*\n"
        msg += f"• Detection: {vt.get('detection_ratio', '0/0')}\n"
        msg += f"• Risk Score: {vt.get('risk_score', 0)}/100\n"
        msg += f"• Risk Level: {_risk_emoji(vt.get('risk_level', ''))} {vt.get('risk_level', 'UNKNOWN')}\n"

        if shodan.get("enabled") and not shodan.get("error"):
            msg += f"\n*🔭 Shodan*\n"
            ports = shodan.get("ports", [])
            if ports:
                msg += f"• Open Ports: {', '.join(str(p) for p in ports[:10])}\n"
            vulns = shodan.get("vulnerabilities", [])
            if vulns:
                msg += f"• CVEs: {', '.join(vulns[:5])}\n"

        cats = risk.get("categories", [])
        if cats and cats != ["clean"]:
            msg += f"\n*🏷️ Categories*: {', '.join(cats)}\n"

        if recs:
            msg += f"\n*💡 Recommendations*\n"
            for r in recs[:4]:
                msg += f"• {r}\n"

    elif check_type == "domain":
        data = result.get("data", {}) if "data" in result else result
        domain_info = data.get("domain_info", {})
        risk_score = data.get("risk_score", {})
        recs = data.get("recommendations", [])
        ssl = domain_info.get("ssl_info", {})
        sec = domain_info.get("security_features", {})
        whois = domain_info.get("whois", {})
        dns = domain_info.get("dns_records", {})
        geo = domain_info.get("geolocation", {})

        level = risk_score.get("level", "unknown")
        score = risk_score.get("score", 0)
        emoji = _risk_emoji(level)

        msg = f"🌐 *Domain Recon Report*\n"
        msg += f"{'─' * 30}\n"
        msg += f"🔎 Domain: `{subject}`\n"
        msg += f"{emoji} Risk: *{level.upper()}* ({score}/100)\n\n"

        msg += f"*📋 WHOIS*\n"
        msg += f"• Registrar: {whois.get('registrar', 'Unknown')}\n"
        msg += f"• Created: {whois.get('creation_date', 'Unknown')}\n"
        msg += f"• Expires: {whois.get('expiration_date', 'Unknown')}\n"
        ns = whois.get("name_servers", [])
        if ns:
            msg += f"• Name Servers: {', '.join(ns[:3])}\n"

        msg += f"\n*🔒 SSL Certificate*\n"
        msg += f"• Valid: {'✅ Yes' if ssl.get('valid') else '❌ No'}\n"
        if ssl.get("issuer"):
            msg += f"• Issuer: {ssl.get('issuer')}\n"
        if ssl.get("days_until_expiry") is not None:
            msg += f"• Expires in: {ssl.get('days_until_expiry')} days\n"
        if ssl.get("grade"):
            msg += f"• SSL Labs Grade: {ssl.get('grade')}\n"

        msg += f"\n*🛡️ Security Features*\n"
        msg += f"• DNSSEC: {'✅' if sec.get('dnssec') else '❌'}\n"
        msg += f"• DMARC: {'✅' if sec.get('dmarc') not in (None, 'Not configured') else '❌'}\n"
        msg += f"• SPF: {'✅' if sec.get('spf') not in (None, 'Not configured') else '❌'}\n"
        msg += f"• WAF: {sec.get('waf_detected', 'Unknown')}\n"
        msg += f"• robots.txt: {'✅' if sec.get('robots_txt', {}).get('present') else '❌'}\n"
        msg += f"• security.txt: {'✅' if sec.get('security_txt', {}).get('present') else '❌'}\n"

        if dns:
            msg += f"\n*📡 DNS Records*\n"
            for rtype, vals in list(dns.items())[:6]:
                vals_str = ", ".join(vals[:2]) if isinstance(vals, list) else str(vals)
                msg += f"• {rtype}: {vals_str[:60]}\n"

        if geo:
            msg += f"\n*🌍 Geolocation*\n"
            msg += f"• IP: {geo.get('ip', 'Unknown')}\n"
            msg += f"• Location: {geo.get('city', '')}, {geo.get('country', '')}\n"
            msg += f"• ISP: {geo.get('isp', 'Unknown')}\n"

        subs = domain_info.get("subdomains", [])
        if subs:
            msg += f"\n*🔗 Subdomains* ({len(subs)} found)\n"
            msg += f"{', '.join(subs[:8])}\n"

        if recs:
            msg += f"\n*💡 Recommendations*\n"
            for r in recs[:5]:
                sev = r.get("severity", "") if isinstance(r, dict) else ""
                text_r = r.get("text", r) if isinstance(r, dict) else str(r)
                sev_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(sev, "•")
                msg += f"{sev_emoji} {text_r}\n"

    elif check_type == "pcap":
        vt = result.get("virustotal", {}).get("risk_assessment", {})
        insights = result.get("network_insights", {})
        threats = result.get("potential_threats", [])
        proto = result.get("protocol_summary", {})

        level = vt.get("risk_level", "UNKNOWN")
        emoji = _risk_emoji(level)

        msg = f"📊 *PCAP Network Analysis*\n"
        msg += f"{'─' * 30}\n"
        msg += f"📁 File: `{subject}`\n"
        msg += f"{emoji} VT Risk: *{level}* | Score: {vt.get('risk_score', 0)}/100\n\n"

        msg += f"*📈 Traffic Summary*\n"
        msg += f"• Total Packets: {insights.get('total_packets', 0):,}\n"
        msg += f"• Total Bytes: {insights.get('total_bytes', 0):,}\n"
        msg += f"• Duration: {insights.get('capture_duration_seconds', 0)}s\n"
        msg += f"• Avg PPS: {insights.get('avg_packets_per_second', 0)}\n"

        top_protos = proto.get("top_protocols", [])
        if top_protos:
            msg += f"\n*🔌 Top Protocols*\n"
            for p in top_protos[:5]:
                msg += f"• {p['name']}: {p['count']:,} pkts ({p['percentage']}%)\n"

        top_src = insights.get("top_source_ips", [])
        if top_src:
            msg += f"\n*📤 Top Source IPs*\n"
            for ip in top_src[:5]:
                msg += f"• {ip['ip']}: {ip['count']:,} pkts\n"

        if threats:
            msg += f"\n*⚠️ Potential Threats*\n"
            for t in threats[:4]:
                sev_emoji = "🔴" if t.get("severity") == "high" else "🟡"
                msg += f"{sev_emoji} {t.get('type')}\n  ↳ {t.get('details', '')[:80]}\n"

        msg += f"\n*🔬 VirusTotal*\n"
        msg += f"• Detection: {vt.get('detection_ratio', '0/0')}\n"
        msg += f"• Malicious: {vt.get('malicious_count', 0)} | Suspicious: {vt.get('suspicious_count', 0)}\n"

    elif check_type == "chat":
        data = result.get("data", {})
        msg = f"💬 *AI Security Query*\n"
        msg += f"{'─' * 30}\n"
        msg += f"❓ Query: `{subject[:150]}`\n\n"
        response_text = data.get("response", "")[:500]
        msg += f"🤖 Response:\n{response_text}"
        if len(data.get("response", "")) > 500:
            msg += "...\n_(truncated)_"

    else:
        msg = f"⚙️ *Security Scan Complete*\n"
        msg += f"{'─' * 30}\n"
        msg += f"• Type: {check_type}\n"
        msg += f"• Target: `{subject}`\n"

    msg += f"\n{'─' * 30}\n🕒 _{ts}_ | CyberRegis Platform"
    return msg


# ──────────────────────────────────────────────────────
#  Telegram Bot Command Handler (inbound /scan commands)
# ──────────────────────────────────────────────────────

_polling_thread = None
_last_update_id = 0


def start_telegram_bot():
    """Start the Telegram bot polling in a background thread."""
    global _polling_thread
    if not cfg.TELEGRAM_BOT_TOKEN:
        logger.info("Telegram bot token not set — bot polling disabled")
        return
    if _polling_thread and _polling_thread.is_alive():
        return
    _polling_thread = threading.Thread(target=_poll_loop, daemon=True, name="telegram-bot")
    _polling_thread.start()
    logger.info("Telegram bot polling started")


def _poll_loop():
    global _last_update_id
    while True:
        try:
            updates = _get_updates(_last_update_id + 1)
            for update in updates:
                _last_update_id = update["update_id"]
                _handle_update(update)
        except Exception as e:
            logger.warning(f"Telegram poll error: {e}")
        import time
        time.sleep(2)


def _get_updates(offset: int) -> list:
    url = f"https://api.telegram.org/bot{cfg.TELEGRAM_BOT_TOKEN}/getUpdates"
    resp = requests.get(url, params={"offset": offset, "timeout": 30}, timeout=35)
    resp.raise_for_status()
    return resp.json().get("result", [])


def _handle_update(update: dict):
    message = update.get("message") or update.get("edited_message")
    if not message:
        return
    chat_id = str(message["chat"]["id"])
    text = (message.get("text") or "").strip()
    if not text.startswith("/"):
        return
    parts = text.split(maxsplit=1)
    command = parts[0].lower().split("@")[0]  # strip @botname suffix
    args = parts[1].strip() if len(parts) > 1 else ""

    try:
        if command == "/start":
            _cmd_start(chat_id)
        elif command == "/help":
            _cmd_help(chat_id)
        elif command == "/scan":
            _cmd_scan(chat_id, args)
        elif command == "/ip":
            _cmd_ip(chat_id, args)
        elif command == "/url":
            _cmd_url(chat_id, args)
        elif command == "/domain":
            _cmd_domain(chat_id, args)
        elif command == "/status":
            _cmd_status(chat_id)
        else:
            _telegram_send(chat_id, f"❓ Unknown command: `{command}`\nUse /help to see available commands.")
    except Exception as e:
        logger.error(f"Command handler error: {e}")
        _telegram_send(chat_id, f"❌ Error processing command: {str(e)[:200]}")


def _cmd_start(chat_id: str):
    msg = (
        "👋 *Welcome to CyberRegis Bot!*\n\n"
        "I'm your cybersecurity threat intelligence assistant.\n\n"
        "*Available Commands:*\n"
        "🔍 `/scan <target>` — Auto-detect and scan IP, domain, or URL\n"
        "🖥️ `/ip <address>` — IP reputation & intelligence\n"
        "🌐 `/domain <domain>` — Full domain reconnaissance\n"
        "🔗 `/url <url>` — URL safety & threat check\n"
        "📊 `/status` — Platform health & stats\n"
        "❓ `/help` — Show this help\n\n"
        "_Powered by VirusTotal, AbuseIPDB, Shodan & more_"
    )
    _telegram_send(chat_id, msg)


def _cmd_help(chat_id: str):
    msg = (
        "📖 *CyberRegis Bot — Command Reference*\n\n"
        "*Scanning:*\n"
        "`/scan 8.8.8.8` — Scan an IP address\n"
        "`/scan google.com` — Scan a domain\n"
        "`/scan https://example.com` — Scan a URL\n\n"
        "*Specific Scans:*\n"
        "`/ip 1.2.3.4` — IP intelligence\n"
        "`/domain example.com` — Domain recon\n"
        "`/url https://site.com` — URL threat check\n\n"
        "*Other:*\n"
        "`/status` — Server health & scan stats\n\n"
        "💡 _Tip: `/scan` auto-detects the target type_"
    )
    _telegram_send(chat_id, msg)


def _cmd_scan(chat_id: str, target: str):
    if not target:
        _telegram_send(chat_id, "❌ Usage: `/scan <ip|domain|url>`\nExample: `/scan google.com`")
        return

    _telegram_send(chat_id, f"🔄 Scanning `{target}`...")

    import re
    # Detect type
    if target.startswith("http://") or target.startswith("https://"):
        _cmd_url(chat_id, target)
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        _cmd_ip(chat_id, target)
    else:
        _cmd_domain(chat_id, target)


def _cmd_ip(chat_id: str, ip: str):
    if not ip:
        _telegram_send(chat_id, "❌ Usage: `/ip <address>`\nExample: `/ip 8.8.8.8`")
        return
    _telegram_send(chat_id, f"🔄 Analysing IP `{ip}`...")
    try:
        base_url = f"http://127.0.0.1:{cfg.FLASK_PORT}"
        resp = requests.post(f"{base_url}/api/check-ip", json={"ip": ip}, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        msg = _format_telegram_message("ip", ip, result)
        _telegram_send(chat_id, msg)
    except Exception as e:
        _telegram_send(chat_id, f"❌ IP scan failed: {str(e)[:200]}")


def _cmd_url(chat_id: str, url: str):
    if not url:
        _telegram_send(chat_id, "❌ Usage: `/url <url>`\nExample: `/url https://google.com`")
        return
    if not url.startswith("http"):
        url = f"https://{url}"
    _telegram_send(chat_id, f"🔄 Checking URL `{url}`...")
    try:
        base_url = f"http://127.0.0.1:{cfg.FLASK_PORT}"
        resp = requests.post(f"{base_url}/api/check-url", json={"url": url}, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        msg = _format_telegram_message("url", url, result)
        _telegram_send(chat_id, msg)
    except Exception as e:
        _telegram_send(chat_id, f"❌ URL scan failed: {str(e)[:200]}")


def _cmd_domain(chat_id: str, domain: str):
    if not domain:
        _telegram_send(chat_id, "❌ Usage: `/domain <domain>`\nExample: `/domain google.com`")
        return
    _telegram_send(chat_id, f"🔄 Running domain recon on `{domain}`...")
    try:
        base_url = f"http://127.0.0.1:{cfg.FLASK_PORT}"
        resp = requests.post(f"{base_url}/api/analyze-domain", json={"domain": domain}, timeout=60)
        resp.raise_for_status()
        result = resp.json()
        data = result.get("data", result)
        msg = _format_telegram_message("domain", domain, {"data": data})
        _telegram_send(chat_id, msg)
    except Exception as e:
        _telegram_send(chat_id, f"❌ Domain scan failed: {str(e)[:200]}")


def _cmd_status(chat_id: str):
    try:
        base_url = f"http://127.0.0.1:{cfg.FLASK_PORT}"
        health = requests.get(f"{base_url}/api/health", timeout=5).json()
        stats = requests.get(f"{base_url}/api/dashboard/stats", timeout=5).json()

        scan_data = stats.get("data", {}).get("scans", {})
        ioc_data = stats.get("data", {}).get("iocs", {})

        msg = f"📊 *CyberRegis Platform Status*\n"
        msg += f"{'─' * 30}\n"
        msg += f"✅ Status: {health.get('data', {}).get('status', 'unknown').upper()}\n"
        msg += f"⏱️ Uptime: {health.get('data', {}).get('uptime_seconds', 0) // 60} minutes\n\n"
        msg += f"*📈 Scan Statistics*\n"
        msg += f"• Total Scans: {scan_data.get('total_scans', 0):,}\n"
        msg += f"• Today: {scan_data.get('today', 0)}\n"
        by_type = scan_data.get("by_type", {})
        if by_type:
            for stype, cnt in list(by_type.items())[:5]:
                msg += f"  ↳ {stype}: {cnt}\n"
        msg += f"\n*🎯 IOC Database*\n"
        msg += f"• Total IOCs: {ioc_data.get('total', 0):,}\n"
        by_sev = ioc_data.get("by_severity", {})
        if by_sev:
            for sev, cnt in by_sev.items():
                msg += f"  ↳ {sev}: {cnt}\n"
        _telegram_send(chat_id, msg)
    except Exception as e:
        _telegram_send(chat_id, f"❌ Status check failed: {str(e)[:200]}")
