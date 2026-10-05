"""
Input Validation Helpers
"""
import ipaddress
import re
from urllib.parse import urlparse
from typing import Optional, Tuple

from netguard import check_host


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """Validate domain format. Returns (is_valid, error_message)."""
    if not domain:
        return False, "Domain is required"
    domain = domain.strip().lower()
    # Remove protocol if present
    if "://" in domain:
        domain = urlparse(domain).netloc or domain
    # Remove path/trailing slash
    domain = domain.split("/")[0]
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
        return False, f"Invalid domain format: {domain}"
    if len(domain) > 253:
        return False, "Domain exceeds maximum length (253 chars)"
    return check_host(domain)


def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate an IPv4/IPv6 address and reject non-public ranges (see netguard)."""
    if not ip:
        return False, "IP address is required"
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False, "Invalid IP address format"
    return check_host(ip)


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate URL format and make sure the host is a public address."""
    if not url:
        return False, "URL is required"
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"
    if len(url) > 2048:
        return False, "URL exceeds maximum length (2048 chars)"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    if not parsed.hostname:
        return False, "URL has no host"
    return check_host(parsed.hostname)


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """Validate a scan target (domain or IP). The target must resolve to public addresses."""
    if not target:
        return False, "Target is required"
    target = target.strip()
    ip_valid, ip_err = validate_ip(target)
    if ip_valid:
        return True, None
    if ip_err != "Invalid IP address format":
        return False, ip_err
    domain_valid, domain_err = validate_domain(target)
    if not domain_valid:
        return False, "Target must be a valid domain name or IP address"
    return check_host(target, require_resolution=True)


def validate_cve_id(cve_id: str) -> Tuple[bool, Optional[str]]:
    """Validate CVE ID format (CVE-YYYY-NNNNN)."""
    if not cve_id:
        return False, "CVE ID is required"
    cve_id = cve_id.strip().upper()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        return False, "Invalid CVE format. Expected: CVE-YYYY-NNNNN"
    return True, None


def sanitize_domain(domain: str) -> str:
    """Clean and normalize a domain string."""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc or domain
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]  # Remove port
    return domain
