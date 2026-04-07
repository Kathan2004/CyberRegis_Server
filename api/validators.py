"""
Input Validation Helpers
"""
import re
from urllib.parse import urlparse
from typing import Optional, Tuple


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
    return True, None


def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate IPv4 address format. Allows localhost for local testing."""
    if not ip:
        return False, "IP address is required"
    ip = ip.strip()
    # Allow localhost aliases
    if ip.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
        return True, None
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False, "Invalid IPv4 address format"
    for octet in match.groups():
        if int(octet) > 255:
            return False, f"Invalid octet value: {octet}"
    # Allow 127.x (localhost range) for local testing
    if ip.startswith("127."):
        return True, None
    # Block other private/reserved ranges for external scanning
    if ip.startswith(("10.", "0.")):
        return False, "Private/reserved IP addresses cannot be scanned"
    if ip.startswith("192.168.") or ip.startswith("169.254."):
        return False, "Private/reserved IP addresses cannot be scanned"
    if re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip):
        return False, "Private/reserved IP addresses cannot be scanned"
    return True, None


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate URL format."""
    if not url:
        return False, "URL is required"
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "URL has no host"
        if len(url) > 2048:
            return False, "URL exceeds maximum length (2048 chars)"
        return True, None
    except Exception:
        return False, "Invalid URL format"


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """Validate scan target (domain or IP). Allows localhost for local testing."""
    if not target:
        return False, "Target is required"
    target = target.strip()
    # Allow localhost directly
    if target.lower() == "localhost":
        return True, None
    # Try as IP first
    ip_valid, _ = validate_ip(target)
    if ip_valid:
        return True, None
    # Try as domain
    domain_valid, _ = validate_domain(target)
    if domain_valid:
        return True, None
    return False, "Target must be a valid domain name or IPv4 address"


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
