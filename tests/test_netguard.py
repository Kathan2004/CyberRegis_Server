import pytest

import netguard
from api.validators import validate_domain, validate_ip, validate_target, validate_url


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.8.8.8", "0.0.0.0", "10.0.0.1", "172.16.5.4", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fd00::1",
    "::ffff:127.0.0.1",
])
def test_non_public_ips_rejected(ip):
    ok, err = validate_ip(ip)
    assert not ok and err


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_accepted(ip):
    assert validate_ip(ip) == (True, None)


def test_garbage_ip_rejected():
    assert validate_ip("999.1.1.1")[0] is False
    assert validate_ip("not-an-ip")[0] is False


def test_domain_resolving_to_private_is_rejected(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_host", lambda h: ["10.0.0.5"])
    assert validate_domain("internal.example.com")[0] is False
    assert validate_target("internal.example.com")[0] is False
    assert validate_url("http://internal.example.com/x")[0] is False


def test_domain_resolving_to_public_is_accepted(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_host", lambda h: ["93.184.216.34"])
    assert validate_domain("example.com") == (True, None)
    assert validate_target("example.com") == (True, None)
    assert validate_url("https://example.com/") == (True, None)


def test_localhost_target_rejected():
    assert validate_target("localhost")[0] is False
    assert validate_url("http://localhost:5000/api/health")[0] is False


def test_metadata_url_rejected():
    assert validate_url("http://169.254.169.254/latest/meta-data/")[0] is False


def test_lab_override(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    assert validate_ip("10.0.0.1") == (True, None)


class _Resp:
    def __init__(self, status, location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.is_redirect = location is not None
        self.history = []


def test_safe_get_blocks_redirect_to_metadata(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_host", lambda h: ["93.184.216.34"])
    monkeypatch.setattr(netguard.requests, "get",
                        lambda url, **kw: _Resp(302, "http://169.254.169.254/latest/"))
    with pytest.raises(netguard.BlockedTargetError):
        netguard.safe_get("http://example.com/")


def test_safe_get_follows_public_redirects(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_host", lambda h: ["93.184.216.34"])
    hops = iter([_Resp(301, "https://example.com/final"), _Resp(200)])
    monkeypatch.setattr(netguard.requests, "get", lambda url, **kw: next(hops))
    resp = netguard.safe_get("http://example.com/")
    assert resp.status_code == 200 and len(resp.history) == 1
