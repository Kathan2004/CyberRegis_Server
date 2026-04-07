import requests
from typing import Any, Dict, Optional
from config import get_config


class ShodanService:
    BASE_URL = "https://api.shodan.io"

    def __init__(self):
        self.cfg = get_config()
        self.api_key = getattr(self.cfg, "SHODAN_API_KEY", "I3OjcV2OowlyjWRPYm3vPrdcLHg0kTWO")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None, timeout: int = 15) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "error": "SHODAN_API_KEY not configured"}

        req_params = dict(params or {})
        req_params["key"] = self.api_key

        try:
            resp = requests.request(
                method=method,
                url=f"{self.BASE_URL}{path}",
                params=req_params,
                json=json_body,
                timeout=timeout,
            )
            if resp.status_code >= 400:
                return {
                    "enabled": True,
                    "ok": False,
                    "status_code": resp.status_code,
                    "error": resp.text[:500],
                }
            payload = resp.json() if resp.text else {}
            return {"enabled": True, "ok": True, "status_code": resp.status_code, "data": payload}
        except Exception as e:
            return {"enabled": True, "ok": False, "error": str(e)}

    # Host & Search
    def host(self, ip: str, history: bool = False, minify: bool = False):
        return self._request("GET", f"/shodan/host/{ip}", {"history": str(history).lower(), "minify": str(minify).lower()})

    def host_count(self, query: str, facets: Optional[str] = None):
        params = {"query": query}
        if facets:
            params["facets"] = facets
        return self._request("GET", "/shodan/host/count", params)

    def host_search(self, query: str, page: int = 1, facets: Optional[str] = None, minify: bool = True):
        params = {"query": query, "page": page, "minify": str(minify).lower()}
        if facets:
            params["facets"] = facets
        return self._request("GET", "/shodan/host/search", params)

    def host_search_facets(self):
        return self._request("GET", "/shodan/host/search/facets")

    def host_search_filters(self):
        return self._request("GET", "/shodan/host/search/filters")

    def host_search_tokens(self, query: str):
        return self._request("GET", "/shodan/host/search/tokens", {"query": query})

    # Scanning
    def ports(self):
        return self._request("GET", "/shodan/ports")

    def protocols(self):
        return self._request("GET", "/shodan/protocols")

    def scan(self, ips):
        return self._request("POST", "/shodan/scan", json_body={"ips": ips})

    def scan_internet(self, port: int, protocol: str):
        return self._request("POST", "/shodan/scan/internet", json_body={"port": port, "protocol": protocol})

    def scans(self):
        return self._request("GET", "/shodan/scans")

    def scan_status(self, scan_id: str):
        return self._request("GET", f"/shodan/scan/{scan_id}")

    # Alerts
    def alert_create(self, name: str, filters: Optional[Dict[str, Any]] = None):
        return self._request("POST", "/shodan/alert", params={"name": name, "filters": filters or {}})

    def alert_info(self, alert_id: str):
        return self._request("GET", f"/shodan/alert/{alert_id}/info")

    def alert_delete(self, alert_id: str):
        return self._request("DELETE", f"/shodan/alert/{alert_id}")

    def alert_edit(self, alert_id: str, name: Optional[str] = None, filters: Optional[Dict[str, Any]] = None):
        params: Dict[str, Any] = {}
        if name is not None:
            params["name"] = name
        if filters is not None:
            params["filters"] = filters
        return self._request("POST", f"/shodan/alert/{alert_id}", params=params)

    def alert_list(self):
        return self._request("GET", "/shodan/alert/info")

    def alert_triggers(self):
        return self._request("GET", "/shodan/alert/triggers")

    def alert_add_trigger(self, alert_id: str, trigger: str):
        return self._request("PUT", f"/shodan/alert/{alert_id}/trigger/{trigger}")

    def alert_remove_trigger(self, alert_id: str, trigger: str):
        return self._request("DELETE", f"/shodan/alert/{alert_id}/trigger/{trigger}")

    def alert_ignore_service(self, alert_id: str, trigger: str, service: str):
        return self._request("PUT", f"/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}")

    def alert_unignore_service(self, alert_id: str, trigger: str, service: str):
        return self._request("DELETE", f"/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}")

    def alert_add_notifier(self, alert_id: str, notifier_id: str):
        return self._request("PUT", f"/shodan/alert/{alert_id}/notifier/{notifier_id}")

    def alert_remove_notifier(self, alert_id: str, notifier_id: str):
        return self._request("DELETE", f"/shodan/alert/{alert_id}/notifier/{notifier_id}")

    # Notifiers
    def notifier_list(self):
        return self._request("GET", "/notifier")

    def notifier_providers(self):
        return self._request("GET", "/notifier/provider")

    def notifier_create(self, provider: str, args: Dict[str, Any], description: str = ""):
        return self._request("POST", "/notifier", json_body={"provider": provider, "args": args, "description": description})

    def notifier_delete(self, notifier_id: str):
        return self._request("DELETE", f"/notifier/{notifier_id}")

    def notifier_get(self, notifier_id: str):
        return self._request("GET", f"/notifier/{notifier_id}")

    def notifier_update(self, notifier_id: str, provider: str, args: Dict[str, Any], description: str = ""):
        return self._request("PUT", f"/notifier/{notifier_id}", json_body={"provider": provider, "args": args, "description": description})

    # Directory & Account
    def query_directory(self, page: int = 1, sort: str = "votes"):
        return self._request("GET", "/shodan/query", {"page": page, "sort": sort})

    def query_search(self, query: str, page: int = 1):
        return self._request("GET", "/shodan/query/search", {"query": query, "page": page})

    def query_tags(self, size: int = 100):
        return self._request("GET", "/shodan/query/tags", {"size": size})

    def account_profile(self):
        return self._request("GET", "/account/profile")

    # DNS
    def dns_domain(self, domain: str):
        return self._request("GET", f"/dns/domain/{domain}")

    def dns_resolve(self, hostnames):
        return self._request("GET", "/dns/resolve", {"hostnames": hostnames})

    def dns_reverse(self, ips):
        return self._request("GET", "/dns/reverse", {"ips": ips})

    # Utility
    def tools_httpheaders(self):
        return self._request("GET", "/tools/httpheaders")

    def tools_myip(self):
        return self._request("GET", "/tools/myip")

    # API status
    def api_info(self):
        return self._request("GET", "/api-info")
