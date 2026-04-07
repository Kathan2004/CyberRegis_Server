import socket
from flask import Blueprint, request
from api.responses import success_response, error_response
from api.validators import validate_ip, validate_domain
from services.shodan_service import ShodanService


shodan_bp = Blueprint("shodan", __name__)
svc = ShodanService()


def _wrap(result, fail_status: int = 502):
    if not result.get("enabled"):
        return error_response(result.get("error", "Shodan not configured"), 503)
    if not result.get("ok"):
        return error_response(result.get("error", "Shodan API error"), fail_status)
    return success_response(result.get("data", {}))


@shodan_bp.route("/api/shodan/api-info", methods=["GET"])
def shodan_api_info():
    return _wrap(svc.api_info())


@shodan_bp.route("/api/shodan/account/profile", methods=["GET"])
def shodan_account_profile():
    return _wrap(svc.account_profile())


@shodan_bp.route("/api/shodan/host/<ip>", methods=["GET"])
def shodan_host(ip: str):
    valid, err = validate_ip(ip)
    if not valid:
        return error_response(err or "Invalid IP", 400)
    history = request.args.get("history", "false").lower() == "true"
    minify = request.args.get("minify", "false").lower() == "true"
    return _wrap(svc.host(ip, history=history, minify=minify))


@shodan_bp.route("/api/shodan/host/count", methods=["GET"])
def shodan_host_count():
    query = request.args.get("query", "").strip()
    if not query:
        return error_response("query is required", 400)
    facets = request.args.get("facets")
    return _wrap(svc.host_count(query=query, facets=facets))


@shodan_bp.route("/api/shodan/host/search", methods=["GET"])
def shodan_host_search():
    query = request.args.get("query", "").strip()
    if not query:
        return error_response("query is required", 400)
    page = int(request.args.get("page", 1) or 1)
    facets = request.args.get("facets")
    minify = request.args.get("minify", "true").lower() == "true"
    return _wrap(svc.host_search(query=query, page=page, facets=facets, minify=minify))


@shodan_bp.route("/api/shodan/host/search/facets", methods=["GET"])
def shodan_host_search_facets():
    return _wrap(svc.host_search_facets())


@shodan_bp.route("/api/shodan/host/search/filters", methods=["GET"])
def shodan_host_search_filters():
    return _wrap(svc.host_search_filters())


@shodan_bp.route("/api/shodan/host/search/tokens", methods=["GET"])
def shodan_host_search_tokens():
    query = request.args.get("query", "").strip()
    if not query:
        return error_response("query is required", 400)
    return _wrap(svc.host_search_tokens(query=query))


@shodan_bp.route("/api/shodan/ports", methods=["GET"])
def shodan_ports():
    return _wrap(svc.ports())


@shodan_bp.route("/api/shodan/protocols", methods=["GET"])
def shodan_protocols():
    return _wrap(svc.protocols())


@shodan_bp.route("/api/shodan/scan", methods=["POST"])
def shodan_scan():
    data = request.get_json(silent=True) or {}
    ips = data.get("ips")
    if not ips:
        return error_response("ips is required", 400)
    return _wrap(svc.scan(ips=ips))


@shodan_bp.route("/api/shodan/scan/internet", methods=["POST"])
def shodan_scan_internet():
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    protocol = data.get("protocol")
    if port is None or not protocol:
        return error_response("port and protocol are required", 400)
    return _wrap(svc.scan_internet(port=int(port), protocol=str(protocol)))


@shodan_bp.route("/api/shodan/scans", methods=["GET"])
def shodan_scans():
    return _wrap(svc.scans())


@shodan_bp.route("/api/shodan/scan/<scan_id>", methods=["GET"])
def shodan_scan_status(scan_id: str):
    return _wrap(svc.scan_status(scan_id))


@shodan_bp.route("/api/shodan/alert", methods=["POST"])
def shodan_alert_create():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    filters = data.get("filters", {})
    if not name:
        return error_response("name is required", 400)
    return _wrap(svc.alert_create(name=name, filters=filters))


@shodan_bp.route("/api/shodan/alert/info", methods=["GET"])
def shodan_alert_list():
    return _wrap(svc.alert_list())


@shodan_bp.route("/api/shodan/alert/triggers", methods=["GET"])
def shodan_alert_triggers():
    return _wrap(svc.alert_triggers())


@shodan_bp.route("/api/shodan/alert/<alert_id>/info", methods=["GET"])
def shodan_alert_info(alert_id: str):
    return _wrap(svc.alert_info(alert_id))


@shodan_bp.route("/api/shodan/alert/<alert_id>", methods=["DELETE", "POST"])
def shodan_alert_update(alert_id: str):
    if request.method == "DELETE":
        return _wrap(svc.alert_delete(alert_id))
    data = request.get_json(silent=True) or {}
    return _wrap(svc.alert_edit(alert_id, name=data.get("name"), filters=data.get("filters")))


@shodan_bp.route("/api/shodan/alert/<alert_id>/trigger/<trigger>", methods=["PUT", "DELETE"])
def shodan_alert_trigger(alert_id: str, trigger: str):
    if request.method == "PUT":
        return _wrap(svc.alert_add_trigger(alert_id, trigger))
    return _wrap(svc.alert_remove_trigger(alert_id, trigger))


@shodan_bp.route("/api/shodan/alert/<alert_id>/trigger/<trigger>/ignore/<service>", methods=["PUT", "DELETE"])
def shodan_alert_trigger_ignore(alert_id: str, trigger: str, service: str):
    if request.method == "PUT":
        return _wrap(svc.alert_ignore_service(alert_id, trigger, service))
    return _wrap(svc.alert_unignore_service(alert_id, trigger, service))


@shodan_bp.route("/api/shodan/alert/<alert_id>/notifier/<notifier_id>", methods=["PUT", "DELETE"])
def shodan_alert_notifier(alert_id: str, notifier_id: str):
    if request.method == "PUT":
        return _wrap(svc.alert_add_notifier(alert_id, notifier_id))
    return _wrap(svc.alert_remove_notifier(alert_id, notifier_id))


@shodan_bp.route("/api/shodan/notifier", methods=["GET", "POST"])
def shodan_notifier_list_create():
    if request.method == "GET":
        return _wrap(svc.notifier_list())
    data = request.get_json(silent=True) or {}
    provider = data.get("provider", "").strip()
    args = data.get("args", {})
    description = data.get("description", "")
    if not provider:
        return error_response("provider is required", 400)
    return _wrap(svc.notifier_create(provider=provider, args=args, description=description))


@shodan_bp.route("/api/shodan/notifier/provider", methods=["GET"])
def shodan_notifier_providers():
    return _wrap(svc.notifier_providers())


@shodan_bp.route("/api/shodan/notifier/<notifier_id>", methods=["GET", "PUT", "DELETE"])
def shodan_notifier_item(notifier_id: str):
    if request.method == "GET":
        return _wrap(svc.notifier_get(notifier_id))
    if request.method == "DELETE":
        return _wrap(svc.notifier_delete(notifier_id))
    data = request.get_json(silent=True) or {}
    provider = data.get("provider", "").strip()
    args = data.get("args", {})
    description = data.get("description", "")
    if not provider:
        return error_response("provider is required", 400)
    return _wrap(svc.notifier_update(notifier_id, provider=provider, args=args, description=description))


@shodan_bp.route("/api/shodan/query", methods=["GET"])
def shodan_query_directory():
    page = int(request.args.get("page", 1) or 1)
    sort = request.args.get("sort", "votes")
    return _wrap(svc.query_directory(page=page, sort=sort))


@shodan_bp.route("/api/shodan/query/search", methods=["GET"])
def shodan_query_search():
    query = request.args.get("query", "").strip()
    if not query:
        return error_response("query is required", 400)
    page = int(request.args.get("page", 1) or 1)
    return _wrap(svc.query_search(query=query, page=page))


@shodan_bp.route("/api/shodan/query/tags", methods=["GET"])
def shodan_query_tags():
    size = int(request.args.get("size", 100) or 100)
    return _wrap(svc.query_tags(size=size))


@shodan_bp.route("/api/shodan/dns/domain/<domain>", methods=["GET"])
def shodan_dns_domain(domain: str):
    valid, err = validate_domain(domain)
    if not valid:
        return error_response(err or "Invalid domain", 400)
    return _wrap(svc.dns_domain(domain))


@shodan_bp.route("/api/shodan/dns/resolve", methods=["GET"])
def shodan_dns_resolve():
    hostnames = request.args.get("hostnames", "").strip()
    if not hostnames:
        return error_response("hostnames is required", 400)
    return _wrap(svc.dns_resolve(hostnames=hostnames))


@shodan_bp.route("/api/shodan/dns/reverse", methods=["GET"])
def shodan_dns_reverse():
    ips = request.args.get("ips", "").strip()
    if not ips:
        return error_response("ips is required", 400)
    return _wrap(svc.dns_reverse(ips=ips))


@shodan_bp.route("/api/shodan/tools/httpheaders", methods=["GET"])
def shodan_tools_httpheaders():
    return _wrap(svc.tools_httpheaders())


@shodan_bp.route("/api/shodan/tools/myip", methods=["GET"])
def shodan_tools_myip():
    return _wrap(svc.tools_myip())


# Integrator helper endpoints
@shodan_bp.route("/api/shodan/enrich/domain", methods=["GET"])
def shodan_enrich_domain():
    domain = request.args.get("domain", "").strip()
    valid, err = validate_domain(domain)
    if not valid:
        return error_response(err or "Invalid domain", 400)

    resolve_result = svc.dns_resolve(hostnames=domain)
    if not resolve_result.get("enabled"):
        return error_response(resolve_result.get("error", "Shodan not configured"), 503)

    resolved_ip = None
    if resolve_result.get("ok"):
        data = resolve_result.get("data", {})
        if isinstance(data, dict):
            resolved_ip = data.get(domain)

    host_result = svc.host(resolved_ip) if resolved_ip else {"enabled": True, "ok": False, "error": "No A record resolved via Shodan DNS"}
    dns_result = svc.dns_domain(domain)

    return success_response({
        "domain": domain,
        "resolved_ip": resolved_ip,
        "dns": dns_result.get("data") if dns_result.get("ok") else {"error": dns_result.get("error")},
        "host": host_result.get("data") if host_result.get("ok") else {"error": host_result.get("error")},
    })


@shodan_bp.route("/api/shodan/enrich/target", methods=["GET"])
def shodan_enrich_target():
    target = request.args.get("target", "").strip()
    if not target:
        return error_response("target is required", 400)

    ip = target
    valid_ip, _ = validate_ip(target)
    if not valid_ip:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return error_response("Unable to resolve target to IP", 400)

    return _wrap(svc.host(ip))
