"""
Network Analysis Blueprint
PCAP file analysis with VirusTotal integration.
"""
import os
import time
import logging
import dpkt
import socket
import ipaddress
from collections import Counter, defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import base64
from flask import Blueprint, request
from api.responses import success_response, error_response
from config import get_config
import database as db
import requests

logger = logging.getLogger(__name__)
network_bp = Blueprint("network", __name__)
cfg = get_config()


class PcapAnalyzer:
    """PCAP file analysis with VirusTotal scanning."""

    def __init__(self):
        self.headers = {"x-apikey": cfg.VIRUSTOTAL_API_KEY}

    def analyze(self, file_path: str) -> dict:
        result: dict = {"metadata": self._get_metadata(file_path)}

        # VirusTotal scan
        result["virustotal"] = self._virustotal_scan(file_path)

        # Protocol analysis
        if file_path.endswith((".pcap", ".pcapng", ".cap")):
            insights = self._analyze_network_insights(file_path)
            protocols = insights.get("protocol_counts", {})
            result["pcap_analysis"] = protocols
            result["network_insights"] = {
                "total_packets": insights.get("total_packets", 0),
                "total_bytes": insights.get("total_bytes", 0),
                "capture_duration_seconds": insights.get("capture_duration_seconds", 0),
                "avg_packets_per_second": insights.get("avg_packets_per_second", 0),
                "packet_size_stats": insights.get("packet_size_stats", {}),
                "top_source_ips": insights.get("top_source_ips", []),
                "top_destination_ips": insights.get("top_destination_ips", []),
                "top_ports": insights.get("top_ports", []),
                "top_flows": insights.get("top_flows", []),
                "tcp_flags": insights.get("tcp_flags", {}),
            }
            result["suspicious_ips"] = insights.get("suspicious_ips", [])
            result["potential_threats"] = insights.get("potential_threats", [])
            result["chart_base64"] = self._generate_chart(protocols)
            result["protocol_summary"] = self._protocol_summary(protocols)

        return result

    def _get_metadata(self, fp: str) -> dict:
        return {
            "filename": os.path.basename(fp),
            "size_bytes": os.path.getsize(fp),
            "file_type": fp.rsplit(".", 1)[-1] if "." in fp else "unknown",
        }

    def _virustotal_scan(self, fp: str) -> dict:
        try:
            if not cfg.VIRUSTOTAL_API_KEY:
                return self._vt_fallback("No API key")

            # Validate key
            test = requests.get("https://www.virustotal.com/api/v3/users/current",
                                headers=self.headers, timeout=10)
            if test.status_code != 200:
                return self._vt_fallback("Invalid API key")

            with open(fp, "rb") as f:
                resp = requests.post("https://www.virustotal.com/api/v3/files",
                                     headers=self.headers, files={"file": f}, timeout=30)

            if resp.status_code != 200:
                return self._vt_fallback(f"Upload failed: HTTP {resp.status_code}")

            file_id = resp.json().get("data", {}).get("id")
            return self._poll_report(file_id)
        except Exception as e:
            return self._vt_fallback(str(e))

    def _poll_report(self, file_id: str, retries: int = 5) -> dict:
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        for _ in range(retries):
            resp = requests.get(url, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                if attrs.get("status") == "completed":
                    return self._process_report(attrs)
            time.sleep(5)
        return self._vt_fallback("Analysis timeout")

    def _process_report(self, attrs: dict) -> dict:
        stats = attrs.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values()) if stats else 0
        risk_score = min(100, int((malicious * 3 + suspicious * 2) / total * 100)) if total else 0

        if risk_score >= 75:
            level = "HIGH"
        elif risk_score >= 50:
            level = "MEDIUM"
        elif risk_score >= 25:
            level = "LOW"
        else:
            level = "VERY_LOW"

        return {
            "risk_assessment": {
                "risk_score": risk_score, "risk_level": level,
                "malicious_count": malicious, "suspicious_count": suspicious,
                "harmless_count": harmless, "undetected_count": undetected,
                "total_engines": total,
                "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
            },
            "metadata": {
                "reputation": attrs.get("reputation", 0),
                "analysis_date": attrs.get("last_analysis_date"),
                "file_type": attrs.get("type_description", "Unknown"),
            },
        }

    def _vt_fallback(self, msg: str) -> dict:
        return {
            "error": f"VirusTotal: {msg}",
            "risk_assessment": {
                "risk_score": 0, "risk_level": "UNKNOWN",
                "malicious_count": 0, "suspicious_count": 0,
                "harmless_count": 0, "undetected_count": 0,
                "total_engines": 0, "detection_ratio": "0/0", "status": "FAILED",
            },
            "metadata": {"reputation": 0, "analysis_date": None, "file_type": "Unknown"},
        }

    def _analyze_protocols(self, fp: str) -> dict:
        counts = {}
        try:
            with open(fp, 'rb') as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                except Exception:
                    f.seek(0)
                    pcap = dpkt.pcapng.Reader(f)
                for _ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        inner = eth.data
                        if isinstance(inner, dpkt.ip.IP):
                            payload = inner.data
                            if isinstance(payload, dpkt.tcp.TCP):
                                proto = 'TCP'
                            elif isinstance(payload, dpkt.udp.UDP):
                                proto = 'UDP'
                            elif isinstance(payload, dpkt.icmp.ICMP):
                                proto = 'ICMP'
                            else:
                                proto = f"IP/{getattr(inner, 'p', '?')}"
                        elif isinstance(inner, dpkt.ip6.IP6):
                            proto = 'IPv6'
                        elif isinstance(inner, dpkt.arp.ARP):
                            proto = 'ARP'
                        else:
                            proto = type(inner).__name__.upper() or 'OTHER'
                        counts[proto] = counts.get(proto, 0) + 1
                    except Exception:
                        counts['UNKNOWN'] = counts.get('UNKNOWN', 0) + 1
        except Exception as e:
            logger.error(f'PCAP parse error: {e}')
        return counts

    def _analyze_network_insights(self, fp: str) -> dict:
        protocol_counts = Counter()
        src_counter = Counter()
        dst_counter = Counter()
        dst_port_counter = Counter()
        flow_counter = Counter()
        packet_sizes = []
        tcp_flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0}
        src_unique_dst_ports = defaultdict(set)
        total_bytes = 0
        first_ts = None
        last_ts = None

        def safe_ip(raw, is_v6=False):
            try:
                return socket.inet_ntop(socket.AF_INET6, raw) if is_v6 else socket.inet_ntoa(raw)
            except Exception:
                return "unknown"

        try:
            with open(fp, "rb") as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                except Exception:
                    f.seek(0)
                    pcap = dpkt.pcapng.Reader(f)

                for ts, buf in pcap:
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts

                    pkt_len = len(buf)
                    total_bytes += pkt_len
                    packet_sizes.append(pkt_len)

                    src_ip = None
                    dst_ip = None
                    proto = "UNKNOWN"
                    sport = None
                    dport = None

                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        inner = eth.data

                        if isinstance(inner, dpkt.ip.IP):
                            payload = inner.data
                            src_ip = safe_ip(getattr(inner, "src", b""))
                            dst_ip = safe_ip(getattr(inner, "dst", b""))
                            if isinstance(payload, dpkt.tcp.TCP):
                                proto = "TCP"
                                sport = getattr(payload, "sport", None)
                                dport = getattr(payload, "dport", None)
                                flags = getattr(payload, "flags", 0)
                                if flags & dpkt.tcp.TH_SYN:
                                    tcp_flags["syn"] += 1
                                if flags & dpkt.tcp.TH_ACK:
                                    tcp_flags["ack"] += 1
                                if flags & dpkt.tcp.TH_FIN:
                                    tcp_flags["fin"] += 1
                                if flags & dpkt.tcp.TH_RST:
                                    tcp_flags["rst"] += 1
                                if flags & dpkt.tcp.TH_PUSH:
                                    tcp_flags["psh"] += 1
                                if flags & dpkt.tcp.TH_URG:
                                    tcp_flags["urg"] += 1
                            elif isinstance(payload, dpkt.udp.UDP):
                                proto = "UDP"
                                sport = getattr(payload, "sport", None)
                                dport = getattr(payload, "dport", None)
                            elif isinstance(payload, dpkt.icmp.ICMP):
                                proto = "ICMP"
                            else:
                                proto = f"IP/{getattr(inner, 'p', '?')}"
                        elif isinstance(inner, dpkt.ip6.IP6):
                            payload = inner.data
                            src_ip = safe_ip(getattr(inner, "src", b""), is_v6=True)
                            dst_ip = safe_ip(getattr(inner, "dst", b""), is_v6=True)
                            if isinstance(payload, dpkt.tcp.TCP):
                                proto = "TCP"
                                sport = getattr(payload, "sport", None)
                                dport = getattr(payload, "dport", None)
                                flags = getattr(payload, "flags", 0)
                                if flags & dpkt.tcp.TH_SYN:
                                    tcp_flags["syn"] += 1
                                if flags & dpkt.tcp.TH_ACK:
                                    tcp_flags["ack"] += 1
                                if flags & dpkt.tcp.TH_FIN:
                                    tcp_flags["fin"] += 1
                                if flags & dpkt.tcp.TH_RST:
                                    tcp_flags["rst"] += 1
                                if flags & dpkt.tcp.TH_PUSH:
                                    tcp_flags["psh"] += 1
                                if flags & dpkt.tcp.TH_URG:
                                    tcp_flags["urg"] += 1
                            elif isinstance(payload, dpkt.udp.UDP):
                                proto = "UDP"
                                sport = getattr(payload, "sport", None)
                                dport = getattr(payload, "dport", None)
                            elif isinstance(payload, dpkt.icmp6.ICMP6):
                                proto = "ICMPv6"
                            else:
                                proto = "IPv6"
                        elif isinstance(inner, dpkt.arp.ARP):
                            proto = "ARP"
                            src_ip = safe_ip(getattr(inner, "spa", b""))
                            dst_ip = safe_ip(getattr(inner, "tpa", b""))
                        else:
                            proto = type(inner).__name__.upper() or "OTHER"
                    except Exception:
                        proto = "UNKNOWN"

                    protocol_counts[proto] += 1
                    if src_ip:
                        src_counter[src_ip] += 1
                    if dst_ip:
                        dst_counter[dst_ip] += 1
                    if dport is not None:
                        dst_port_counter[(dport, proto)] += 1
                    if src_ip and dport is not None:
                        src_unique_dst_ports[src_ip].add(dport)

                    flow_label = None
                    if src_ip and dst_ip and sport is not None and dport is not None:
                        flow_label = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto})"
                    elif src_ip and dst_ip:
                        flow_label = f"{src_ip} -> {dst_ip} ({proto})"
                    if flow_label:
                        flow_counter[flow_label] += 1
        except Exception as e:
            logger.error(f"PCAP deep parse error: {e}")

        total_packets = sum(protocol_counts.values())
        duration = max(0, (last_ts - first_ts)) if first_ts is not None and last_ts is not None else 0
        avg_pps = round(total_packets / duration, 2) if duration > 0 else 0
        avg_size = round(total_bytes / total_packets, 2) if total_packets else 0

        def top_counter(counter, key_name, limit=10):
            out = []
            for k, v in counter.most_common(limit):
                out.append({
                    key_name: k,
                    "count": v,
                    "percentage": round((v / total_packets) * 100, 2) if total_packets else 0,
                })
            return out

        top_ports = []
        for (port, proto), count in dst_port_counter.most_common(10):
            top_ports.append({
                "port": port,
                "protocol": proto,
                "count": count,
                "percentage": round((count / total_packets) * 100, 2) if total_packets else 0,
            })

        top_flows = []
        for flow, packets in flow_counter.most_common(10):
            top_flows.append({"flow": flow, "packets": packets})

        suspicious_ips = set()
        potential_threats = []

        for src_ip, ports in src_unique_dst_ports.items():
            if len(ports) >= 20:
                suspicious_ips.add(src_ip)
                potential_threats.append({
                    "type": "Potential port scan behavior",
                    "severity": "high" if len(ports) >= 50 else "medium",
                    "details": f"Source {src_ip} contacted {len(ports)} distinct destination ports",
                })

        if tcp_flags["syn"] > 100 and tcp_flags["syn"] > (tcp_flags["ack"] * 2):
            potential_threats.append({
                "type": "High SYN-to-ACK ratio",
                "severity": "medium",
                "details": f"SYN={tcp_flags['syn']} ACK={tcp_flags['ack']} suggests scanning or half-open attempts",
            })

        high_risk_ports = {21, 22, 23, 25, 445, 3389, 5900}
        for item in top_ports:
            if item["port"] in high_risk_ports and item["count"] >= 10:
                potential_threats.append({
                    "type": "High-risk service exposure in traffic",
                    "severity": "medium",
                    "details": f"Frequent traffic observed on port {item['port']} ({item['count']} packets)",
                })

        for ip, _count in src_counter.most_common(10):
            try:
                if ip != "unknown" and ipaddress.ip_address(ip).is_private:
                    continue
                if ip != "unknown" and src_counter[ip] >= max(20, int(total_packets * 0.2)):
                    suspicious_ips.add(ip)
            except Exception:
                continue

        return {
            "protocol_counts": dict(protocol_counts),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "capture_duration_seconds": round(duration, 2),
            "avg_packets_per_second": avg_pps,
            "packet_size_stats": {
                "min": min(packet_sizes) if packet_sizes else 0,
                "max": max(packet_sizes) if packet_sizes else 0,
                "avg": avg_size,
            },
            "top_source_ips": top_counter(src_counter, "ip"),
            "top_destination_ips": top_counter(dst_counter, "ip"),
            "top_ports": top_ports,
            "top_flows": top_flows,
            "tcp_flags": tcp_flags,
            "suspicious_ips": sorted(list(suspicious_ips))[:20],
            "potential_threats": potential_threats[:10],
        }

    def _generate_chart(self, counts: dict) -> str:
        if not counts:
            return ""
        protocols = list(counts.keys())
        values = list(counts.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        cmap = plt.get_cmap("viridis")
        colors = cmap([i / len(protocols) for i in range(len(protocols))])
        ax.bar(protocols, values, color=colors)
        ax.set_xlabel("Protocol", fontsize=12)
        ax.set_ylabel("Packet Count", fontsize=12)
        ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        buf.seek(0)
        b64 = base64.b64encode(buf.getvalue()).decode()
        plt.close(fig)
        buf.close()
        return b64

    def _protocol_summary(self, counts: dict) -> dict:
        total = sum(counts.values())
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_packets": total,
            "unique_protocols": len(counts),
            "top_protocols": [{"name": p, "count": c, "percentage": round(c / total * 100, 1)} for p, c in top],
        }


@network_bp.route("/api/analyze-pcap", methods=["POST"])
def analyze_pcap():
    start = time.time()
    try:
        if "file" not in request.files:
            return error_response("No file provided", 400)

        file = request.files["file"]
        if not file.filename or not file.filename.endswith((".pcap", ".cap", ".pcapng")):
            return error_response("Only .pcap / .cap / .pcapng files are supported", 400)

        os.makedirs(cfg.UPLOAD_FOLDER, exist_ok=True)
        file_path = os.path.join(cfg.UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        analyzer = PcapAnalyzer()
        result = analyzer.analyze(file_path)

        duration_ms = int((time.time() - start) * 1000)
        result["scan_duration_ms"] = duration_ms

        # Persist
        try:
            vt = result.get("virustotal", {}).get("risk_assessment", {})
            db.save_scan("pcap", file.filename, result,
                         risk_level=vt.get("risk_level"),
                         score=vt.get("risk_score"),
                         summary=f"PCAP: {file.filename}", duration_ms=duration_ms)
        except Exception as e:
            logger.warning(f"Failed to save scan: {e}")

        # Notify
        try:
            from services.notification_service import notify
            notify("pcap", file.filename, result)
        except Exception:
            pass

        return success_response(result)
    except Exception as e:
        logger.error(f"PCAP analysis error: {e}")
        return error_response(str(e), 500)
