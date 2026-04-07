"""
Network Analysis Blueprint
PCAP file analysis with VirusTotal integration.
"""
import os
import time
import logging
import dpkt
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
        result = {"metadata": self._get_metadata(file_path)}

        # VirusTotal scan
        result["virustotal"] = self._virustotal_scan(file_path)

        # Protocol analysis
        if file_path.endswith((".pcap", ".pcapng", ".cap")):
            protocols = self._analyze_protocols(file_path)
            result["pcap_analysis"] = protocols
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
                            if isinstance(inner.data, dpkt.tcp.TCP):
                                proto = 'TCP'
                            elif isinstance(inner.data, dpkt.udp.UDP):
                                proto = 'UDP'
                            elif isinstance(inner.data, dpkt.icmp.ICMP):
                                proto = 'ICMP'
                            else:
                                proto = f'IP/{inner.p}'
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

    def _generate_chart(self, counts: dict) -> str:
        if not counts:
            return ""
        protocols = list(counts.keys())
        values = list(counts.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        colors = plt.cm.viridis([i / len(protocols) for i in range(len(protocols))])
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
