"""
PCAP Analysis Report Model
"""
import os
import time
import io
import base64
import requests
import pyshark
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from app.config import Config


class AnalysisReport:
    """AnalysisReport Class for PCAP Analysis"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or Config.VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key}

    def analyze_file(self, file_path: str) -> dict:
        """Analyze a file (PCAP or other)"""
        file_info = {}
        try:
            working_directory = os.path.dirname(file_path)
            os.makedirs(working_directory, exist_ok=True)
            os.chdir(working_directory)

            file_info['metadata'] = self.get_metadata(file_path)
            file_info['virustotal'] = self.analyze_with_virustotal(file_path)

            if file_path.endswith('.pcap'):
                file_info['pcap_analysis'] = self.analyze_pcap(file_path)
                file_info['chart_base64'] = self.generate_pcap_chart(
                    file_info['pcap_analysis'], file_path
                )

            return file_info
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error during file analysis: {e}")
            return {"error": str(e)}

    def get_metadata(self, file_path: str) -> dict:
        """Get file metadata"""
        return {
            "Filename": os.path.basename(file_path),
            "Size (bytes)": os.path.getsize(file_path),
            "File Type": self.get_file_type(file_path)
        }

    def get_file_type(self, file_path: str) -> str:
        """Get file type from extension"""
        return file_path.split('.')[-1]

    def analyze_with_virustotal(self, file_path: str) -> dict:
        """Analyze file with VirusTotal API"""
        url = "https://www.virustotal.com/api/v3/files"
        try:
            with open(file_path, "rb") as file:
                response = requests.post(url, headers=self.headers, files={"file": file})
                if response.status_code == 200:
                    file_id = response.json().get("data", {}).get("id")
                    return self.get_virustotal_report(file_id)
                else:
                    raise Exception(f"VirusTotal API error: {response.status_code} - {response.text}")
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error during VirusTotal analysis: {e}")
            return {}

    def get_virustotal_report(self, file_id: str) -> dict:
        """Get VirusTotal analysis report"""
        url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        try:
            for _ in range(5):  # Retry up to 5 times
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    report = response.json()
                    if report.get('data', {}).get('attributes', {}).get('status') == 'completed':
                        return report
                    time.sleep(5)  # Wait before retrying
                else:
                    raise Exception(f"Failed to fetch report: {response.status_code} - {response.text}")
            raise Exception("VirusTotal analysis not completed in time")
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error fetching VirusTotal report: {e}")
            return {}

    def analyze_pcap(self, file_path: str) -> dict:
        """Analyze PCAP file"""
        capture = pyshark.FileCapture(file_path)
        protocol_counts = {}

        for packet in capture:
            protocol = packet.highest_layer
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        capture.close()
        return protocol_counts

    def generate_pcap_chart(self, protocol_counts: dict, file_path: str) -> str:
        """Generate PCAP analysis chart"""
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(protocols, counts, color='blue')
        plt.xlabel('Protocols')
        plt.ylabel('Counts')
        plt.title('PCAP Protocol Analysis')
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Save chart to a bytes buffer and encode as base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        chart_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()
        buffer.close()

        return chart_base64

