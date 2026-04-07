"""
PCAP Analysis Routes
"""
import os
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter

from app.models.analysis_report import AnalysisReport
from app.models.response_formatter import PrettyJSONResponse
from app.services.telegram_service import TelegramService
from app.config import Config

bp = Blueprint('pcap', __name__, url_prefix='/api')
telegram_service = TelegramService()


def init_routes(limiter: Limiter):
    """Initialize routes with rate limiting"""
    
    @bp.route("/analyze-pcap", methods=["POST"])
    @limiter.limit("5 per minute")
    def analyze_pcap():
        try:
            if 'file' not in request.files:
                return jsonify(PrettyJSONResponse.format({
                    "error": "No file provided",
                    "message": "Please upload a PCAP file"
                })), 400

            file = request.files['file']
            if not file.filename.endswith(('.pcap', '.cap', '.pcapng')):
                return jsonify(PrettyJSONResponse.format({
                    "error": "Invalid file type",
                    "message": "Only .pcap, .cap, or .pcapng files are supported"
                })), 400

            upload_dir = Config.UPLOAD_FOLDER
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, file.filename)
            file.save(file_path)

            report = AnalysisReport()
            file_info = report.analyze_file(file_path)

            if "error" in file_info:
                return jsonify(PrettyJSONResponse.format({
                    "error": "Analysis failed",
                    "message": file_info["error"]
                })), 500

            result = {
                "metadata": file_info.get("metadata", {}),
                "virustotal": file_info.get("virustotal", {}),
                "pcap_analysis": file_info.get("pcap_analysis", {}),
                "chart_base64": file_info.get("chart_base64", "")
            }
            formatted_response = PrettyJSONResponse.format(result)
            
            # Send Telegram notification
            telegram_service.send_notification("pcap", file.filename, formatted_response)
            
            return jsonify(formatted_response)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error in PCAP analysis: {e}")
            return jsonify(PrettyJSONResponse.format({
                "error": "Server error",
                "message": str(e)
            })), 500

