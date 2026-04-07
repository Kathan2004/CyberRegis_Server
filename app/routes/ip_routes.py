"""
IP Check Routes
"""
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter

from app.services.ip_service import IPService
from app.services.telegram_service import TelegramService

bp = Blueprint('ip', __name__, url_prefix='/api')
telegram_service = TelegramService()
ip_service = None


def init_routes(limiter: Limiter, cache):
    """Initialize routes with rate limiting"""
    global ip_service
    ip_service = IPService(cache=cache)
    
    @bp.route("/check-ip", methods=["POST"])
    @limiter.limit("20 per minute")
    def api_check_ip():
        try:
            data = request.get_json()
            ip = data.get("ip", "").strip()
            if not ip:
                return jsonify({
                    "error": "IP address is required"
                }), 400
            
            result = ip_service.check_ip_reputation(ip)
            
            # Send Telegram notification
            telegram_service.send_notification("ip", ip, result)
            
            return jsonify(result)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error in check-ip endpoint: {e}")
            return jsonify({
                "error": "IP check failed",
                "message": str(e)
            }), 500

