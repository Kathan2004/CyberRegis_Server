"""
URL Check Routes
"""
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
import traceback

from app.services.url_service import URLService
from app.services.telegram_service import TelegramService

bp = Blueprint('url', __name__, url_prefix='/api')
telegram_service = TelegramService()
url_service = None


def init_routes(limiter: Limiter, cache):
    """Initialize routes with rate limiting"""
    global url_service
    url_service = URLService(cache=cache)
    
    @bp.route("/check-url", methods=["POST"])
    @limiter.limit("20 per minute")
    def api_check_url():
        try:
            data = request.get_json()
            if not data:
                return jsonify({
                    "status": "error",
                    "message": "No data provided"
                }), 400
                
            url = data.get("url", "").strip()
            if not url:
                return jsonify({
                    "status": "error",
                    "message": "URL is required"
                }), 400
            
            result = url_service.check_url_safety(url)
            
            # Send Telegram notification only for important events
            telegram_service.send_notification("url", url, result)
            
            return jsonify(result)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error in check-url endpoint: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                "status": "error",
                "message": f"URL check failed: {str(e)}"
            }), 500
    
    @bp.route("/test-url", methods=["POST"])
    def test_url_endpoint():
        from app.utils.validators import is_valid_url
        from app.services.url_service import URLService
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
                
            url = data.get("url", "").strip()
            if not url:
                return jsonify({"status": "error", "message": "URL is required"}), 400
            
            if not is_valid_url(url):
                return jsonify({
                    "status": "error", 
                    "message": "Invalid URL format",
                    "url": url
                }), 400
            
            url_service = URLService()
            url_details = url_service._get_url_details(url)
            
            return jsonify({
                "status": "success",
                "message": "URL validation successful",
                "url": url,
                "parsed": url_details,
                "timestamp": __import__('datetime').datetime.now().isoformat()
            })
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Test URL endpoint error: {e}")
            return jsonify({
                "status": "error",
                "message": f"Test failed: {str(e)}"
            }), 500

