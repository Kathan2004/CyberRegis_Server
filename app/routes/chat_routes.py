"""
Chat Routes
"""
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter

from app.services.gemini_service import GeminiService
from app.services.telegram_service import TelegramService
from app.models.response_formatter import PrettyJSONResponse

bp = Blueprint('chat', __name__, url_prefix='/api')
gemini_service = GeminiService()
telegram_service = TelegramService()


def init_routes(limiter: Limiter):
    """Initialize routes with rate limiting"""
    
    @bp.route("/chat", methods=["POST"])
    @limiter.limit("10 per minute")
    def api_chat():
        try:
            data = request.get_json()
            message = data.get("message", "").strip()
            if not message:
                return jsonify(PrettyJSONResponse.format({"error": "Message is required"})), 400
            
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.info(f"Processing chat message: {message}")
            
            # Generate response using Gemini
            ai_response = gemini_service.generate_response(message)
            
            result = {"response": ai_response}
            formatted_response = PrettyJSONResponse.format(result)
            
            # Don't send Telegram notifications for chat (too frequent)
            # telegram_service.send_notification("chat", message, formatted_response)
            
            return jsonify(formatted_response)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Error in chat endpoint: {e}")
            return jsonify(PrettyJSONResponse.format({
                "error": "Chat processing failed",
                "message": str(e)
            })), 500

