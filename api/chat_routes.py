"""
Chat Blueprint
AI-powered cybersecurity assistant via Google Gemini.
"""
import logging
import requests
from flask import Blueprint, request as flask_request
from api.responses import success_response, error_response
from config import get_config

logger = logging.getLogger(__name__)
chat_bp = Blueprint("chat", __name__)
cfg = get_config()

SYSTEM_PROMPT = (
    "You are CyberRegis AI, an advanced cybersecurity threat intelligence assistant. "
    "You have deep expertise in malware analysis, network forensics, vulnerability assessment, "
    "incident response, and threat hunting. Provide accurate, actionable, and well-structured "
    "answers. Use Markdown formatting: bullet points for lists, code blocks for technical "
    "content, and headings sparingly. Always cite MITRE ATT&CK technique IDs when relevant."
)


@chat_bp.route("/api/chat", methods=["POST"])
def chat():
    """Cybersecurity AI assistant endpoint."""
    try:
        data = flask_request.get_json(silent=True) or {}
        message = data.get("message", "").strip()
        if not message:
            return error_response("Message is required", 400)
        if len(message) > 4000:
            return error_response("Message too long (max 4000 chars)", 400)

        full_prompt = f"{SYSTEM_PROMPT}\n\nUser question: {message}"

        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": cfg.GEMINI_API_KEY,
        }
        payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024},
        }

        resp = requests.post(cfg.GEMINI_API_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()

        resp_data = resp.json()
        if "candidates" in resp_data and resp_data["candidates"]:
            ai_response = resp_data["candidates"][0]["content"]["parts"][0]["text"].strip()
        else:
            raise Exception("No response from Gemini API")

        # Legacy-compatible response
        from datetime import datetime
        result = {"response": ai_response}
        response = {
            "data": result,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "success",
        }

        try:
            from services.notification_service import notify
            notify("chat", message, response)
        except Exception:
            pass

        return response, 200

    except requests.RequestException as e:
        logger.error(f"Chat API error: {e}")
        error_msg = str(e)
        if hasattr(e, "response") and e.response is not None:
            try:
                error_msg = e.response.json().get("error", {}).get("message", str(e))
            except Exception:
                error_msg = getattr(e.response, "text", str(e))
        return error_response(f"Chat failed: {error_msg}", 500)
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return error_response(str(e), 500)
