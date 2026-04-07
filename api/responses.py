"""
Standardized API Response Format
All endpoints return responses through these helpers.
"""
from datetime import datetime
from flask import jsonify
from typing import Any, Dict, List, Optional


def success_response(data: Any = None, message: str = None,
                     meta: Dict = None, status_code: int = 200):
    """Return a standardized success response."""
    body = {
        "status": "success",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    if message:
        body["message"] = message
    if data is not None:
        body["data"] = data
    if meta:
        body["meta"] = meta
    return jsonify(body), status_code


def error_response(message: str, status_code: int = 400,
                   error_code: str = None, details: Any = None):
    """Return a standardized error response."""
    body = {
        "status": "error",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "error": {
            "message": message,
            "code": error_code or f"ERR_{status_code}",
        }
    }
    if details:
        body["error"]["details"] = details
    return jsonify(body), status_code


def paginated_response(items: List, total: int, limit: int, offset: int,
                       resource_name: str = "items"):
    """Return a paginated list response."""
    return success_response(
        data={resource_name: items},
        meta={
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total
        }
    )
