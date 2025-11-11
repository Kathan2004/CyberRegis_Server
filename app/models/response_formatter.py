"""
Response formatter model
"""
import json
import html
from datetime import datetime
from typing import Dict


class PrettyJSONResponse:
    """Custom JSON Response Formatter"""
    
    @staticmethod
    def format(data: Dict) -> Dict:
        """Format JSON response with pretty-printed HTML and metadata."""
        formatted_json = json.dumps(data, indent=2, sort_keys=True)
        return {
            "data": data,
            "formatted": f"<pre style='color: #22c55e; background: black; padding: 0;'>{html.escape(formatted_json)}</pre>",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "success" if "error" not in data else "error"
        }

