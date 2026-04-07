"""
CyberRegis Server - Main Flask Application
"""
import os
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import Config
from app.utils.logger import setup_logger
from app.utils.cache import setup_cache

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Setup CORS
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
CORS(app,
     origins=cors_origins,
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True)

# Setup Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{os.getenv('RATE_LIMIT_PER_DAY', '100')} per day", 
                    f"{os.getenv('RATE_LIMIT_PER_MINUTE', '10')} per minute"],
    storage_uri="memory://"
)

# Setup Logger
logger = setup_logger()

# Setup Cache
cache = setup_cache()

# Register Blueprints (import after limiter is created)
from app.routes import register_blueprints
register_blueprints(app, limiter)

# Initialize route handlers (after cache is set up)
from app.routes import url_routes, ip_routes, chat_routes, pcap_routes, domain_routes, security_routes, health_routes
url_routes.init_routes(limiter, cache)
ip_routes.init_routes(limiter, cache)
chat_routes.init_routes(limiter)
pcap_routes.init_routes(limiter)
domain_routes.init_routes(limiter)
security_routes.init_routes(limiter)
health_routes.init_routes(limiter)

# Preflight handler for CORS
@app.before_request
def handle_preflight():
    from flask import make_response, request
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        return response

