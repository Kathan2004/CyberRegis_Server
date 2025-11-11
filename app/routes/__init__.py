"""
Route blueprints registration
"""
from flask import Flask
from flask_limiter import Limiter

from app.routes import (
    url_routes,
    ip_routes,
    chat_routes,
    pcap_routes,
    domain_routes,
    security_routes,
    health_routes
)


def register_blueprints(app: Flask, limiter: Limiter):
    """Register all route blueprints"""
    app.register_blueprint(url_routes.bp)
    app.register_blueprint(ip_routes.bp)
    app.register_blueprint(chat_routes.bp)
    app.register_blueprint(pcap_routes.bp)
    app.register_blueprint(domain_routes.bp)
    app.register_blueprint(security_routes.bp)
    app.register_blueprint(health_routes.bp)

