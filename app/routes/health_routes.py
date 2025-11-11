"""
Health Check and Status Routes
"""
from datetime import datetime
from flask import Blueprint, jsonify, make_response, request
from flask_limiter import Limiter

bp = Blueprint('health', __name__, url_prefix='/api')


def init_routes(limiter: Limiter):
    """Initialize routes with rate limiting"""
    
    @bp.route('/health', methods=['GET'])
    def health_check():
        try:
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "CyberRegis Security Scanner",
                "version": "1.0.0"
            })
        except Exception as e:
            return jsonify({
                "status": "unhealthy",
                "error": str(e)
            }), 500
    
    @bp.route('/status', methods=['GET'])
    def system_status():
        try:
            import psutil
            import os
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            status_data = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "system": {
                    "cpu_usage": f"{cpu_percent}%",
                    "memory_usage": f"{memory.percent}%",
                    "memory_available": f"{memory.available // (1024**3):.1f} GB",
                    "disk_usage": f"{disk.percent}%",
                    "disk_free": f"{disk.free // (1024**3):.1f} GB"
                },
                "process": {
                    "pid": os.getpid(),
                    "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
                }
            }
            
            return jsonify(status_data)
            
        except ImportError:
            return jsonify({
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "message": "Basic status available. Install psutil for detailed system metrics.",
                "system": "psutil not available"
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Status check failed: {str(e)}"
            }), 500
    
    @bp.route('/monitoring-results', methods=['GET'])
    def get_monitoring_results():
        """Optimized monitoring results endpoint - returns cached/lightweight data"""
        try:
            # Use cached system info to avoid slow operations
            import sys
            import os
            
            # Lightweight response - no heavy system calls
            monitoring_data = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "server_status": "running",
                "system_info": {
                    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    "active_endpoints": [
                        "/api/check-url",
                        "/api/check-ip", 
                        "/api/analyze-domain",
                        "/api/scan-ports",
                        "/api/vulnerability-scan",
                        "/api/security-headers",
                        "/api/email-security",
                        "/api/analyze-pcap",
                        "/api/chat",
                        "/api/health",
                        "/api/status"
                    ]
                }
            }
            
            return jsonify(monitoring_data)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Monitoring results error: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to get monitoring results: {str(e)}'
            }), 500
    
    @bp.route('/test', methods=['GET', 'POST', 'OPTIONS'])
    def test_endpoint():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
            response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            return response
        
        return jsonify({
            "status": "success",
            "message": "CORS test successful",
            "method": request.method,
            "timestamp": datetime.now().isoformat()
        })

