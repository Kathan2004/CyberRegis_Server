"""
Security Analysis Routes (Port Scanner, Vulnerability Scanner, etc.)
"""
from datetime import datetime
import socket
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter

from all_functions import all_functions

bp = Blueprint('security', __name__, url_prefix='/api')


def init_routes(limiter: Limiter):
    """Initialize routes with rate limiting"""
    
    @bp.route('/scan-ports', methods=['POST'])
    @limiter.limit("5 per minute")
    def scan_ports():
        try:
            data = request.get_json()
            target = data.get('target', '').strip()
            
            if not target:
                return jsonify({
                    'status': 'error',
                    'message': 'Target is required'
                }), 400
            
            # Validate target format (IP or domain)
            from app.utils.validators import is_valid_ip
            if not (is_valid_ip(target) or '.' in target):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid target format. Provide a valid IP address or domain name.'
                }), 400
            
            recon = all_functions()
            result = recon.scan_ports_detailed(target)
            
            # Ensure result has proper structure
            if not isinstance(result, dict):
                result = {'status': 'success', 'data': result}
            
            return jsonify(result)
            
        except TimeoutError:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Port scan timeout for {target}")
            return jsonify({
                'status': 'error',
                'message': 'Port scan timed out. The target may be unreachable or blocking connections.'
            }), 504
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Port scan error: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Port scan failed: {str(e)}'
            }), 500
    
    @bp.route('/vulnerability-scan', methods=['POST'])
    @limiter.limit("3 per minute")
    def vulnerability_scan():
        try:
            data = request.get_json()
            target = data.get('target', '').strip()
            
            if not target:
                return jsonify({
                    'status': 'error',
                    'message': 'Target is required'
                }), 400
            
            # Validate target format
            from app.utils.validators import is_valid_ip
            if not (is_valid_ip(target) or '.' in target):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid target format. Provide a valid IP address or domain name.'
                }), 400
            
            recon = all_functions()
            result = recon.vulnerability_scan(target)
            
            # Ensure result has proper structure
            if not isinstance(result, dict):
                result = {'status': 'success', 'data': result}
            
            return jsonify(result)
            
        except TimeoutError:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Vulnerability scan timeout for {target}")
            return jsonify({
                'status': 'error',
                'message': 'Vulnerability scan timed out. This scan may take longer for complex targets.'
            }), 504
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Vulnerability scan error: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Vulnerability scan failed: {str(e)}'
            }), 500
    
    @bp.route('/security-headers', methods=['POST'])
    @limiter.limit("10 per minute")
    def security_headers():
        try:
            data = request.get_json()
            url = data.get('url', '').strip()
            
            if not url:
                return jsonify({
                    'status': 'error',
                    'message': 'URL is required'
                }), 400
            
            # Validate URL format
            from app.utils.validators import is_valid_url
            if not is_valid_url(url):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid URL format. URL must start with http:// or https://'
                }), 400
            
            recon = all_functions()
            result = recon.security_headers_scan(url)
            
            # Ensure result has proper structure
            if not isinstance(result, dict):
                result = {'status': 'success', 'data': result}
            
            return jsonify(result)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Security headers scan error for {url}: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Security headers scan failed: {str(e)}'
            }), 500
    
    @bp.route('/email-security', methods=['POST'])
    @limiter.limit("10 per minute")
    def email_security():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({
                    'status': 'error',
                    'message': 'Domain is required'
                }), 400
            
            # Remove protocol if present
            domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
            
            recon = all_functions()
            result = recon.email_security_deep_scan(domain)
            
            # Ensure result has proper structure
            if not isinstance(result, dict):
                result = {'status': 'success', 'data': result}
            
            return jsonify(result)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Email security scan error for {domain}: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Email security scan failed: {str(e)}'
            }), 500

