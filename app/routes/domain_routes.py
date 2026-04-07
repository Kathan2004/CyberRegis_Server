"""
Domain Analysis Routes
"""
import requests
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
import traceback

from all_functions import all_functions

bp = Blueprint('domain', __name__, url_prefix='/api')


def init_routes(limiter: Limiter):
    """Initialize routes with rate limiting"""
    
    @bp.route('/analyze-domain', methods=['POST'])
    @limiter.limit("10 per minute")
    def analyze_domain():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({
                    'status': 'error',
                    'message': 'Domain is required'
                }), 400
            
            # Initialize the reconnaissance class
            recon = all_functions()
            logger = None
            
            # Collect all domain information
            domain_info = {
                'domain': domain,
                'whois': {},
                'dns_records': {},
                'ssl_info': {},
                'security_features': {},
                'subdomains': [],
                'geolocation': {}
            }
            
            recommendations = []
            
            # Initialize logger once
            from app.utils.logger import setup_logger
            logger = setup_logger()
            
            # WHOIS Information (with timeout protection)
            try:
                whois_data = recon.perform_whois_lookup(domain)
                if whois_data and isinstance(whois_data, list):
                    whois_info = {}
                    for item in whois_data:
                        field = item.get('Field', '').lower()
                        value = item.get('Value', '')
                        if 'registrar' in field:
                            whois_info['registrar'] = value
                        elif 'created' in field or 'creation' in field:
                            whois_info['creation_date'] = value
                        elif 'expires' in field or 'expiration' in field:
                            whois_info['expiration_date'] = value
                        elif 'registrant' in field:
                            whois_info['registrant'] = value
                        elif 'country' in field:
                            whois_info['country'] = value
                        elif 'name servers' in field:
                            whois_info['name_servers'] = value.split(', ')
                    domain_info['whois'] = whois_info
            except Exception as e:
                logger.warning(f"WHOIS lookup failed for {domain}: {e}")
                domain_info['whois'] = {'error': 'WHOIS lookup unavailable'}
            
            # DNS Records (with timeout protection)
            try:
                dns_data = recon.get_dns_records(domain)
                if dns_data and isinstance(dns_data, list):
                    dns_records = {}
                    for item in dns_data:
                        record_type = item.get('Field', '')
                        value = item.get('Value', '')
                        if value and 'No records found' not in value and 'Error' not in value:
                            dns_records[record_type] = value.split(', ')
                    domain_info['dns_records'] = dns_records
            except Exception as e:
                logger.warning(f"DNS lookup failed for {domain}: {e}")
                domain_info['dns_records'] = {'error': 'DNS lookup unavailable'}
            
            # SSL Certificate Information (with timeout protection)
            try:
                ssl_data = recon.get_ssl_chain_details(domain)
                if ssl_data and isinstance(ssl_data, list):
                    ssl_info = {}
                    for item in ssl_data:
                        field = item.get('Field', '').lower()
                        value = item.get('Value', '')
                        if 'issuer' in field:
                            ssl_info['issuer'] = value
                        elif 'subject' in field:
                            ssl_info['subject'] = value
                        elif 'valid from' in field:
                            ssl_info['valid_from'] = value
                        elif 'valid until' in field:
                            ssl_info['valid_until'] = value
                        elif 'days until expiry' in field:
                            try:
                                ssl_info['days_until_expiry'] = int(value)
                            except:
                                ssl_info['days_until_expiry'] = value
                    ssl_info['valid'] = True if ssl_info else False
                    domain_info['ssl_info'] = ssl_info
            except Exception as e:
                logger.warning(f"SSL lookup failed for {domain}: {e}")
                domain_info['ssl_info'] = {'valid': False, 'error': 'SSL lookup unavailable'}
            
            # Security Features (with timeout protection)
            security_features = {}
            
            # DNSSEC
            try:
                dnssec_data = recon.check_dnssec(domain)
                dnssec_enabled = False
                if dnssec_data and isinstance(dnssec_data, list):
                    for item in dnssec_data:
                        if 'keys found' in item.get('Value', '').lower():
                            dnssec_enabled = True
                            break
                security_features['dnssec'] = dnssec_enabled
            except Exception as e:
                logger.warning(f"DNSSEC check failed for {domain}: {e}")
                security_features['dnssec'] = False
            
            domain_info['security_features'] = security_features
            
            # Generate recommendations
            if not security_features.get('dnssec', False):
                recommendations.append("Enable DNSSEC for enhanced DNS security")
            
            if domain_info['ssl_info'].get('days_until_expiry', 0) < 30:
                recommendations.append("SSL certificate expires soon - plan for renewal")
            
            response_data = {
                'status': 'success',
                'domain_info': domain_info,
                'recommendations': recommendations,
                'timestamp': datetime.now().isoformat()
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            from app.utils.logger import setup_logger
            logger = setup_logger()
            logger.error(f"Domain analysis error: {e}")
            logger.error(traceback.format_exc())
            return jsonify({
                'status': 'error',
                'message': f'Domain analysis failed: {str(e)}'
            }), 500

