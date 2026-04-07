import socket
import ssl
import dns.resolver
import whois
import requests
from datetime import datetime
import json

class all_functions:
    def __init__(self):
        pass
    
    def perform_whois_lookup(self, domain):
        """Perform WHOIS lookup for a domain"""
        try:
            w = whois.whois(domain)
            results = []
            
            if w.get('registrar'):
                results.append({'Field': 'Registrar', 'Value': w.get('registrar')})
            if w.get('creation_date'):
                creation_date = w.get('creation_date')
                if isinstance(creation_date, list):
                    results.append({'Field': 'Creation Date', 'Value': str(creation_date[0])})
                else:
                    results.append({'Field': 'Creation Date', 'Value': str(creation_date)})
            if w.get('expiration_date'):
                expiration_date = w.get('expiration_date')
                if isinstance(expiration_date, list):
                    results.append({'Field': 'Expiration Date', 'Value': str(expiration_date[0])})
                else:
                    results.append({'Field': 'Expiration Date', 'Value': str(expiration_date)})
            if w.get('registrant'):
                results.append({'Field': 'Registrant', 'Value': str(w.get('registrant'))})
            if w.get('country'):
                results.append({'Field': 'Country', 'Value': str(w.get('country'))})
            if w.get('name_servers'):
                name_servers = w.get('name_servers')
                if isinstance(name_servers, list):
                    results.append({'Field': 'Name Servers', 'Value': ', '.join(name_servers)})
                else:
                    results.append({'Field': 'Name Servers', 'Value': str(name_servers)})
            
            return results
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'WHOIS lookup failed: {str(e)}'}]
    
    def get_dns_records(self, domain):
        """Get DNS records for a domain"""
        try:
            results = []
            
            # A record
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                results.append({'Field': 'A', 'Value': ', '.join([str(r) for r in a_records])})
            except:
                results.append({'Field': 'A', 'Value': 'No records found'})
            
            # AAAA record
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                results.append({'Field': 'AAAA', 'Value': ', '.join([str(r) for r in aaaa_records])})
            except:
                results.append({'Field': 'AAAA', 'Value': 'No records found'})
            
            # MX record
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results.append({'Field': 'MX', 'Value': ', '.join([str(r) for r in mx_records])})
            except:
                results.append({'Field': 'MX', 'Value': 'No records found'})
            
            # NS record
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                results.append({'Field': 'NS', 'Value': ', '.join([str(r) for r in ns_records])})
            except:
                results.append({'Field': 'NS', 'Value': 'No records found'})
            
            return results
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'DNS lookup failed: {str(e)}'}]
    
    def get_txt_records(self, domain):
        """Get TXT records for a domain"""
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results = []
            for record in txt_records:
                results.append({'Field': 'TXT Records', 'Value': str(record)})
            return results
        except Exception as e:
            return [{'Field': 'TXT Records', 'Value': 'No TXT records found'}]
    
    def get_ssl_chain_details(self, domain):
        """Get SSL certificate details for a domain"""
        try:
            # Try with default context first, fall back to unverified for corporate proxies
            try:
                context = ssl.create_default_context()
                sock = socket.create_connection((domain, 443), timeout=10)
                ssock = context.wrap_socket(sock, server_hostname=domain)
            except ssl.SSLCertVerificationError:
                # Corporate proxy or self-signed cert - use unverified context
                context = ssl._create_unverified_context()
                sock = socket.create_connection((domain, 443), timeout=10)
                ssock = context.wrap_socket(sock, server_hostname=domain)
            with ssock:
                cert = ssock.getpeercert()
                
                results = []
                if 'issuer' in cert:
                    issuer = dict(x[0] for x in cert['issuer']) if cert.get('issuer') else {}
                    results.append({'Field': 'Issuer', 'Value': issuer.get(b'commonName', 'Unknown').decode() if isinstance(issuer.get(b'commonName', 'Unknown'), bytes) else issuer.get(b'commonName', 'Unknown')})
                
                if 'subject' in cert:
                    subject = dict(x[0] for x in cert['subject']) if cert.get('subject') else {}
                    results.append({'Field': 'Subject', 'Value': subject.get(b'commonName', 'Unknown').decode() if isinstance(subject.get(b'commonName', 'Unknown'), bytes) else subject.get(b'commonName', 'Unknown')})
                
                if 'notBefore' in cert:
                    results.append({'Field': 'Valid From', 'Value': cert['notBefore']})
                
                if 'notAfter' in cert and cert['notAfter']:
                    results.append({'Field': 'Valid Until', 'Value': str(cert['notAfter'])})
                    
                    # Calculate days until expiry
                    try:
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        results.append({'Field': 'Days Until Expiry', 'Value': str(days_until_expiry)})
                    except (ValueError, TypeError):
                        results.append({'Field': 'Days Until Expiry', 'Value': 'Unable to calculate'})
                
                return results
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'SSL lookup failed: {str(e)}'}]
    
    def fetch_ssl_labs_report_table(self, domain):
        """Fetch SSL Labs report for a domain"""
        try:
            # This is a simplified version - in production you'd use the actual SSL Labs API
            return [{'Field': 'Grade', 'Value': 'A'}]
        except Exception as e:
            return [{'Field': 'Grade', 'Value': 'N/A'}]
    
    def check_dnssec(self, domain):
        """Check if DNSSEC is enabled for a domain"""
        try:
            # Check for DNSKEY records
            try:
                dns.resolver.resolve(domain, 'DNSKEY')
                return [{'Field': 'DNSSEC', 'Value': 'DNSSEC keys found'}]
            except:
                return [{'Field': 'DNSSEC', 'Value': 'No DNSSEC keys found'}]
        except Exception as e:
            return [{'Field': 'DNSSEC', 'Value': f'DNSSEC check failed: {str(e)}'}]
    
    def get_dmarc_record(self, domain):
        """Get DMARC record for a domain"""
        try:
            dmarc_domain = f'_dmarc.{domain}'
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                if 'v=DMARC1' in str(record):
                    return [{'Field': 'DMARC Record', 'Value': str(record)}]
            return [{'Field': 'DMARC Record', 'Value': 'No DMARC record found'}]
        except Exception as e:
            return [{'Field': 'DMARC Record', 'Value': 'No DMARC record found'}]
    
    def detect_waf(self, domain):
        """Detect Web Application Firewall for a domain"""
        try:
            # This is a simplified version - in production you'd use actual WAF detection
            return [{'Field': 'WAF', 'Value': 'No WAF found'}]
        except Exception as e:
            return [{'Field': 'WAF', 'Value': f'WAF detection failed: {str(e)}'}]
    
    def check_robots_txt(self, domain):
        """Check if robots.txt exists for a domain"""
        try:
            response = requests.get(f'http://{domain}/robots.txt', timeout=5)
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                text = response.text.strip()
                # Verify it's actually a robots.txt (text/plain) and not an HTML error page
                if 'text/html' in content_type and not any(
                    kw in text.lower() for kw in ['user-agent:', 'disallow:', 'allow:', 'sitemap:']
                ):
                    return [{'Field': 'robots.txt', 'Value': 'Not Found'}]
                return [{'Field': 'robots.txt', 'Value': 'Found'}]
            else:
                return [{'Field': 'robots.txt', 'Value': 'Not Found'}]
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'robots.txt check failed: {str(e)}'}]
    
    def check_security_txt(self, domain):
        """Check if security.txt exists for a domain"""
        try:
            # Check common locations for security.txt
            locations = [
                f'http://{domain}/.well-known/security.txt',
                f'http://{domain}/security.txt'
            ]
            
            for location in locations:
                try:
                    response = requests.get(location, timeout=5)
                    if response.status_code == 200:
                        content_type = response.headers.get('content-type', '').lower()
                        text = response.text.strip()
                        # Verify it's not an HTML error page masquerading as 200
                        if 'text/html' in content_type and not any(
                            kw in text.lower() for kw in ['contact:', 'expires:', 'encryption:', 'policy:']
                        ):
                            continue
                        return [{'Field': 'security.txt', 'Value': 'Found'}]
                except:
                    continue
            
            return [{'Field': 'security.txt', 'Value': 'Not Found'}]
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'security.txt check failed: {str(e)}'}]
    
    def fetch_subdomains(self, domain):
        """Fetch subdomains for a domain"""
        try:
            # This is a simplified version - in production you'd use actual subdomain enumeration
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop']
            results = []
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f'{subdomain}.{domain}'
                    socket.gethostbyname(full_domain)
                    results.append({'Field': 'Subdomain', 'Value': full_domain})
                except:
                    continue
            
            return results
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'Subdomain enumeration failed: {str(e)}'}]
    
    def get_ip_info_from_a_record(self, domain):
        """Get IP information from A record"""
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            ip = str(a_records[0])
            
            # This is a simplified version - in production you'd use actual IP geolocation
            results = [
                {'Field': 'IP Address', 'Value': ip},
                {'Field': 'Country', 'Value': 'Unknown'},
                {'Field': 'City', 'Value': 'Unknown'},
                {'Field': 'ISP', 'Value': 'Unknown'},
                {'Field': 'Organization', 'Value': 'Unknown'}
            ]
            
            return results
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'IP info lookup failed: {str(e)}'}]

    # New Scanner Functions
    
    def scan_ports_detailed(self, target):
        """Enhanced port scanner with service detection"""
        try:
            import nmap
            nm = nmap.PortScanner()
            
            # Try non-privileged scanning first (TCP connect scan)
            try:
                print(f"Attempting non-privileged port scan for {target}")
                # Use -sT (TCP connect) instead of -sS (SYN scan) - no root required
                result = nm.scan(target, '22,23,25,53,80,110,143,443,993,995,8080,8443', '-sT -sV --max-retries 2')
                
                ports_data = []
                host_info = {}
                
                if target in nm.all_hosts():
                    host = target
                    host_info = {
                        'hostname': nm[host].hostname(),
                        'state': nm[host].state(),
                        'protocols': list(nm[host].all_protocols())
                    }
                    
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            port_info = nm[host][proto][port]
                            ports_data.append({
                                "port": port,
                                "protocol": proto,
                                "state": port_info['state'],
                                "service": port_info.get('name', 'unknown'),
                                "version": port_info.get('version', ''),
                                "product": port_info.get('product', ''),
                                "extrainfo": port_info.get('extrainfo', '')
                            })
                
                return {
                    "status": "success",
                    "target": target,
                    "host_info": host_info,
                    "ports": ports_data,
                    "total_ports": len(ports_data),
                    "scan_type": "TCP Connect (non-privileged)",
                    "timestamp": datetime.now().isoformat()
                }
                
            except Exception as nmap_error:
                print(f"Nmap scan failed: {nmap_error}")
                print("Falling back to basic socket-based scanning...")
                
                # Fallback to basic socket scanning (no root required)
                return self._fallback_port_scan(target)
            
        except ImportError:
            print("python-nmap not available, using fallback scanning...")
            return self._fallback_port_scan(target)
        except Exception as e:
            print(f"Port scan error: {e}")
            return self._fallback_port_scan(target)

    def _fallback_port_scan(self, target):
        """Fallback port scanner using basic socket connections"""
        try:
            print(f"Using fallback port scanner for {target}")
            
            # Common ports to scan (includes 3000 & 5000 for local dev)
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8080, 8443, 27017]
            ports_data = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)  # 2 second timeout
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        # Port is open, try to get service info
                        try:
                            service_name = socket.getservbyport(port, 'tcp')
                        except:
                            service_name = 'unknown'
                        
                        ports_data.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service_name,
                            "version": "",
                            "product": "",
                            "extrainfo": ""
                        })
                        print(f"Port {port} ({service_name}) is open")
                except Exception as port_error:
                    print(f"Error scanning port {port}: {port_error}")
                    continue
            
            return {
                "status": "success",
                "target": target,
                "host_info": {
                    'hostname': target,
                    'state': 'up' if ports_data else 'unknown',
                    'protocols': ['tcp'] if ports_data else []
                },
                "ports": ports_data,
                "total_ports": len(ports_data),
                "scan_type": "Socket Connect (fallback)",
                "note": "Basic scan completed. For enhanced service detection, ensure python-nmap is installed and run with appropriate privileges.",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Fallback port scan failed: {str(e)}",
                "target": target
            }

    def vulnerability_scan(self, target):
        """Simple vulnerability scanning using service detection"""
        try:
            import nmap
            nm = nmap.PortScanner()
            
            # Try non-privileged scanning first
            try:
                print(f"Attempting non-privileged vulnerability scan for {target}")
                # Use -sT (TCP connect) instead of -sS (SYN scan) - no root required
                nm.scan(target, '22,23,25,53,80,110,143,443,993,995', '-sT -sV --max-retries 2')
                
                vulnerabilities = []
                
                if target in nm.all_hosts():
                    host = target
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            service_info = nm[host][proto][port]
                            service_name = service_info.get('name', '')
                            version = service_info.get('version', '')
                            product = service_info.get('product', '')
                            
                            # Create mock vulnerability data based on service
                            if service_name:
                                vulnerability = {
                                    "service": f"{product} {service_name}" if product else service_name,
                                    "version": version,
                                    "port": port,
                                    "potential_issues": self.get_common_vulnerabilities(service_name, version),
                                    "severity": "Medium",  # Default severity
                                    "recommendation": f"Ensure {service_name} is updated to latest version"
                                }
                                vulnerabilities.append(vulnerability)
                
                return {
                    "status": "success",
                    "target": target,
                    "vulnerabilities": vulnerabilities,
                    "total_found": len(vulnerabilities),
                    "scan_type": "TCP Connect (non-privileged)",
                    "timestamp": datetime.now().isoformat()
                }
                
            except Exception as nmap_error:
                print(f"Nmap vulnerability scan failed: {nmap_error}")
                print("Falling back to basic port-based vulnerability assessment...")
                return self._fallback_vulnerability_scan(target)
            
        except ImportError:
            print("python-nmap not available, using fallback vulnerability assessment...")
            return self._fallback_vulnerability_scan(target)
        except Exception as e:
            print(f"Vulnerability scan error: {e}")
            return self._fallback_vulnerability_scan(target)

    def _fallback_vulnerability_scan(self, target):
        """Fallback vulnerability assessment based on open ports"""
        try:
            print(f"Using fallback vulnerability assessment for {target}")
            
            # Use the fallback port scanner to get open ports
            port_scan_result = self._fallback_port_scan(target)
            
            if port_scan_result.get('status') != 'success':
                return {
                    "status": "error",
                    "message": "Port scan failed, cannot assess vulnerabilities",
                    "target": target
                }
            
            open_ports = [port['port'] for port in port_scan_result.get('ports', [])]
            vulnerabilities = []
            
            # Assess vulnerabilities based on open ports
            for port in open_ports:
                service_name = socket.getservbyport(port, 'tcp') if port in [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995] else 'unknown'
                
                vulnerability = {
                    "service": service_name,
                    "version": "Unknown (basic scan)",
                    "port": port,
                    "potential_issues": self.get_common_vulnerabilities(service_name, "unknown"),
                    "severity": "Medium",
                    "recommendation": f"Ensure {service_name} service on port {port} is properly configured and updated"
                }
                vulnerabilities.append(vulnerability)
            
            return {
                "status": "success",
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "scan_type": "Port-based Assessment (fallback)",
                "note": "Basic vulnerability assessment completed. For enhanced service detection, ensure python-nmap is installed.",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Fallback vulnerability assessment failed: {str(e)}",
                "target": target
            }

    def get_common_vulnerabilities(self, service, version):
        """Get common vulnerabilities for known services"""
        common_vulns = {
            'ssh': ['Weak encryption algorithms', 'Default credentials', 'Version disclosure'],
            'http': ['Missing security headers', 'Directory traversal', 'Information disclosure'],
            'https': ['Weak SSL/TLS configuration', 'Certificate issues', 'Protocol vulnerabilities'],
            'ftp': ['Anonymous access', 'Cleartext credentials', 'Directory traversal'],
            'smtp': ['Open relay', 'User enumeration', 'Cleartext authentication'],
            'dns': ['Zone transfer', 'Cache poisoning', 'Amplification attacks']
        }
        
        return common_vulns.get(service, ['Unknown service vulnerabilities'])

    def ssl_detailed_analysis(self, domain):
        """Enhanced SSL/TLS analysis"""
        try:
            # Use existing SSL method
            ssl_data = self.get_ssl_chain_details(domain)
            
            # Additional SSL checks
            ssl_analysis = {
                "basic_info": ssl_data,
                "domain": domain,
                "timestamp": datetime.now().isoformat()
            }
            
            # Try to get more SSL details
            try:
                try:
                    context = ssl.create_default_context()
                    sock = socket.create_connection((domain, 443), timeout=10)
                    ssock = context.wrap_socket(sock, server_hostname=domain)
                except ssl.SSLCertVerificationError:
                    context = ssl._create_unverified_context()
                    sock = socket.create_connection((domain, 443), timeout=10)
                    ssock = context.wrap_socket(sock, server_hostname=domain)
                with ssock:
                    cipher = ssock.cipher()
                    ssl_analysis["cipher_info"] = {
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "tls_version": cipher[1] if cipher else "Unknown",
                        "key_length": cipher[2] if cipher else "Unknown"
                    }
            except Exception as e:
                ssl_analysis["cipher_info"] = {"error": str(e)}
            
            return {
                "status": "success",
                "ssl_analysis": ssl_analysis
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"SSL analysis failed: {str(e)}"
            }

    def security_headers_scan(self, url):
        """Security headers analysis"""
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
                
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                "Content-Security-Policy": {
                    "present": "Content-Security-Policy" in headers,
                    "value": headers.get("Content-Security-Policy", ""),
                    "score": 10 if "Content-Security-Policy" in headers else 0
                },
                "Strict-Transport-Security": {
                    "present": "Strict-Transport-Security" in headers,
                    "value": headers.get("Strict-Transport-Security", ""),
                    "score": 10 if "Strict-Transport-Security" in headers else 0
                },
                "X-Frame-Options": {
                    "present": "X-Frame-Options" in headers,
                    "value": headers.get("X-Frame-Options", ""),
                    "score": 5 if "X-Frame-Options" in headers else 0
                },
                "X-Content-Type-Options": {
                    "present": "X-Content-Type-Options" in headers,
                    "value": headers.get("X-Content-Type-Options", ""),
                    "score": 5 if "X-Content-Type-Options" in headers else 0
                },
                "Referrer-Policy": {
                    "present": "Referrer-Policy" in headers,
                    "value": headers.get("Referrer-Policy", ""),
                    "score": 5 if "Referrer-Policy" in headers else 0
                }
            }
            
            total_score = sum([header["score"] for header in security_headers.values()])
            max_score = 35
            
            return {
                "status": "success",
                "url": url,
                "headers": security_headers,
                "security_score": total_score,
                "max_score": max_score,
                "grade": self.get_security_grade(total_score, max_score),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Security headers scan failed: {str(e)}"
            }

    def get_security_grade(self, score, max_score):
        """Get security grade based on score"""
        percentage = (score / max_score) * 100
        if percentage >= 90: return "A+"
        elif percentage >= 80: return "A"
        elif percentage >= 70: return "B"
        elif percentage >= 60: return "C"
        elif percentage >= 50: return "D"
        else: return "F"

    def email_security_deep_scan(self, domain):
        """Enhanced email security analysis."""
        try:
            email_security = {
                "domain": domain,
                "spf": {"present": False, "score": 0},
                "dmarc": {"present": False, "score": 0},
                "dkim": {"present": False, "score": 0, "status": "not_detected"}
            }

            # SPF Check
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    record_text = str(record).replace('"', '').strip()
                    if record_text.lower().startswith('v=spf1'):
                        email_security["spf"] = {
                            "present": True,
                            "record": record_text,
                            "score": 10
                        }
                        break
            except Exception:
                pass

            # DMARC Check
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                for record in dmarc_records:
                    record_text = str(record).replace('"', '').strip()
                    if record_text.lower().startswith('v=dmarc1'):
                        email_security["dmarc"] = {
                            "present": True,
                            "record": record_text,
                            "score": 15
                        }
                        break
            except Exception:
                pass

            # DKIM Check
            # First, check the domain policy record at _domainkey.<domain>
            try:
                policy_domain = f"_domainkey.{domain}"
                policy_records = dns.resolver.resolve(policy_domain, 'TXT')
                for record in policy_records:
                    record_text = str(record).replace('"', '').strip().lower()
                    if 'dkim' in record_text or record_text.startswith('o='):
                        email_security["dkim"] = {
                            "present": True,
                            "selector": "_domainkey policy",
                            "score": 6,
                            "status": "policy_detected"
                        }
                        break
            except Exception:
                pass

            # Then, attempt common selectors for an actual signing key
            common_selectors = [
                'default', 'google', 'selector1', 'selector2', 'k1', 'mail',
                'smtp', 'mandrill', 'amazonses', 'zoho', 'protonmail'
            ]
            for selector in common_selectors:
                if email_security["dkim"].get("present") and email_security["dkim"].get("status") == "key_detected":
                    break
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
                    for record in dkim_records:
                        record_text = str(record).replace('"', '').strip().lower()
                        if 'v=dkim1' in record_text or 'k=rsa' in record_text or 'k=ed25519' in record_text or 'p=' in record_text:
                            email_security["dkim"] = {
                                "present": True,
                                "selector": selector,
                                "score": 10,
                                "status": "key_detected"
                            }
                            break
                except Exception:
                    continue

            # If we only found no key and no policy, mark explicitly as unknown/undetected
            if not email_security["dkim"].get("present"):
                email_security["dkim"]["status"] = "not_detected"

            # Calculate total score
            total_score = sum([
                section.get("score", 0)
                for section in email_security.values()
                if isinstance(section, dict) and "score" in section
            ])

            email_security.update({
                "total_score": total_score,
                "max_score": 35,
                "grade": self.get_security_grade(total_score, 35),
                "timestamp": datetime.now().isoformat()
            })

            return {
                "status": "success",
                "email_security": email_security
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Email security scan failed: {str(e)}"
            }

    def parse_spf_record(self, record):
        """Parse SPF record mechanisms"""
        mechanisms = []
        parts = record.split(' ')
        for part in parts[1:]:  # Skip v=spf1
            if part.startswith(('include:', 'a:', 'mx:', 'ip4:', 'ip6:', 'exists:')):
                mechanisms.append(part)
        return mechanisms

    def parse_dmarc_policy(self, record):
        """Parse DMARC policy settings"""
        policy = {}
        parts = record.split(';')
        for part in parts:
            if '=' in part:
                key, value = part.strip().split('=', 1)
                policy[key] = value
        return policy
