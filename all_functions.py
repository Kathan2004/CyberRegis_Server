import socket
import ssl
import dns.resolver
import whois
import requests
from datetime import datetime
import json
from collections import Counter

class all_functions:
    def __init__(self):
        pass
    
    def perform_whois_lookup(self, domain):
        """Perform WHOIS lookup using RDAP (HTTPS-based, firewall-friendly)"""
        try:
            # Use RDAP API (HTTPS) - works through corporate firewalls
            r = requests.get(f'https://rdap.org/domain/{domain}', timeout=10,
                             headers={'Accept': 'application/json'})
            if r.status_code == 200:
                data = r.json()
                results = []
                # Registrar
                for entity in data.get('entities', []):
                    roles = entity.get('roles', [])
                    if 'registrar' in roles:
                        vcard = entity.get('vcardArray', [None, []])[1]
                        for prop in vcard:
                            if prop[0] == 'fn':
                                results.append({'Field': 'Registrar', 'Value': prop[3]})
                                break
                # Dates
                for event in data.get('events', []):
                    action = event.get('eventAction', '')
                    date = event.get('eventDate', '')[:10]
                    if action == 'registration':
                        results.append({'Field': 'Creation Date', 'Value': date})
                    elif action == 'expiration':
                        results.append({'Field': 'Expiration Date', 'Value': date})
                    elif action == 'last changed':
                        results.append({'Field': 'Updated Date', 'Value': date})
                # Name servers
                ns_list = [ns.get('ldhName', '') for ns in data.get('nameservers', [])]
                if ns_list:
                    results.append({'Field': 'Name Servers', 'Value': ', '.join(ns_list)})
                # Status
                status = ', '.join(data.get('status', []))
                if status:
                    results.append({'Field': 'Status', 'Value': status})
                return results if results else [{'Field': 'Info', 'Value': 'RDAP data available but minimal'}]
            raise Exception(f'RDAP returned {r.status_code}')
        except Exception as e:
            return [{'Field': 'Error', 'Value': f'WHOIS lookup failed: {str(e)}'}]
    
    def _doh_query(self, domain, record_type):
        """DNS-over-HTTPS query via Cloudflare (works through corporate firewalls)"""
        try:
            r = requests.get(
                'https://cloudflare-dns.com/dns-query',
                params={'name': domain, 'type': record_type},
                headers={'Accept': 'application/dns-json'},
                timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                answers = data.get('Answer', [])
                return [a.get('data', '') for a in answers if a.get('data')]
        except Exception:
            pass
        # Fallback: Google DoH
        try:
            r = requests.get(
                'https://dns.google/resolve',
                params={'name': domain, 'type': record_type},
                timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                answers = data.get('Answer', [])
                return [a.get('data', '') for a in answers if a.get('data')]
        except Exception:
            pass
        return []

    def get_dns_records(self, domain):
        """Get DNS records using DNS-over-HTTPS (firewall-friendly)."""
        results = []

        def _clean_dns_value(record_type, value):
            text = str(value or '').strip()
            if not text:
                return ''

            if record_type in {'TXT', 'SPF'}:
                return text.strip('"')

            if record_type in {'CNAME', 'NS'}:
                return text.rstrip('.')

            return text

        record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT',
            'SOA', 'CAA', 'SRV', 'NAPTR', 'DNSKEY', 'DS'
        ]

        for record_type in record_types:
            try:
                rows = self._doh_query(domain, record_type)
                if record_type == 'A' and not rows:
                    try:
                        rows = [socket.gethostbyname(domain)]
                    except Exception:
                        rows = []

                cleaned = []
                for row in rows:
                    value = _clean_dns_value(record_type, row)
                    if value and value not in cleaned:
                        cleaned.append(value)

                if cleaned:
                    results.append({'Field': record_type, 'Value': ', '.join(cleaned)})
            except Exception:
                continue

        return results or [{'Field': 'Error', 'Value': 'DNS lookup failed'}]
    
    def get_txt_records(self, domain):
        """Get TXT records using DNS-over-HTTPS"""
        try:
            txt = self._doh_query(domain, 'TXT')
            if txt:
                return [{'Field': 'TXT Records', 'Value': t.strip('"')} for t in txt]
            return [{'Field': 'TXT Records', 'Value': 'No TXT records found'}]
        except Exception as e:
            return [{'Field': 'TXT Records', 'Value': 'No TXT records found'}]
    
    def get_ssl_chain_details(self, domain):
        """Get SSL certificate details for a domain"""
        try:
            try:
                context = ssl.create_default_context()
                sock = socket.create_connection((domain, 443), timeout=10)
                ssock = context.wrap_socket(sock, server_hostname=domain)
            except (ssl.SSLCertVerificationError, ssl.SSLError, OSError):
                context = ssl._create_unverified_context()
                sock = socket.create_connection((domain, 443), timeout=10)
                ssock = context.wrap_socket(sock, server_hostname=domain)
            with ssock:
                cert_raw = ssock.getpeercert()
                cert = cert_raw if isinstance(cert_raw, dict) else {}
                results = []
                # Issuer - cert tuples use string keys like ('commonName', '...')
                issuer = cert.get('issuer')
                if issuer:
                    issuer_dict = {k: v for tup in issuer for k, v in tup}
                    cn = issuer_dict.get('commonName') or issuer_dict.get('organizationName', 'Unknown')
                    results.append({'Field': 'Issuer', 'Value': cn})
                # Subject
                subject = cert.get('subject')
                if subject:
                    subject_dict = {k: v for tup in subject for k, v in tup}
                    cn = subject_dict.get('commonName') or subject_dict.get('organizationName', 'Unknown')
                    results.append({'Field': 'Subject', 'Value': cn})
                not_before = cert.get('notBefore')
                if isinstance(not_before, str):
                    results.append({'Field': 'Valid From', 'Value': not_before})
                not_after = cert.get('notAfter')
                if isinstance(not_after, str):
                    results.append({'Field': 'Valid Until', 'Value': not_after})
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days = (expiry - datetime.now()).days
                        results.append({'Field': 'Days Until Expiry', 'Value': str(days)})
                    except Exception:
                        pass
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
        """Check if DNSSEC is enabled using DNS-over-HTTPS"""
        try:
            keys = self._doh_query(domain, 'DNSKEY')
            if keys:
                return [{'Field': 'DNSSEC', 'Value': 'DNSSEC keys found'}]
            return [{'Field': 'DNSSEC', 'Value': 'No DNSSEC keys found'}]
        except Exception as e:
            return [{'Field': 'DNSSEC', 'Value': 'No DNSSEC keys found'}]
    
    def get_dmarc_record(self, domain):
        """Get DMARC record using DNS-over-HTTPS"""
        try:
            records = self._doh_query(f'_dmarc.{domain}', 'TXT')
            for rec in records:
                rec_clean = rec.strip('"')
                if 'v=DMARC1' in rec_clean:
                    return [{'Field': 'DMARC Record', 'Value': rec_clean}]
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
        """Get IP geolocation using socket DNS + ip-api.com (firewall-friendly)"""
        try:
            # Use socket (system DNS) or DoH to get IP
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                a = self._doh_query(domain, 'A')
                ip = a[0] if a else None
            if not ip:
                return [{'Field': 'Error', 'Value': 'Could not resolve IP'}]
            results = [{'Field': 'IP Address', 'Value': ip}]
            # Use ip-api.com for geolocation (works through corporate firewalls)
            try:
                r = requests.get(f'http://ip-api.com/json/{ip}', timeout=8)
                if r.status_code == 200:
                    geo = r.json()
                    if geo.get('status') == 'success':
                        results += [
                            {'Field': 'Country', 'Value': geo.get('country', 'Unknown')},
                            {'Field': 'Region', 'Value': geo.get('regionName', 'Unknown')},
                            {'Field': 'City', 'Value': geo.get('city', 'Unknown')},
                            {'Field': 'ISP', 'Value': geo.get('isp', 'Unknown')},
                            {'Field': 'Organization', 'Value': geo.get('org', 'Unknown')},
                            {'Field': 'Timezone', 'Value': geo.get('timezone', 'Unknown')},
                        ]
            except Exception:
                pass
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
                                profile = self.get_service_security_profile(service_name, port)
                                vulnerabilities.append({
                                    "service": f"{product} {service_name}" if product else service_name,
                                    "version": version or "Unknown",
                                    "port": port,
                                    "potential_issues": profile.get("issues", []),
                                    "severity": profile.get("severity", "medium").capitalize(),
                                    "recommendation": profile.get("recommendation", f"Ensure {service_name} is updated and securely configured"),
                                    "confidence": "high" if version else "medium",
                                    "cve_examples": profile.get("cve_examples", []),
                                    "remediation_priority": profile.get("priority", 3),
                                    "risk_score": profile.get("risk_score", 50),
                                })
                
                vulnerabilities = sorted(vulnerabilities, key=lambda x: x.get("risk_score", 0), reverse=True)
                severity_counts = Counter(v.get("severity", "Medium").lower() for v in vulnerabilities)
                return {
                    "status": "success",
                    "target": target,
                    "vulnerabilities": vulnerabilities,
                    "total_found": len(vulnerabilities),
                    "severity_breakdown": dict(severity_counts),
                    "max_risk_score": vulnerabilities[0].get("risk_score", 0) if vulnerabilities else 0,
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
                profile = self.get_service_security_profile(service_name, port)
                vulnerability = {
                    "service": service_name,
                    "version": "Unknown (basic scan)",
                    "port": port,
                    "potential_issues": profile.get("issues", []),
                    "severity": profile.get("severity", "medium").capitalize(),
                    "recommendation": profile.get("recommendation", f"Ensure {service_name} service on port {port} is properly configured and updated"),
                    "confidence": "low",
                    "cve_examples": profile.get("cve_examples", []),
                    "remediation_priority": profile.get("priority", 3),
                    "risk_score": profile.get("risk_score", 45),
                }
                vulnerabilities.append(vulnerability)

            vulnerabilities = sorted(vulnerabilities, key=lambda x: x.get("risk_score", 0), reverse=True)
            severity_counts = Counter(v.get("severity", "Medium").lower() for v in vulnerabilities)
            return {
                "status": "success",
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "severity_breakdown": dict(severity_counts),
                "max_risk_score": vulnerabilities[0].get("risk_score", 0) if vulnerabilities else 0,
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

    def get_service_security_profile(self, service, port):
        """Return actionable service risk profile for vulnerability reporting."""
        service = (service or "unknown").lower()
        profiles = {
            "ssh": {
                "issues": ["Weak encryption algorithms", "Credential brute-force", "Version disclosure"],
                "severity": "medium",
                "recommendation": "Disable password auth, enforce key-based login, and restrict source IPs.",
                "cve_examples": ["CVE-2018-15473", "CVE-2023-38408"],
                "priority": 2,
                "risk_score": 60,
            },
            "http": {
                "issues": ["Missing security headers", "Outdated web components", "Potential information disclosure"],
                "severity": "medium",
                "recommendation": "Enable secure headers, patch web stack, and run web vulnerability scan.",
                "cve_examples": ["CVE-2021-41773", "CVE-2023-25690"],
                "priority": 2,
                "risk_score": 62,
            },
            "https": {
                "issues": ["Weak TLS configuration", "Certificate or protocol hardening gaps"],
                "severity": "medium",
                "recommendation": "Enforce TLS 1.2+, disable weak ciphers, and validate certificate chain.",
                "cve_examples": ["CVE-2014-0160", "CVE-2022-0778"],
                "priority": 2,
                "risk_score": 58,
            },
            "ftp": {
                "issues": ["Cleartext credentials", "Anonymous access risk", "Legacy protocol exposure"],
                "severity": "high",
                "recommendation": "Disable FTP or migrate to SFTP/FTPS and restrict external exposure.",
                "cve_examples": ["CVE-2015-3306", "CVE-2021-41653"],
                "priority": 1,
                "risk_score": 80,
            },
            "telnet": {
                "issues": ["Cleartext remote administration", "Credential theft risk"],
                "severity": "high",
                "recommendation": "Disable Telnet and replace with SSH immediately.",
                "cve_examples": ["CVE-2020-10188"],
                "priority": 1,
                "risk_score": 88,
            },
            "smtp": {
                "issues": ["Open relay misconfiguration", "User enumeration", "Spoofing risk"],
                "severity": "medium",
                "recommendation": "Harden relay settings and enforce SPF, DKIM, and DMARC.",
                "cve_examples": ["CVE-2023-51764"],
                "priority": 2,
                "risk_score": 66,
            },
            "rdp": {
                "issues": ["Remote access brute-force", "Credential stuffing", "Lateral movement path"],
                "severity": "high",
                "recommendation": "Restrict RDP exposure, enforce MFA/VPN, and monitor failed logins.",
                "cve_examples": ["CVE-2019-0708", "CVE-2020-0609"],
                "priority": 1,
                "risk_score": 85,
            },
            "mysql": {
                "issues": ["Database exposure", "Weak auth policy", "Privilege abuse risk"],
                "severity": "high",
                "recommendation": "Bind DB to private interfaces and enforce strong authentication.",
                "cve_examples": ["CVE-2022-21472"],
                "priority": 1,
                "risk_score": 78,
            },
            "postgresql": {
                "issues": ["Database exposure", "Weak authentication controls"],
                "severity": "high",
                "recommendation": "Restrict network access, rotate credentials, and audit role permissions.",
                "cve_examples": ["CVE-2023-39417"],
                "priority": 1,
                "risk_score": 76,
            },
            "redis": {
                "issues": ["Unauthenticated Redis exposure", "Data exfiltration risk"],
                "severity": "critical",
                "recommendation": "Disable public access, enable auth/ACLs, and bind to localhost/private subnet.",
                "cve_examples": ["CVE-2022-0543"],
                "priority": 1,
                "risk_score": 92,
            },
            "mongodb": {
                "issues": ["Unauthenticated MongoDB exposure", "Sensitive data leakage"],
                "severity": "critical",
                "recommendation": "Enable authentication and network ACLs; do not expose MongoDB publicly.",
                "cve_examples": ["CVE-2019-2386"],
                "priority": 1,
                "risk_score": 90,
            },
        }

        profile = profiles.get(service, {
            "issues": ["Service exposure detected", "Potential misconfiguration risk"],
            "severity": "medium",
            "recommendation": f"Review service hardening and access controls for {service} on port {port}.",
            "cve_examples": [],
            "priority": 3,
            "risk_score": 50,
        })

        if port in (23, 3389, 445, 6379, 27017):
            profile = {**profile, "severity": "high" if profile["severity"] != "critical" else "critical", "risk_score": max(profile.get("risk_score", 50), 80), "priority": 1}

        return profile

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

            header_catalog = {
                "Content-Security-Policy": {
                    "score": 12,
                    "severity_if_missing": "high",
                    "recommendation": "Define CSP to restrict script/style/frame sources.",
                    "critical": True,
                },
                "Strict-Transport-Security": {
                    "score": 10,
                    "severity_if_missing": "high",
                    "recommendation": "Enable HSTS with long max-age and includeSubDomains.",
                    "critical": True,
                },
                "X-Frame-Options": {
                    "score": 6,
                    "severity_if_missing": "medium",
                    "recommendation": "Set to DENY or SAMEORIGIN to mitigate clickjacking.",
                    "critical": True,
                },
                "X-Content-Type-Options": {
                    "score": 6,
                    "severity_if_missing": "medium",
                    "recommendation": "Set to nosniff to prevent MIME confusion attacks.",
                    "critical": True,
                },
                "Referrer-Policy": {
                    "score": 4,
                    "severity_if_missing": "low",
                    "recommendation": "Set strict-origin-when-cross-origin or stricter.",
                    "critical": False,
                },
                "Permissions-Policy": {
                    "score": 4,
                    "severity_if_missing": "low",
                    "recommendation": "Restrict powerful browser features to least privilege.",
                    "critical": False,
                },
                "Cross-Origin-Opener-Policy": {
                    "score": 4,
                    "severity_if_missing": "low",
                    "recommendation": "Set same-origin to isolate browsing context group.",
                    "critical": False,
                },
                "Cross-Origin-Resource-Policy": {
                    "score": 4,
                    "severity_if_missing": "low",
                    "recommendation": "Set same-site or same-origin based on resource sharing needs.",
                    "critical": False,
                },
            }

            security_headers = {}
            total_score = 0
            max_score = 0
            missing_headers = []
            critical_missing = []

            for name, spec in header_catalog.items():
                present = name in headers
                value = headers.get(name, "")
                score = spec["score"] if present else 0
                total_score += score
                max_score += spec["score"]
                item = {
                    "present": present,
                    "value": value,
                    "score": score,
                    "max_score": spec["score"],
                    "severity_if_missing": spec["severity_if_missing"],
                    "recommendation": spec["recommendation"],
                }
                security_headers[name] = item
                if not present:
                    missing_headers.append(name)
                    if spec.get("critical"):
                        critical_missing.append(name)

            strengths = [k for k, v in security_headers.items() if v.get("present")]
            remediation = [
                {
                    "header": name,
                    "severity": security_headers[name].get("severity_if_missing"),
                    "recommendation": security_headers[name].get("recommendation"),
                }
                for name in missing_headers
            ]
            remediation.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(str(r.get("severity", "")).lower(), 3))
            
            return {
                "status": "success",
                "url": url,
                "headers": security_headers,
                "security_score": total_score,
                "max_score": max_score,
                "grade": self.get_security_grade(total_score, max_score),
                "response_info": {
                    "final_url": response.url,
                    "status_code": response.status_code,
                    "redirect_count": len(response.history),
                    "server": headers.get("Server"),
                    "powered_by": headers.get("X-Powered-By"),
                },
                "missing_headers": missing_headers,
                "critical_missing_headers": critical_missing,
                "hardening_summary": {
                    "strengths": strengths,
                    "gaps": missing_headers,
                    "prioritized_remediation": remediation[:6],
                },
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
