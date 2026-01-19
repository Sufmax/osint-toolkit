"""
Wrapper pour exécuter les outils OSINT de manière uniforme et sécurisée.
"""
import subprocess
import json
import tempfile
import os
import re
import ipaddress
import logging
from datetime import datetime

import requests

# Logger pour ce module
logger = logging.getLogger(__name__)

# DNS
import dns.resolver
import dns.reversename
import dns.exception

# WHOIS
import whois

# Phone
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers import PhoneNumberFormat

# Wayback
from waybackpy import WaybackMachineCDXServerAPI

# Email validator
from email_validator import validate_email, EmailNotValidError

# New OSINT Tools (lightweight)
from tools import (
    ExifAnalyzer,
    SubdomainFinder,
    SSLAnalyzer,
    HashLookup,
    MACLookup,
    SocialAnalyzer,
    MaigretRunner
)


class OSINTRunner:
    """Exécute les outils OSINT avec gestion des timeouts et erreurs."""
    
    # Timeout par défaut (secondes)
    DEFAULT_TIMEOUT = 60
    
    # Sites populaires pour Sherlock (mode rapide)
    TOP_SITES = [
        "Instagram", "Twitter", "Facebook", "TikTok", "YouTube",
        "Reddit", "GitHub", "LinkedIn", "Pinterest", "Twitch",
        "Snapchat", "Steam", "Spotify", "Telegram", "Discord",
        "Medium", "Tumblr", "VK", "Flickr", "DeviantArt"
    ]
    
    def __init__(self, socketio=None):
        """
        Initialise le runner.
        
        Args:
            socketio: Instance Flask-SocketIO pour les updates temps réel
        """
        self.socketio = socketio
    
    def emit_progress(self, sid, tool, message, progress=None, result=None):
        """Émet un événement de progression via WebSocket."""
        if self.socketio and sid:
            self.socketio.emit('progress', {
                'tool': tool,
                'message': message,
                'progress': progress,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }, room=sid)
    
    def get_available_tools(self):
        """Retourne la liste des outils disponibles."""
        return {
            'sherlock': {
                'name': 'Username Search',
                'description': 'Search username across 400+ sites'
            },
            'holehe': {
                'name': 'Email Accounts',
                'description': 'Check email registration on 120+ sites'
            },
            'email_validator': {
                'name': 'Email Validator',
                'description': 'Validate email syntax and domain'
            },
            'whois': {
                'name': 'WHOIS Lookup',
                'description': 'Domain registration info'
            },
            'dns': {
                'name': 'DNS Lookup',
                'description': 'DNS records lookup'
            },
            'phone': {
                'name': 'Phone Analysis',
                'description': 'Phone number validation and info'
            },
            'ip': {
                'name': 'IP Lookup',
                'description': 'IP address information'
            },
            'wayback': {
                'name': 'Wayback Machine',
                'description': 'Historical website archives'
            },
            # New lightweight tools
            'exif': {
                'name': 'EXIF Analyzer',
                'description': 'Extract image metadata (GPS, camera, date)'
            },
            'subdomains': {
                'name': 'Subdomain Finder',
                'description': 'Discover subdomains via CT logs and APIs'
            },
            'ssl': {
                'name': 'SSL Analyzer',
                'description': 'Analyze SSL/TLS certificates'
            },
            'hash': {
                'name': 'Hash Lookup',
                'description': 'Check file hashes against threat intel DBs'
            },
            'mac': {
                'name': 'MAC Lookup',
                'description': 'Identify device vendor from MAC address'
            },
            'social': {
                'name': 'Social Analyzer',
                'description': 'Find social profiles from email/username'
            },
            'maigret': {
                'name': 'Maigret Search',
                'description': 'Advanced username search on 3000+ sites'
            }
        }
    
    # ==================== SHERLOCK ====================
    
    def run_sherlock(self, username, sid=None, fast_mode=True, timeout=120):
        """
        Recherche un username avec Sherlock.
        Parse la sortie stdout pour des résultats fiables.
        """
        self.emit_progress(sid, 'sherlock', f"Recherche de '{username}'...", 0)
        
        site_timeout = min(timeout // 10, 15)
        
        cmd = [
            "sherlock",
            username,
            "--timeout", str(site_timeout),
            "--print-found",
            "--no-color"  # Évite les codes ANSI
        ]
        
        # Mode rapide: limiter aux sites populaires
        if fast_mode:
            for site in self.TOP_SITES:
                cmd.extend(["--site", site])
        
        try:
            import time
            start_time = time.time()
            
            # Exécuter Sherlock et capturer la sortie avec encoding explicite pour Windows
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout
            )
            
            found_sites = []
            seen_urls = set()
            
            # Debug logging
            logger.debug(f"Sherlock stdout length: {len(process.stdout or '')}")
            logger.debug(f"Sherlock stderr length: {len(process.stderr or '')}")
            
            # Parser la sortie stdout
            # Combiner stdout et stderr car Sherlock peut écrire sur les deux
            combined_output = (process.stdout or '') + '\n' + (process.stderr or '')
            
            # Normaliser les fins de ligne (Windows \r\n -> \n)
            combined_output = combined_output.replace('\r\n', '\n').replace('\r', '\n')
            
            for line in combined_output.split('\n'):
                line = line.strip()
                if '[+]' in line and 'http' in line:
                    # Pattern: [+] SiteName: URL (SiteName peut contenir des points)
                    # Essayer plusieurs patterns
                    patterns = [
                        r'\[\+\]\s*([^:]+):\s*(https?://[^\s]+)',  # Standard
                        r'\[\+\]\s*(.+?):\s*(https?://[^\s]+)',     # Non-greedy
                    ]
                    
                    for pattern in patterns:
                        match = re.search(pattern, line)
                        if match:
                            site_name = match.group(1).strip()
                            url = match.group(2).strip().rstrip('.,;:!?)"\'')  # Nettoyer l'URL
                            
                            if site_name and url and url not in seen_urls:
                                seen_urls.add(url)
                                found_sites.append({
                                    'site': site_name,
                                    'url': url
                                })
                                self.emit_progress(
                                    sid, 'sherlock',
                                    f"Trouvé: {site_name}",
                                    min(90, len(found_sites) * 2),
                                    {'site': site_name, 'url': url}
                                )
                            break
            
            logger.debug(f"Found {len(found_sites)} sites from stdout parsing")
            
            elapsed = time.time() - start_time
            self.emit_progress(sid, 'sherlock', "Recherche terminée", 100)
            
            return {
                'success': True,
                'username': username,
                'found': found_sites,
                'count': len(found_sites),
                'mode': 'fast' if fast_mode else 'full',
                'duration_seconds': round(elapsed, 2)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'username': username,
                'error': f'Timeout dépassé ({timeout}s)',
                'found': [],
                'count': 0
            }
        except FileNotFoundError:
            return {
                'success': False,
                'username': username,
                'error': 'Sherlock non installé. Exécutez: pip install sherlock-project'
            }
        except Exception as e:
            return {
                'success': False,
                'username': username,
                'error': str(e)
            }
    
    # ==================== HOLEHE ====================
    
    def run_holehe(self, email, sid=None, timeout=120):
        """
        Vérifie sur quels sites un email est enregistré.
        """
        self.emit_progress(sid, 'holehe', f"Vérification de '{email}'...", 0)
        
        try:
            result = subprocess.run(
                ["holehe", email, "--only-used", "--no-color"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout
            )
            
            found_sites = []
            
            # Combiner stdout et stderr, normaliser les fins de ligne
            combined_output = (result.stdout or '') + '\n' + (result.stderr or '')
            combined_output = combined_output.replace('\r\n', '\n').replace('\r', '\n')
            lines = combined_output.split('\n')
            
            logger.debug(f"Holehe output lines: {len(lines)}")
            
            for i, line in enumerate(lines):
                progress = int((i / max(len(lines), 1)) * 100)
                line = line.strip()
                
                if '[+]' in line:
                    # Pattern plus flexible pour holehe
                    match = re.search(r'\[\+\]\s*([\w.]+)', line)
                    if match:
                        site = match.group(1)
                        found_sites.append({
                            'site': site,
                            'exists': True,
                            'method': 'registration_check'
                        })
                        self.emit_progress(
                            sid, 'holehe',
                            f"Trouvé: {site}",
                            progress,
                            {'site': site}
                        )
            
            logger.debug(f"Holehe found {len(found_sites)} sites")
            self.emit_progress(sid, 'holehe', "Vérification terminée", 100)
            
            return {
                'success': True,
                'email': email,
                'found': found_sites,
                'count': len(found_sites)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'email': email,
                'error': 'Timeout dépassé'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'email': email,
                'error': 'Holehe non installé. Exécutez: pip install holehe'
            }
        except Exception as e:
            return {
                'success': False,
                'email': email,
                'error': str(e)
            }
    
    # ==================== EMAIL VALIDATOR ====================
    
    def run_email_validator(self, email, sid=None, check_dns=True):
        """
        Valide une adresse email (syntaxe + DNS).
        """
        self.emit_progress(sid, 'email_validator', f"Validation de '{email}'...", 30)
        
        try:
            result = validate_email(
                email,
                check_deliverability=check_dns,
                allow_smtputf8=True,
                globally_deliverable=True,
                timeout=10
            )
            
            self.emit_progress(sid, 'email_validator', "Validation terminée", 100)
            
            return {
                'success': True,
                'valid': True,
                'email': result.email,
                'local_part': result.local_part,
                'domain': result.domain,
                'ascii_email': result.ascii_email,
                'ascii_domain': result.ascii_domain,
                'smtputf8': result.smtputf8,
                'dns_checked': check_dns
            }
            
        except EmailNotValidError as e:
            self.emit_progress(sid, 'email_validator', "Email invalide", 100)
            return {
                'success': True,
                'valid': False,
                'email': email,
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'email': email,
                'error': str(e)
            }
    
    # ==================== WHOIS ====================
    
    def run_whois(self, domain, sid=None):
        """
        Récupère les informations WHOIS d'un domaine.
        """
        self.emit_progress(sid, 'whois', f"Requête WHOIS pour '{domain}'...", 30)
        
        try:
            w = whois.whois(domain)
            
            def format_date(date_val):
                if isinstance(date_val, list):
                    date_val = date_val[0] if date_val else None
                if hasattr(date_val, 'isoformat'):
                    return date_val.isoformat()
                return str(date_val) if date_val else None
            
            def to_list(val):
                if isinstance(val, list):
                    return [str(v).rstrip('.') for v in val if v]
                return [str(val).rstrip('.')] if val else []
            
            self.emit_progress(sid, 'whois', "Requête terminée", 100)
            
            return {
                'success': True,
                'domain': domain,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': format_date(w.creation_date),
                'expiration_date': format_date(w.expiration_date),
                'updated_date': format_date(w.updated_date),
                'name_servers': to_list(w.name_servers),
                'status': to_list(w.status),
                'emails': to_list(w.emails),
                'dnssec': w.dnssec,
                'registrant': {
                    'name': w.name,
                    'org': w.org,
                    'country': w.country,
                    'state': w.state,
                    'city': w.city
                }
            }
            
        except Exception as e:
            self.emit_progress(sid, 'whois', "Erreur WHOIS", 100)
            return {
                'success': False,
                'domain': domain,
                'error': str(e)
            }
    
    # ==================== DNS ====================
    
    def run_dns(self, domain, sid=None, record_types=None):
        """
        Effectue des requêtes DNS sur un domaine.
        """
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        self.emit_progress(sid, 'dns', f"Requêtes DNS pour '{domain}'...", 0)
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0
        
        results = {
            'success': True,
            'domain': domain,
            'records': {},
            'errors': []
        }
        
        for i, rtype in enumerate(record_types):
            progress = int((i / len(record_types)) * 100)
            self.emit_progress(sid, 'dns', f"Requête {rtype}...", progress)
            
            try:
                answers = resolver.resolve(domain, rtype)
                records = []
                
                for rdata in answers:
                    if rtype == 'MX':
                        records.append({
                            'priority': rdata.preference,
                            'host': str(rdata.exchange).rstrip('.')
                        })
                    elif rtype == 'SOA':
                        records.append({
                            'mname': str(rdata.mname).rstrip('.'),
                            'rname': str(rdata.rname).rstrip('.'),
                            'serial': rdata.serial
                        })
                    elif rtype == 'TXT':
                        txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                        records.append(txt)
                    else:
                        records.append(str(rdata).rstrip('.'))
                
                results['records'][rtype] = records
                
            except dns.resolver.NXDOMAIN:
                results['errors'].append(f"{rtype}: Domaine inexistant")
                results['success'] = False
            except dns.resolver.NoAnswer:
                results['records'][rtype] = []
            except dns.resolver.Timeout:
                results['errors'].append(f"{rtype}: Timeout")
            except dns.exception.DNSException as e:
                results['errors'].append(f"{rtype}: {str(e)}")
        
        # Vérifications sécurité email
        self.emit_progress(sid, 'dns', "Vérification SPF/DMARC...", 90)
        
        security = {}
        
        # SPF - 🟠 Exceptions typées au lieu de bare except
        try:
            txt_records = results['records'].get('TXT', [])
            spf = [r for r in txt_records if 'v=spf1' in r]
            security['spf'] = spf[0] if spf else None
        except (KeyError, IndexError, TypeError) as e:
            # KeyError si 'TXT' absent, IndexError si liste vide, TypeError si None
            security['spf'] = None
        
        # DMARC - 🟠 Exceptions typées au lieu de bare except
        try:
            dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            security['dmarc'] = str(list(dmarc_answers)[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout,
                dns.exception.DNSException, IndexError) as e:
            # Exceptions DNS ou liste vide
            security['dmarc'] = None
        
        results['security'] = security
        
        self.emit_progress(sid, 'dns', "Requêtes terminées", 100)
        
        return results
    
    # ==================== PHONE ====================
    
    def run_phone(self, number, sid=None, default_region='FR'):
        """
        Analyse un numéro de téléphone.
        """
        self.emit_progress(sid, 'phone', f"Analyse de '{number}'...", 30)
        
        try:
            parsed = phonenumbers.parse(number, default_region)
            
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            
            num_type = phonenumbers.number_type(parsed)
            type_names = {
                0: "Fixe",
                1: "Mobile",
                2: "Fixe ou Mobile",
                3: "Numéro vert",
                4: "Numéro surtaxé",
                5: "VoIP",
                6: "Personnel",
                99: "Inconnu"
            }
            
            country_code = parsed.country_code
            region_code = phonenumbers.region_code_for_number(parsed)
            location = geocoder.description_for_number(parsed, "fr")
            carrier_name = carrier.name_for_number(parsed, "fr")
            time_zones = list(timezone.time_zones_for_number(parsed))
            
            formats = {
                'E164': phonenumbers.format_number(parsed, PhoneNumberFormat.E164),
                'international': phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
                'national': phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
            }
            
            self.emit_progress(sid, 'phone', "Analyse terminée", 100)
            
            return {
                'success': True,
                'valid': is_valid,
                'possible': is_possible,
                'input': number,
                'country_code': country_code,
                'region': region_code,
                'location': location or None,
                'carrier': carrier_name or None,
                'type': type_names.get(num_type, "Inconnu"),
                'timezones': time_zones,
                'formats': formats
            }
            
        except phonenumbers.NumberParseException as e:
            self.emit_progress(sid, 'phone', "Numéro invalide", 100)
            return {
                'success': True,
                'valid': False,
                'input': number,
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'input': number,
                'error': str(e)
            }
    
    # ==================== IP (via API publique HTTPS) ====================
    
    def run_ip(self, ip_address, sid=None):
        """
        Recherche les informations d'une adresse IP via API publique.
        
        🔴 SÉCURITÉ: Migration vers HTTPS (ipinfo.io)
        - Ancien: http://ip-api.com (HTTP non chiffré, vulnérable MITM)
        - Nouveau: https://ipinfo.io (HTTPS natif, gratuit 50k req/mois)
        """
        self.emit_progress(sid, 'ip', f"Recherche pour '{ip_address}'...", 30)
        
        # Vérifier si IP privée
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                self.emit_progress(sid, 'ip', "IP privée détectée", 100)
                return {
                    'success': True,
                    'ip': ip_address,
                    'is_private': True,
                    'error': 'Adresse IP privée (non routable sur Internet)'
                }
            if ip_obj.is_loopback:
                return {
                    'success': True,
                    'ip': ip_address,
                    'is_private': True,
                    'error': 'Adresse IP loopback (localhost)'
                }
        except ValueError:
            return {
                'success': False,
                'ip': ip_address,
                'error': 'Format d\'adresse IP invalide'
            }
        
        try:
            # 🔴 HTTPS: Utiliser ipinfo.io (gratuit, HTTPS natif, pas de clé requise)
            response = requests.get(
                f'https://ipinfo.io/{ip_address}/json',
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'OSINT-Toolkit/1.0'
                },
                timeout=10
            )
            
            # Gérer les erreurs HTTP
            if response.status_code == 429:
                return {
                    'success': False,
                    'ip': ip_address,
                    'error': 'Rate limit atteint (50k req/mois). Réessayez plus tard.'
                }
            
            if response.status_code != 200:
                return {
                    'success': False,
                    'ip': ip_address,
                    'error': f'Erreur API: HTTP {response.status_code}'
                }
            
            data = response.json()
            
            # ipinfo.io retourne 'bogon': true pour les IPs réservées
            if data.get('bogon'):
                return {
                    'success': True,
                    'ip': ip_address,
                    'is_private': True,
                    'error': 'Adresse IP réservée (bogon)'
                }
            
            self.emit_progress(sid, 'ip', "Recherche terminée", 100)
            
            # Parser les coordonnées (format "lat,lon")
            loc = data.get('loc', '')
            lat, lon = None, None
            if loc and ',' in loc:
                try:
                    lat, lon = map(float, loc.split(','))
                except (ValueError, TypeError):
                    pass
            
            # Extraire le numéro ASN (format "AS12345 Nom")
            org_info = data.get('org', '')
            asn_match = re.search(r'AS(\d+)', org_info)
            asn_number = asn_match.group(1) if asn_match else None
            asn_name = org_info.split(' ', 1)[1] if ' ' in org_info else org_info
            
            return {
                'success': True,
                'ip': ip_address,
                'is_private': False,
                'asn': {
                    'number': asn_number,
                    'name': asn_name,
                    'description': org_info,
                    'country': data.get('country', ''),
                    'registry': None
                },
                'network': {
                    'isp': data.get('org', ''),
                    'org': data.get('org', ''),
                    'country': data.get('country', '')
                },
                'location': {
                    'country': data.get('country', ''),
                    'country_code': data.get('country', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'zip': data.get('postal', ''),
                    'lat': lat,
                    'lon': lon,
                    'timezone': data.get('timezone', '')
                },
                'organization': data.get('org', ''),
                'hostname': data.get('hostname', '')
            }
            
        except requests.Timeout:
            return {
                'success': False,
                'ip': ip_address,
                'error': 'Timeout lors de la requête'
            }
        except requests.RequestException as e:
            return {
                'success': False,
                'ip': ip_address,
                'error': f'Erreur réseau: {str(e)}'
            }
        except (ValueError, KeyError) as e:
            return {
                'success': False,
                'ip': ip_address,
                'error': f'Erreur parsing réponse: {str(e)}'
            }
    
    # ==================== WAYBACK ====================
    
    def run_wayback(self, url, sid=None, limit=20):
        """
        Récupère les informations Wayback Machine pour une URL.
        """
        self.emit_progress(sid, 'wayback', f"Recherche pour '{url}'...", 30)
        
        try:
            cdx = WaybackMachineCDXServerAPI(
                url=url,
                user_agent="OSINT-Toolkit/1.0"
            )
            
            snapshots = []
            for i, snapshot in enumerate(cdx.snapshots()):
                if i >= limit:
                    break
                snapshots.append({
                    'timestamp': snapshot.timestamp,
                    'archive_url': snapshot.archive_url,
                    'statuscode': getattr(snapshot, 'statuscode', None),
                    'datetime': snapshot.datetime_timestamp.isoformat() if hasattr(snapshot, 'datetime_timestamp') else None
                })
                
                progress = min(90, int((i / limit) * 100))
                self.emit_progress(sid, 'wayback', f"Snapshot {i+1}...", progress)
            
            if not snapshots:
                self.emit_progress(sid, 'wayback', "Aucune archive trouvée", 100)
                return {
                    'success': True,
                    'url': url,
                    'archived': False,
                    'count': 0,
                    'message': "URL non trouvée dans la Wayback Machine"
                }
            
            self.emit_progress(sid, 'wayback', "Recherche terminée", 100)
            
            return {
                'success': True,
                'url': url,
                'archived': True,
                'count': len(snapshots),
                'oldest': snapshots[-1] if snapshots else None,
                'newest': snapshots[0] if snapshots else None,
                'snapshots': snapshots
            }
            
        except Exception as e:
            return {
                'success': False,
                'url': url,
                'error': str(e)
            }
    
    # ==================== NEW TOOLS ====================
    
    def run_exif(self, file_path_or_url, sid=None, **options):
        """
        Extrait les métadonnées EXIF d'une image.
        """
        self.emit_progress(sid, 'exif', f"Analyse EXIF...", 30)
        
        try:
            analyzer = ExifAnalyzer()
            
            if file_path_or_url.startswith(('http://', 'https://')):
                result = analyzer.analyze_url(file_path_or_url)
            else:
                result = analyzer.analyze(file_path_or_url)
            
            self.emit_progress(sid, 'exif', "Analyse terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def run_subdomains(self, domain, sid=None, **options):
        """
        Découvre les sous-domaines d'un domaine.
        """
        self.emit_progress(sid, 'subdomains', f"Recherche sous-domaines de '{domain}'...", 10)
        
        try:
            finder = SubdomainFinder()
            result = finder.find(domain)
            
            self.emit_progress(sid, 'subdomains', "Recherche terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'error': str(e)
            }
    
    def run_ssl(self, hostname, sid=None, port=443, **options):
        """
        Analyse le certificat SSL d'un serveur.
        """
        self.emit_progress(sid, 'ssl', f"Analyse SSL de '{hostname}'...", 30)
        
        try:
            analyzer = SSLAnalyzer()
            result = analyzer.analyze(hostname, port=port)
            
            self.emit_progress(sid, 'ssl', "Analyse terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'hostname': hostname,
                'error': str(e)
            }
    
    def run_hash(self, hash_value, sid=None, **options):
        """
        Recherche un hash dans les bases de threat intelligence.
        """
        self.emit_progress(sid, 'hash', f"Recherche du hash...", 30)
        
        try:
            lookup = HashLookup(vt_api_key=options.get('vt_api_key'))
            result = lookup.lookup(hash_value)
            
            self.emit_progress(sid, 'hash', "Recherche terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'hash': hash_value,
                'error': str(e)
            }
    
    def run_mac(self, mac_address, sid=None, **options):
        """
        Identifie le fabricant d'une adresse MAC.
        """
        self.emit_progress(sid, 'mac', f"Recherche MAC '{mac_address}'...", 30)
        
        try:
            lookup = MACLookup()
            result = lookup.lookup(mac_address)
            
            self.emit_progress(sid, 'mac', "Recherche terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'mac_address': mac_address,
                'error': str(e)
            }
    
    def run_social(self, identifier, sid=None, **options):
        """
        Analyse un email ou username sur les réseaux sociaux.
        """
        self.emit_progress(sid, 'social', f"Analyse sociale de '{identifier}'...", 30)
        
        try:
            analyzer = SocialAnalyzer()
            result = analyzer.full_analysis(identifier)
            
            self.emit_progress(sid, 'social', "Analyse terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'identifier': identifier,
                'error': str(e)
            }
    
    def run_maigret(self, username, sid=None, **options):
        """
        Recherche avancée de username via Maigret (3000+ sites).
        """
        mode = options.get('mode', 'fast')
        tags = options.get('tags', None)
        
        self.emit_progress(sid, 'maigret', f"Recherche Maigret de '{username}'...", 10)
        
        try:
            runner = MaigretRunner(timeout=options.get('timeout', 120))
            result = runner.search(
                username,
                mode=mode,
                tags=tags,
                top_sites=options.get('top_sites', 50)
            )
            
            self.emit_progress(sid, 'maigret', "Recherche terminée", 100)
            return result
            
        except Exception as e:
            return {
                'success': False,
                'username': username,
                'error': str(e)
            }
    
    # ==================== DISPATCHER ====================
    
    def run(self, tool, value, sid=None, **options):
        """
        Dispatcher principal pour exécuter un outil OSINT.
        """
        tools = {
            'sherlock': self.run_sherlock,
            'holehe': self.run_holehe,
            'email_validator': self.run_email_validator,
            'whois': self.run_whois,
            'dns': self.run_dns,
            'phone': self.run_phone,
            'ip': self.run_ip,
            'wayback': self.run_wayback,
            # New lightweight tools
            'exif': self.run_exif,
            'subdomains': self.run_subdomains,
            'ssl': self.run_ssl,
            'hash': self.run_hash,
            'mac': self.run_mac,
            'social': self.run_social,
            'maigret': self.run_maigret
        }
        
        runner = tools.get(tool)
        if not runner:
            return {
                'success': False,
                'error': f"Outil inconnu: {tool}"
            }
        
        return runner(value, sid=sid, **options)
