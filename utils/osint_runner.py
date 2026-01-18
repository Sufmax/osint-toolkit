"""
Wrapper pour exécuter les outils OSINT de manière uniforme et sécurisée.
"""
import subprocess
import asyncio
import json
import tempfile
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime

# DNS
import dns.resolver
import dns.reversename

# WHOIS
import whois

# Phone
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

# IP
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

# Wayback
from waybackpy import WaybackMachineCDXServerAPI

# Email validator
from email_validator import validate_email, EmailNotValidError


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
        self.executor = ThreadPoolExecutor(max_workers=2)
    
    def emit_progress(self, sid, tool, message, progress=None, result=None):
        """Émet un événement de progression via WebSocket."""
        if self.socketio:
            self.socketio.emit('progress', {
                'tool': tool,
                'message': message,
                'progress': progress,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }, room=sid)
    
    # ==================== SHERLOCK ====================
    
    def run_sherlock(self, username, sid=None, fast_mode=True, timeout=60):
        """
        Recherche un username avec Sherlock.
        
        Args:
            username: Nom d'utilisateur à rechercher
            sid: Session ID pour WebSocket
            fast_mode: Limiter aux sites populaires
            timeout: Timeout en secondes
        
        Returns:
            dict: Résultats de la recherche
        """
        self.emit_progress(sid, 'sherlock', f"Recherche de '{username}'...", 0)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, f"{username}.json")
            
            cmd = [
                "sherlock",
                username,
                "--timeout", "10",
                "--json", output_file,
                "--print-found"
            ]
            
            # Mode rapide: limiter aux sites populaires
            if fast_mode:
                for site in self.TOP_SITES:
                    cmd.extend(["--site", site])
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                found_sites = []
                site_count = 0
                total_sites = len(self.TOP_SITES) if fast_mode else 400
                
                # Lire la sortie en temps réel
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    site_count += 1
                    progress = min(95, int((site_count / total_sites) * 100))
                    
                    # Détecter les sites trouvés
                    if '[+]' in line or 'http' in line.lower():
                        # Extraire le nom du site et l'URL
                        match = re.search(r'\[.\]\s*(\w+):\s*(https?://\S+)', line)
                        if match:
                            site_name = match.group(1)
                            url = match.group(2)
                            found_sites.append({
                                'site': site_name,
                                'url': url
                            })
                            self.emit_progress(
                                sid, 'sherlock',
                                f"Trouvé: {site_name}",
                                progress,
                                {'site': site_name, 'url': url}
                            )
                
                process.wait(timeout=timeout)
                
                # Lire le fichier JSON si disponible
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        try:
                            json_results = json.load(f)
                            # Parser les résultats JSON
                            for site, data in json_results.items():
                                if isinstance(data, dict) and data.get('status') == 'Claimed':
                                    if not any(s['site'] == site for s in found_sites):
                                        found_sites.append({
                                            'site': site,
                                            'url': data.get('url_user', '')
                                        })
                        except json.JSONDecodeError:
                            pass
                
                self.emit_progress(sid, 'sherlock', "Recherche terminée", 100)
                
                return {
                    'success': True,
                    'username': username,
                    'found': found_sites,
                    'count': len(found_sites),
                    'mode': 'fast' if fast_mode else 'full'
                }
                
            except subprocess.TimeoutExpired:
                process.kill()
                return {
                    'success': False,
                    'username': username,
                    'error': 'Timeout dépassé',
                    'found': found_sites,
                    'count': len(found_sites)
                }
            except FileNotFoundError:
                return {
                    'success': False,
                    'username': username,
                    'error': 'Sherlock non installé'
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
        
        Args:
            email: Adresse email à vérifier
            sid: Session ID pour WebSocket
            timeout: Timeout en secondes
        
        Returns:
            dict: Sites où l'email est enregistré
        """
        self.emit_progress(sid, 'holehe', f"Vérification de '{email}'...", 0)
        
        try:
            result = subprocess.run(
                ["holehe", email, "--only-used", "--no-color"],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            found_sites = []
            lines = result.stdout.split('\n')
            
            for i, line in enumerate(lines):
                progress = int((i / max(len(lines), 1)) * 100)
                
                if '[+]' in line:
                    # Extraire le nom du service
                    match = re.search(r'\[\+\]\s*(\w+)', line)
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
                'error': 'Holehe non installé'
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
        
        Args:
            email: Adresse email à valider
            sid: Session ID pour WebSocket
            check_dns: Vérifier les enregistrements MX
        
        Returns:
            dict: Résultats de validation
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
        
        Args:
            domain: Nom de domaine à interroger
            sid: Session ID pour WebSocket
        
        Returns:
            dict: Informations WHOIS
        """
        self.emit_progress(sid, 'whois', f"Requête WHOIS pour '{domain}'...", 30)
        
        try:
            w = whois.whois(domain)
            
            # Normaliser les dates
            def format_date(date_val):
                if isinstance(date_val, list):
                    date_val = date_val[0] if date_val else None
                if hasattr(date_val, 'isoformat'):
                    return date_val.isoformat()
                return str(date_val) if date_val else None
            
            # Normaliser les listes
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
        
        Args:
            domain: Nom de domaine
            sid: Session ID pour WebSocket
            record_types: Types d'enregistrements à rechercher
        
        Returns:
            dict: Enregistrements DNS
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
        
        # SPF
        try:
            txt_records = results['records'].get('TXT', [])
            spf = [r for r in txt_records if 'v=spf1' in r]
            security['spf'] = spf[0] if spf else None
        except:
            security['spf'] = None
        
        # DMARC
        try:
            dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            security['dmarc'] = str(list(dmarc_answers)[0])
        except:
            security['dmarc'] = None
        
        results['security'] = security
        
        self.emit_progress(sid, 'dns', "Requêtes terminées", 100)
        
        return results
    
    # ==================== PHONE ====================
    
    def run_phone(self, number, sid=None, default_region='FR'):
        """
        Analyse un numéro de téléphone.
        
        Args:
            number: Numéro de téléphone
            sid: Session ID pour WebSocket
            default_region: Code pays par défaut
        
        Returns:
            dict: Informations sur le numéro
        """
        self.emit_progress(sid, 'phone', f"Analyse de '{number}'...", 30)
        
        try:
            parsed = phonenumbers.parse(number, default_region)
            
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            
            # Type de numéro
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
            
            # Informations géographiques
            country_code = parsed.country_code
            region_code = phonenumbers.region_code_for_number(parsed)
            location = geocoder.description_for_number(parsed, "fr")
            
            # Opérateur
            carrier_name = carrier.name_for_number(parsed, "fr")
            
            # Fuseaux horaires
            time_zones = list(timezone.time_zones_for_number(parsed))
            
            # Formats
            from phonenumbers import PhoneNumberFormat
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
    
    # ==================== IP WHOIS ====================
    
    def run_ip(self, ip_address, sid=None):
        """
        Recherche les informations WHOIS/RDAP d'une adresse IP.
        
        Args:
            ip_address: Adresse IP à rechercher
            sid: Session ID pour WebSocket
        
        Returns:
            dict: Informations sur l'IP
        """
        self.emit_progress(sid, 'ip', f"Recherche pour '{ip_address}'...", 30)
        
        try:
            obj = IPWhois(ip_address)
            result = obj.lookup_rdap(depth=1, asn_methods=['dns', 'whois'])
            
            # Extraire les informations
            network = result.get('network', {})
            nets = result.get('nets', [])
            primary_net = nets[0] if nets else {}
            
            self.emit_progress(sid, 'ip', "Recherche terminée", 100)
            
            return {
                'success': True,
                'ip': ip_address,
                'asn': {
                    'number': result.get('asn'),
                    'cidr': result.get('asn_cidr'),
                    'country': result.get('asn_country_code'),
                    'description': result.get('asn_description'),
                    'registry': result.get('asn_registry')
                },
                'network': {
                    'cidr': network.get('cidr') or primary_net.get('cidr'),
                    'name': network.get('name') or primary_net.get('name'),
                    'country': network.get('country') or primary_net.get('country')
                },
                'organization': primary_net.get('description') or network.get('name'),
                'abuse_emails': primary_net.get('abuse_emails', [])
            }
            
        except IPDefinedError as e:
            self.emit_progress(sid, 'ip', "IP privée/réservée", 100)
            return {
                'success': True,
                'ip': ip_address,
                'error': f"IP privée ou réservée: {str(e)}",
                'is_private': True
            }
        except Exception as e:
            return {
                'success': False,
                'ip': ip_address,
                'error': str(e)
            }
    # ==================== WAYBACK ====================
    
    def run_wayback(self, url, sid=None, limit=20):
        """
        Récupère les informations Wayback Machine pour une URL.
        
        Args:
            url: URL à rechercher
            sid: Session ID pour WebSocket
            limit: Nombre max de snapshots à retourner
        
        Returns:
            dict: Informations sur les archives
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
                    'statuscode': snapshot.statuscode,
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
    
    # ==================== DISPATCHER ====================
    def run(self, tool, value, sid=None, **options):
        """
        Dispatcher principal pour exécuter un outil OSINT.
        
        Args:
            tool: Nom de l'outil
            value: Valeur à rechercher
            sid: Session ID pour WebSocket
            **options: Options spécifiques à l'outil
        
        Returns:
            dict: Résultats de l'outil
        """
        tools = {
            'sherlock': self.run_sherlock,
            'holehe': self.run_holehe,
            'email_validator': self.run_email_validator,
            'whois': self.run_whois,
            'dns': self.run_dns,
            'phone': self.run_phone,
            'ip': self.run_ip,
            'wayback': self.run_wayback
        }
        
        runner = tools.get(tool)
        if not runner:
            return {
                'success': False,
                'error': f"Outil inconnu: {tool}"
            }
        
        return runner(value, sid=sid, **options)