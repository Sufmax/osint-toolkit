"""
Module: SSL Analyzer
Description: Analyse des certificats SSL/TLS (expiration, issuer, SAN, vulnérabilités)
RAM: ~2 Mo | Dépendances: ssl (builtin), socket (builtin)

Informations extraites:
- Dates validité (expiration, émission)
- Émetteur (CA) et sujet
- Subject Alternative Names (SAN)
- Version protocole et cipher
"""

import logging
import ssl
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import re

logger = logging.getLogger(__name__)


class SSLAnalyzer:
    """
    Analyseur de certificats SSL/TLS.
    
    Utilise les modules builtin Python (ssl, socket) pour ne pas
    ajouter de dépendances supplémentaires.
    """
    
    # Ciphers considérés comme faibles
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialise l'analyseur.
        
        Args:
            timeout: Timeout de connexion en secondes
        """
        self.timeout = timeout
    
    def analyze(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Analyse le certificat SSL d'un serveur.
        
        Args:
            hostname: Nom d'hôte ou domaine
            port: Port SSL (défaut: 443)
            
        Returns:
            dict: Informations détaillées sur le certificat
        """
        # Nettoyer le hostname
        hostname = self._clean_hostname(hostname)
        if not hostname:
            return {
                'success': False,
                'error': 'Hostname invalide'
            }
        
        try:
            # Créer le contexte SSL
            context = ssl.create_default_context()
            
            # Connexion avec timeout
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            if not cert:
                return {
                    'success': False,
                    'hostname': hostname,
                    'error': 'Impossible de récupérer le certificat'
                }
            
            # Parser le certificat
            result = self._parse_certificate(cert, hostname)
            result['connection'] = {
                'protocol': version,
                'cipher_suite': cipher[0] if cipher else None,
                'cipher_bits': cipher[2] if cipher else None
            }
            
            # Vérifications de sécurité
            result['security'] = self._check_security(result, cipher)
            
            return result
            
        except ssl.SSLCertVerificationError as e:
            return {
                'success': False,
                'hostname': hostname,
                'error': f"Erreur vérification certificat: {e}",
                'verification_failed': True
            }
        except ssl.SSLError as e:
            return {
                'success': False,
                'hostname': hostname,
                'error': f"Erreur SSL: {e}"
            }
        except socket.timeout:
            return {
                'success': False,
                'hostname': hostname,
                'error': 'Timeout de connexion'
            }
        except socket.gaierror as e:
            return {
                'success': False,
                'hostname': hostname,
                'error': f"Erreur DNS: {e}"
            }
        except ConnectionRefusedError:
            return {
                'success': False,
                'hostname': hostname,
                'error': f"Connexion refusée sur le port {port}"
            }
        except Exception as e:
            logger.error(f"Erreur analyse SSL: {e}")
            return {
                'success': False,
                'hostname': hostname,
                'error': str(e)
            }
    
    def _clean_hostname(self, hostname: str) -> str:
        """Nettoie un hostname."""
        hostname = hostname.lower().strip()
        # Retirer le protocole
        hostname = re.sub(r'^https?://', '', hostname)
        # Retirer le path et port
        hostname = hostname.split('/')[0].split(':')[0]
        return hostname
    
    def _parse_certificate(self, cert: Dict, hostname: str) -> Dict[str, Any]:
        """Parse les informations du certificat."""
        result = {
            'success': True,
            'hostname': hostname
        }
        
        # Sujet
        subject = dict(x[0] for x in cert.get('subject', []))
        result['subject'] = {
            'common_name': subject.get('commonName'),
            'organization': subject.get('organizationName'),
            'organizational_unit': subject.get('organizationalUnitName'),
            'country': subject.get('countryName'),
            'state': subject.get('stateOrProvinceName'),
            'locality': subject.get('localityName')
        }
        
        # Émetteur
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result['issuer'] = {
            'common_name': issuer.get('commonName'),
            'organization': issuer.get('organizationName'),
            'country': issuer.get('countryName')
        }
        
        # Dates de validité
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        result['validity'] = {}
        
        if not_before:
            dt_before = self._parse_cert_date(not_before)
            result['validity']['not_before'] = dt_before.isoformat() if dt_before else not_before
        
        if not_after:
            dt_after = self._parse_cert_date(not_after)
            if dt_after:
                result['validity']['not_after'] = dt_after.isoformat()
                result['validity']['expires_in_days'] = (dt_after - datetime.now(timezone.utc)).days
                result['validity']['is_expired'] = dt_after < datetime.now(timezone.utc)
            else:
                result['validity']['not_after'] = not_after
        
        # Subject Alternative Names (SAN)
        san = cert.get('subjectAltName', [])
        result['san'] = {
            'dns_names': [name for type_, name in san if type_ == 'DNS'],
            'ip_addresses': [name for type_, name in san if type_ == 'IP Address'],
            'emails': [name for type_, name in san if type_ == 'email']
        }
        result['san']['count'] = len(san)
        
        # Numéro de série
        result['serial_number'] = cert.get('serialNumber')
        
        # Version
        result['version'] = cert.get('version')
        
        return result
    
    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """Parse une date de certificat."""
        formats = [
            '%b %d %H:%M:%S %Y %Z',
            '%b  %d %H:%M:%S %Y %Z',
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
    
    def _check_security(self, cert_info: Dict, cipher: tuple) -> Dict[str, Any]:
        """Vérifie les aspects sécurité du certificat."""
        security = {
            'issues': [],
            'score': 100
        }
        
        # Vérifier expiration
        validity = cert_info.get('validity', {})
        if validity.get('is_expired'):
            security['issues'].append({
                'severity': 'critical',
                'message': 'Certificat expiré'
            })
            security['score'] -= 50
        elif validity.get('expires_in_days', 999) < 30:
            security['issues'].append({
                'severity': 'warning',
                'message': f"Certificat expire dans {validity.get('expires_in_days')} jours"
            })
            security['score'] -= 10
        
        # Vérifier cipher
        if cipher:
            cipher_name = cipher[0]
            for weak in self.WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    security['issues'].append({
                        'severity': 'high',
                        'message': f'Cipher faible détecté: {cipher_name}'
                    })
                    security['score'] -= 30
                    break
        
        # Vérifier protocole
        connection = cert_info.get('connection', {})
        protocol = connection.get('protocol', '')
        if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            security['issues'].append({
                'severity': 'high',
                'message': f'Protocole obsolète: {protocol}'
            })
            security['score'] -= 20
        
        # Vérifier si self-signed
        subject_cn = cert_info.get('subject', {}).get('common_name')
        issuer_cn = cert_info.get('issuer', {}).get('common_name')
        if subject_cn == issuer_cn:
            security['issues'].append({
                'severity': 'warning',
                'message': 'Certificat auto-signé'
            })
            security['score'] -= 15
        
        security['score'] = max(0, security['score'])
        security['rating'] = self._score_to_rating(security['score'])
        
        return security
    
    def _score_to_rating(self, score: int) -> str:
        """Convertit un score en note lettre."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'


# Fonction utilitaire pour usage direct
def analyze_ssl(hostname: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Fonction raccourcie pour analyser un certificat SSL.
    
    Args:
        hostname: Nom d'hôte
        port: Port SSL
        timeout: Timeout en secondes
        
    Returns:
        dict: Informations sur le certificat
    """
    analyzer = SSLAnalyzer(timeout=timeout)
    return analyzer.analyze(hostname, port)
