"""
Module: MAC Address Lookup
Description: Identification du fabricant d'un appareil via son adresse MAC
RAM: ~1 Mo | Dépendances: requests (déjà présent)

APIs utilisées:
- macvendors.com (gratuit, rate limit)
- maclookup.app (gratuit, rate limit)
"""

import logging
import re
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)


class MACLookup:
    """
    Recherche d'informations sur les adresses MAC.
    
    Identifie le fabricant d'un appareil réseau via l'OUI
    (Organizationally Unique Identifier) des 3 premiers octets.
    """
    
    # APIs publiques
    APIS = {
        'macvendors': {
            'url': 'https://api.macvendors.com/',
            'rate_limit': '2/sec'
        },
        'maclookup': {
            'url': 'https://api.maclookup.app/v2/macs/',
            'rate_limit': '2/sec'
        }
    }
    
    # Regex pour validation MAC
    MAC_PATTERNS = [
        re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),  # AA:BB:CC:DD:EE:FF
        re.compile(r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'),     # AABB.CCDD.EEFF
        re.compile(r'^[0-9A-Fa-f]{12}$')                            # AABBCCDDEEFF
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialise le lookup.
        
        Args:
            timeout: Timeout pour les requêtes
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Toolkit/1.0 (MAC Lookup)'
        })
    
    def lookup(self, mac_address: str) -> Dict[str, Any]:
        """
        Recherche le fabricant d'une adresse MAC.
        
        Args:
            mac_address: Adresse MAC (formats supportés: AA:BB:CC:DD:EE:FF,
                        AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, AABBCCDDEEFF)
            
        Returns:
            dict: Informations sur le fabricant
        """
        # Normaliser l'adresse MAC
        normalized = self._normalize_mac(mac_address)
        if not normalized:
            return {
                'success': False,
                'error': 'Format MAC invalide. Formats acceptés: AA:BB:CC:DD:EE:FF, '
                        'AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, AABBCCDDEEFF'
            }
        
        result = {
            'success': True,
            'mac_address': mac_address,
            'mac_normalized': normalized,
            'oui': normalized[:6].upper(),
            'vendor': None,
            'sources': {}
        }
        
        # Essayer macvendors d'abord
        mv_result = self._query_macvendors(normalized)
        result['sources']['macvendors'] = mv_result
        
        if mv_result.get('found'):
            result['vendor'] = mv_result.get('vendor')
        else:
            # Fallback sur maclookup
            ml_result = self._query_maclookup(normalized)
            result['sources']['maclookup'] = ml_result
            
            if ml_result.get('found'):
                result['vendor'] = ml_result.get('vendor')
                result['company_details'] = {
                    'name': ml_result.get('company'),
                    'address': ml_result.get('address'),
                    'country': ml_result.get('country')
                }
        
        # Analyser l'OUI pour des infos supplémentaires
        result['oui_analysis'] = self._analyze_oui(normalized)
        
        return result
    
    def lookup_batch(self, mac_addresses: list) -> Dict[str, Any]:
        """
        Recherche plusieurs adresses MAC.
        
        Args:
            mac_addresses: Liste d'adresses MAC
            
        Returns:
            dict: Résultats pour chaque adresse
        """
        results = {
            'success': True,
            'total': len(mac_addresses),
            'found': 0,
            'not_found': 0,
            'errors': 0,
            'results': {}
        }
        
        for mac in mac_addresses:
            lookup_result = self.lookup(mac)
            results['results'][mac] = lookup_result
            
            if not lookup_result.get('success'):
                results['errors'] += 1
            elif lookup_result.get('vendor'):
                results['found'] += 1
            else:
                results['not_found'] += 1
        
        return results
    
    def _normalize_mac(self, mac_address: str) -> Optional[str]:
        """
        Normalise une adresse MAC.
        
        Returns:
            str: MAC normalisée (minuscules, sans séparateurs) ou None si invalide
        """
        mac = mac_address.strip().upper()
        
        # Vérifier le format
        valid = any(pattern.match(mac) for pattern in self.MAC_PATTERNS)
        if not valid:
            return None
        
        # Retirer les séparateurs
        normalized = re.sub(r'[:\-.]', '', mac).lower()
        
        # Vérifier la longueur finale
        if len(normalized) != 12:
            return None
        
        return normalized
    
    def _format_mac(self, normalized: str, separator: str = ':') -> str:
        """Formate une MAC normalisée avec séparateur."""
        return separator.join(
            normalized[i:i+2] for i in range(0, 12, 2)
        ).upper()
    
    def _query_macvendors(self, normalized_mac: str) -> Dict[str, Any]:
        """Interroge macvendors.com."""
        try:
            # Formater pour l'API
            formatted = self._format_mac(normalized_mac)
            
            response = self.session.get(
                f"{self.APIS['macvendors']['url']}{formatted}",
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                return {'found': False}
            
            if response.status_code == 429:
                return {
                    'found': False,
                    'error': 'Rate limit atteint'
                }
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            vendor = response.text.strip()
            if vendor:
                return {
                    'found': True,
                    'vendor': vendor
                }
            
            return {'found': False}
            
        except requests.RequestException as e:
            logger.warning(f"macvendors error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
    
    def _query_maclookup(self, normalized_mac: str) -> Dict[str, Any]:
        """Interroge maclookup.app."""
        try:
            response = self.session.get(
                f"{self.APIS['maclookup']['url']}{normalized_mac}",
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                return {'found': False}
            
            if response.status_code == 429:
                return {
                    'found': False,
                    'error': 'Rate limit atteint'
                }
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            
            if not data.get('success') or not data.get('found'):
                return {'found': False}
            
            return {
                'found': True,
                'vendor': data.get('company'),
                'company': data.get('company'),
                'address': data.get('address'),
                'country': data.get('country'),
                'mac_prefix': data.get('macPrefix'),
                'block_type': data.get('blockType')
            }
            
        except requests.RequestException as e:
            logger.warning(f"maclookup error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"maclookup parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _analyze_oui(self, normalized_mac: str) -> Dict[str, Any]:
        """
        Analyse l'OUI pour extraire des informations supplémentaires.
        """
        oui = normalized_mac[:6].upper()
        
        analysis = {
            'oui': f'{oui[:2]}:{oui[2:4]}:{oui[4:6]}',
            'is_multicast': bool(int(oui[1], 16) & 1),
            'is_local': bool(int(oui[1], 16) & 2)
        }
        
        # Classification
        if analysis['is_local']:
            analysis['address_type'] = 'Locally Administered (LAA)'
            analysis['note'] = 'Adresse possiblement modifiée/virtuelle'
        elif analysis['is_multicast']:
            analysis['address_type'] = 'Multicast'
            analysis['note'] = 'Adresse de groupe/broadcast'
        else:
            analysis['address_type'] = 'Universally Administered (UAA)'
            analysis['note'] = 'Adresse fabricant standard'
        
        return analysis


# Fonction utilitaire pour usage direct
def lookup_mac(mac_address: str) -> Dict[str, Any]:
    """
    Fonction raccourcie pour rechercher une adresse MAC.
    
    Args:
        mac_address: Adresse MAC à rechercher
        
    Returns:
        dict: Informations sur le fabricant
    """
    lookup = MACLookup()
    return lookup.lookup(mac_address)
