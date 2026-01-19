"""
Module: Hash Lookup
Description: Vérification de hashes (fichiers malveillants) via APIs publiques
RAM: ~2 Mo | Dépendances: requests (déjà présent)

APIs utilisées:
- MalwareBazaar (gratuit, sans clé)
- VirusTotal (optionnel, avec clé API)
"""

import logging
import re
import hashlib
import os
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)


class HashLookup:
    """
    Recherche d'informations sur des hashes de fichiers.
    
    Supporte MD5, SHA1, SHA256 et interroge des bases de threat intel
    pour identifier les fichiers malveillants.
    """
    
    # APIs de threat intelligence
    APIS = {
        'malwarebazaar': {
            'url': 'https://mb-api.abuse.ch/api/v1/',
            'requires_key': False
        },
        'virustotal': {
            'url': 'https://www.virustotal.com/api/v3/files/',
            'requires_key': True,
            'env_key': 'VT_API_KEY'
        }
    }
    
    # Regex pour validation des hashes
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$')
    }
    
    def __init__(self, vt_api_key: str = None, timeout: int = 15):
        """
        Initialise le lookup.
        
        Args:
            vt_api_key: Clé API VirusTotal (optionnelle)
            timeout: Timeout pour les requêtes
        """
        self.timeout = timeout
        self.vt_api_key = vt_api_key or os.environ.get('VT_API_KEY')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Toolkit/1.0 (Hash Lookup)'
        })
    
    def lookup(self, hash_value: str, sources: list = None) -> Dict[str, Any]:
        """
        Recherche un hash dans les bases de threat intel.
        
        Args:
            hash_value: Hash à rechercher (MD5, SHA1 ou SHA256)
            sources: Sources à interroger (None = toutes disponibles)
            
        Returns:
            dict: Informations trouvées
        """
        hash_value = hash_value.strip().lower()
        
        # Identifier le type de hash
        hash_type = self._identify_hash_type(hash_value)
        if not hash_type:
            return {
                'success': False,
                'error': 'Format de hash invalide (MD5, SHA1 ou SHA256 attendu)'
            }
        
        result = {
            'success': True,
            'hash': hash_value,
            'hash_type': hash_type,
            'sources': {},
            'is_malicious': False,
            'detections': []
        }
        
        # Sélectionner les sources
        if sources is None:
            sources = ['malwarebazaar']
            if self.vt_api_key:
                sources.append('virustotal')
        
        # Interroger chaque source
        for source in sources:
            if source == 'malwarebazaar':
                mb_result = self._query_malwarebazaar(hash_value, hash_type)
                result['sources']['malwarebazaar'] = mb_result
                if mb_result.get('found'):
                    result['is_malicious'] = True
                    result['detections'].append({
                        'source': 'MalwareBazaar',
                        'malware_family': mb_result.get('malware_family'),
                        'tags': mb_result.get('tags', [])
                    })
            
            elif source == 'virustotal' and self.vt_api_key:
                vt_result = self._query_virustotal(hash_value)
                result['sources']['virustotal'] = vt_result
                if vt_result.get('found') and vt_result.get('malicious', 0) > 0:
                    result['is_malicious'] = True
                    result['detections'].append({
                        'source': 'VirusTotal',
                        'malicious_count': vt_result.get('malicious'),
                        'total_engines': vt_result.get('total_engines')
                    })
        
        # Score de menace
        result['threat_score'] = self._calculate_threat_score(result)
        
        return result
    
    def hash_file(self, file_path: str) -> Dict[str, str]:
        """
        Calcule les hashes d'un fichier local.
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            dict: Hashes MD5, SHA1, SHA256
        """
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            return {
                'success': True,
                'file': file_path,
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        
        except FileNotFoundError:
            return {
                'success': False,
                'error': f'Fichier non trouvé: {file_path}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _identify_hash_type(self, hash_value: str) -> Optional[str]:
        """Identifie le type de hash."""
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                return hash_type
        return None
    
    def _query_malwarebazaar(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """Interroge MalwareBazaar."""
        try:
            response = self.session.post(
                self.APIS['malwarebazaar']['url'],
                data={
                    'query': 'get_info',
                    'hash': hash_value
                },
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            
            if data.get('query_status') == 'hash_not_found':
                return {'found': False}
            
            if data.get('query_status') == 'ok' and data.get('data'):
                info = data['data'][0]
                return {
                    'found': True,
                    'sha256': info.get('sha256_hash'),
                    'sha1': info.get('sha1_hash'),
                    'md5': info.get('md5_hash'),
                    'file_name': info.get('file_name'),
                    'file_type': info.get('file_type'),
                    'file_size': info.get('file_size'),
                    'malware_family': info.get('signature'),
                    'tags': info.get('tags', []),
                    'first_seen': info.get('first_seen'),
                    'last_seen': info.get('last_seen'),
                    'intelligence': info.get('intelligence', {})
                }
            
            return {'found': False}
            
        except requests.RequestException as e:
            logger.warning(f"MalwareBazaar error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"MalwareBazaar parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _query_virustotal(self, hash_value: str) -> Dict[str, Any]:
        """Interroge VirusTotal (nécessite clé API)."""
        if not self.vt_api_key:
            return {
                'found': False,
                'error': 'Clé API VirusTotal non configurée'
            }
        
        try:
            response = self.session.get(
                f"{self.APIS['virustotal']['url']}{hash_value}",
                headers={
                    'x-apikey': self.vt_api_key
                },
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                return {'found': False}
            
            if response.status_code == 401:
                return {
                    'found': False,
                    'error': 'Clé API invalide'
                }
            
            if response.status_code == 429:
                return {
                    'found': False,
                    'error': 'Rate limit dépassé'
                }
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            
            return {
                'found': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_engines': sum(stats.values()),
                'file_type': attrs.get('type_description'),
                'file_size': attrs.get('size'),
                'names': attrs.get('names', [])[:5],
                'reputation': attrs.get('reputation'),
                'first_submission': attrs.get('first_submission_date'),
                'last_analysis': attrs.get('last_analysis_date')
            }
            
        except requests.RequestException as e:
            logger.warning(f"VirusTotal error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"VirusTotal parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _calculate_threat_score(self, result: Dict) -> int:
        """
        Calcule un score de menace (0-100).
        
        0 = Sûr/Inconnu, 100 = Hautement malveillant
        """
        score = 0
        
        # MalwareBazaar détection
        mb = result.get('sources', {}).get('malwarebazaar', {})
        if mb.get('found'):
            score += 60  # Présence dans MalwareBazaar = très suspect
        
        # VirusTotal détections
        vt = result.get('sources', {}).get('virustotal', {})
        if vt.get('found'):
            malicious = vt.get('malicious', 0)
            total = vt.get('total_engines', 1)
            if total > 0:
                ratio = malicious / total
                score += int(ratio * 40)  # Max +40 pour VT
        
        return min(100, score)


# Fonction utilitaire pour usage direct
def lookup_hash(hash_value: str, vt_api_key: str = None) -> Dict[str, Any]:
    """
    Fonction raccourcie pour rechercher un hash.
    
    Args:
        hash_value: Hash à rechercher
        vt_api_key: Clé API VirusTotal (optionnelle)
        
    Returns:
        dict: Informations threat intel
    """
    lookup = HashLookup(vt_api_key=vt_api_key)
    return lookup.lookup(hash_value)
