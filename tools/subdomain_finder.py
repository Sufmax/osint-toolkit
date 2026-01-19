"""
Module: Subdomain Finder
Description: Recherche de sous-domaines via APIs publiques (crt.sh, HackerTarget)
RAM: ~2 Mo | Dépendances: requests (déjà présent)

APIs utilisées:
- crt.sh (Certificate Transparency logs)
- HackerTarget (DNS lookup)
"""

import logging
import re
from typing import Dict, Any, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

logger = logging.getLogger(__name__)


class SubdomainFinder:
    """
    Recherche de sous-domaines via sources passives.
    
    Ne nécessite pas de brute-force, utilise uniquement des APIs publiques
    pour rester léger et rapide.
    """
    
    # Configuration des sources
    SOURCES = {
        'crt_sh': {
            'url': 'https://crt.sh/?q=%.{domain}&output=json',
            'timeout': 15,
            'enabled': True
        },
        'hackertarget': {
            'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
            'timeout': 10,
            'enabled': True
        },
        'threatcrowd': {
            'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
            'timeout': 10,
            'enabled': True
        }
    }
    
    # Regex pour valider les sous-domaines
    SUBDOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    def __init__(self, timeout: int = 15):
        """
        Initialise le finder.
        
        Args:
            timeout: Timeout par défaut pour les requêtes (secondes)
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Toolkit/1.0 (Subdomain Research)',
            'Accept': 'application/json'
        })
    
    def find(self, domain: str, sources: List[str] = None) -> Dict[str, Any]:
        """
        Recherche les sous-domaines d'un domaine.
        
        Args:
            domain: Domaine cible (ex: "example.com")
            sources: Liste des sources à utiliser (None = toutes)
            
        Returns:
            dict: Résultats avec sous-domaines uniques
        """
        # Nettoyer le domaine
        domain = self._clean_domain(domain)
        if not domain:
            return {
                'success': False,
                'error': 'Domaine invalide'
            }
        
        # Sélectionner les sources
        if sources is None:
            sources = [name for name, config in self.SOURCES.items() if config['enabled']]
        
        all_subdomains: Set[str] = set()
        source_results = {}
        errors = []
        
        # Exécuter les recherches en parallèle
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for source in sources:
                if source in self.SOURCES:
                    futures[executor.submit(self._query_source, source, domain)] = source
            
            for future in as_completed(futures, timeout=30):
                source = futures[future]
                try:
                    result = future.result()
                    source_results[source] = {
                        'count': len(result['subdomains']),
                        'status': 'success'
                    }
                    all_subdomains.update(result['subdomains'])
                except Exception as e:
                    source_results[source] = {
                        'count': 0,
                        'status': 'error',
                        'error': str(e)
                    }
                    errors.append(f"{source}: {e}")
        
        # Filtrer et trier les résultats
        valid_subdomains = sorted([
            s for s in all_subdomains 
            if self._is_valid_subdomain(s, domain)
        ])
        
        return {
            'success': True,
            'domain': domain,
            'subdomains': valid_subdomains,
            'count': len(valid_subdomains),
            'sources': source_results,
            'errors': errors if errors else None
        }
    
    def _clean_domain(self, domain: str) -> str:
        """Nettoie et valide un domaine."""
        domain = domain.lower().strip()
        # Retirer le protocole si présent
        domain = re.sub(r'^https?://', '', domain)
        # Retirer le path
        domain = domain.split('/')[0]
        # Retirer le port
        domain = domain.split(':')[0]
        # Retirer le www
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    
    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Vérifie si un sous-domaine est valide."""
        if not subdomain or not parent_domain:
            return False
        
        subdomain = subdomain.lower().strip()
        
        # Doit se terminer par le domaine parent
        if not subdomain.endswith('.' + parent_domain) and subdomain != parent_domain:
            return False
        
        # Validation regex
        if not self.SUBDOMAIN_REGEX.match(subdomain):
            return False
        
        # Exclure les wildcards
        if '*' in subdomain:
            return False
        
        return True
    
    def _query_source(self, source: str, domain: str) -> Dict[str, Any]:
        """Interroge une source spécifique."""
        config = self.SOURCES[source]
        url = config['url'].format(domain=domain)
        timeout = config.get('timeout', self.timeout)
        
        if source == 'crt_sh':
            return self._query_crtsh(url, domain, timeout)
        elif source == 'hackertarget':
            return self._query_hackertarget(url, domain, timeout)
        elif source == 'threatcrowd':
            return self._query_threatcrowd(url, domain, timeout)
        else:
            return {'subdomains': set()}
    
    def _query_crtsh(self, url: str, domain: str, timeout: int) -> Dict[str, Any]:
        """Interroge crt.sh (Certificate Transparency)."""
        subdomains = set()
        
        try:
            response = self.session.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Un certificat peut couvrir plusieurs noms
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith('*'):
                            subdomains.add(sub)
        
        except requests.RequestException as e:
            logger.warning(f"crt.sh error: {e}")
            raise
        except (ValueError, KeyError) as e:
            logger.warning(f"crt.sh parse error: {e}")
        
        return {'subdomains': subdomains}
    
    def _query_hackertarget(self, url: str, domain: str, timeout: int) -> Dict[str, Any]:
        """Interroge HackerTarget API."""
        subdomains = set()
        
        try:
            response = self.session.get(url, timeout=timeout)
            
            if response.status_code == 200:
                text = response.text
                
                # Vérifier si erreur API
                if 'error' in text.lower() or 'API count exceeded' in text:
                    logger.warning(f"HackerTarget: {text}")
                    return {'subdomains': subdomains}
                
                for line in text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain:
                            subdomains.add(subdomain)
        
        except requests.RequestException as e:
            logger.warning(f"HackerTarget error: {e}")
            raise
        
        return {'subdomains': subdomains}
    
    def _query_threatcrowd(self, url: str, domain: str, timeout: int) -> Dict[str, Any]:
        """Interroge ThreatCrowd API."""
        subdomains = set()
        
        try:
            response = self.session.get(url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == '1':
                    for sub in data.get('subdomains', []):
                        subdomains.add(sub.lower())
        
        except requests.RequestException as e:
            logger.warning(f"ThreatCrowd error: {e}")
            raise
        except (ValueError, KeyError) as e:
            logger.warning(f"ThreatCrowd parse error: {e}")
        
        return {'subdomains': subdomains}


# Fonction utilitaire pour usage direct
def find_subdomains(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """
    Fonction raccourcie pour rechercher des sous-domaines.
    
    Args:
        domain: Domaine cible
        timeout: Timeout en secondes
        
    Returns:
        dict: Sous-domaines trouvés
    """
    finder = SubdomainFinder(timeout=timeout)
    return finder.find(domain)
