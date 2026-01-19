"""
OSINT Toolkit - Modules d'outils supplémentaires
================================================

Outils légers optimisés pour environnements à ressources limitées.
Contraintes: RAM ≤ 512 Mo, CPU ≤ 0.1 vCPU, Stockage < 1 Go

Catégories disponibles:
- Métadonnées (EXIF)
- Reconnaissance (Subdomains, SSL)
- Threat Intelligence (Hash lookup)
- Network OSINT (MAC lookup)
- Social OSINT (Gravatar, GitHub)
"""

from .exif_analyzer import ExifAnalyzer
from .subdomain_finder import SubdomainFinder
from .ssl_analyzer import SSLAnalyzer
from .hash_lookup import HashLookup
from .mac_lookup import MACLookup
from .social_analyzer import SocialAnalyzer
from .maigret_runner import MaigretRunner

__all__ = [
    'ExifAnalyzer',
    'SubdomainFinder', 
    'SSLAnalyzer',
    'HashLookup',
    'MACLookup',
    'SocialAnalyzer',
    'MaigretRunner'
]

__version__ = '1.1.0'
