"""
Module: Maigret Runner
Description: Recherche avancée de profils sociaux via Maigret (fork de Sherlock)
RAM: ~50-100 Mo | Dépendances: maigret

Maigret supporte 3000+ sites avec:
- Parsing de pages de profils
- Extraction d'informations personnelles
- Recherche récursive de usernames liés
- Support des tags (catégories, pays)
"""

import logging
import subprocess
import tempfile
import os
import json
import re
import time
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class MaigretRunner:
    """
    Wrapper pour Maigret - Recherche avancée de profils sociaux.
    
    Maigret est plus puissant que Sherlock avec 3000+ sites supportés,
    parsing de profils, et recherche récursive.
    """
    
    # Tags disponibles pour filtrer les sites
    AVAILABLE_TAGS = {
        'social': ['social', 'photo', 'video', 'music'],
        'tech': ['coding', 'tech', 'gaming'],
        'geo': ['us', 'ru', 'cn', 'de', 'fr', 'uk', 'br'],
        'type': ['dating', 'forum', 'blog', 'shopping']
    }
    
    # Sites populaires pour le mode rapide
    TOP_SITES = [
        "Instagram", "Twitter", "Facebook", "TikTok", "YouTube",
        "Reddit", "GitHub", "LinkedIn", "Pinterest", "Twitch",
        "Snapchat", "Steam", "Spotify", "Telegram", "Discord",
        "Medium", "Tumblr", "VK", "Flickr", "DeviantArt",
        "SoundCloud", "Vimeo", "Dribbble", "Behance", "GitLab"
    ]
    
    def __init__(self, timeout: int = 120):
        """
        Initialise le runner Maigret.
        
        Args:
            timeout: Timeout global en secondes
        """
        self.timeout = timeout
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Vérifie que Maigret est installé."""
        try:
            result = subprocess.run(
                ["maigret", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Maigret version: {result.stdout.strip()}")
                return True
        except FileNotFoundError:
            logger.warning("Maigret non installé. Exécutez: pip install maigret")
        except subprocess.TimeoutExpired:
            pass
        return False
    
    def search(
        self,
        username: str,
        mode: str = 'fast',
        tags: List[str] = None,
        top_sites: int = 50,
        parse_pages: bool = False
    ) -> Dict[str, Any]:
        """
        Recherche un username sur les réseaux sociaux.
        
        Args:
            username: Nom d'utilisateur à rechercher
            mode: 'fast' (top sites), 'normal' (500 sites), 'full' (tous)
            tags: Tags pour filtrer (ex: ['photo', 'fr'])
            top_sites: Nombre de sites en mode fast
            parse_pages: Parser les pages pour extraire des infos
            
        Returns:
            dict: Résultats de la recherche
        """
        username = username.strip()
        
        if not username or len(username) < 2:
            return {
                'success': False,
                'error': 'Username invalide (minimum 2 caractères)'
            }
        
        # Sanitize username
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            return {
                'success': False,
                'error': 'Username invalide (caractères alphanumériques, ., _ et - uniquement)'
            }
        
        # Construire la commande - parser directement stdout (plus fiable)
        cmd = [
            "maigret",
            username,
            "--timeout", str(min(self.timeout // 10, 15)),
            "--no-recursion",
            "--no-progressbar",  # Évite les erreurs d'affichage sur Windows
            "--no-color"  # Évite les codes ANSI dans la sortie
        ]
        
        # Mode de recherche
        if mode == 'fast':
            # Limiter aux top sites
            cmd.extend(["--top-sites", str(top_sites)])
        elif mode == 'normal':
            # 500 sites par défaut
            pass
        elif mode == 'full':
            cmd.append("-a")  # Tous les sites
        
        # Tags de filtrage
        if tags:
            cmd.extend(["--tags", ",".join(tags)])
        
        # Parser les pages (plus lent mais plus d'infos)
        if parse_pages:
            cmd.append("--parse-url")
        
        try:
            start_time = time.time()
            
            # Utiliser encoding explicite pour Windows
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.timeout
            )
            
            elapsed = time.time() - start_time
            
            # Debug: log stdout/stderr
            logger.debug(f"Maigret stdout length: {len(process.stdout or '')}")
            logger.debug(f"Maigret stderr length: {len(process.stderr or '')}")
            
            # Parser la sortie stdout (maigret écrit les résultats sur stdout)
            stdout_output = process.stdout or ''
            stderr_output = process.stderr or ''
            
            # Combiner stdout et stderr au cas où
            combined_output = stdout_output + '\n' + stderr_output
            found_sites = self._parse_stdout(combined_output)
            
            logger.debug(f"Found {len(found_sites)} sites from stdout parsing")
            
            return {
                'success': True,
                'username': username,
                'mode': mode,
                'tags_used': tags,
                'found': found_sites,
                'count': len(found_sites),
                'duration_seconds': round(elapsed, 2),
                'sites_checked': self._extract_sites_count(process.stdout or '')
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'username': username,
                'error': f'Timeout dépassé ({self.timeout}s)',
                'found': [],
                'count': 0
            }
        except FileNotFoundError:
            return {
                'success': False,
                'username': username,
                'error': 'Maigret non installé. Exécutez: pip install maigret'
            }
        except Exception as e:
            logger.error(f"Maigret error: {e}")
            return {
                'success': False,
                'username': username,
                'error': str(e)
            }
    
    def _parse_stdout(self, stdout: str) -> List[Dict[str, str]]:
        """Parse la sortie stdout pour extraire les sites trouvés."""
        found = []
        seen_urls = set()
        
        if not stdout:
            return found
        
        # Normaliser les fins de ligne (Windows \r\n -> \n)
        stdout = stdout.replace('\r\n', '\n').replace('\r', '\n')
        
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Pattern 1: [+] SiteName: URL
            # Pattern 2: [+] SiteName [Extra]: URL
            # Le site name peut contenir des espaces, crochets, points, etc.
            if '[+]' in line and 'http' in line:
                # Plusieurs patterns possibles selon la version de maigret
                patterns = [
                    # Pattern standard: [+] Site: https://...
                    r'\[\+\]\s*([^:]+):\s*(https?://[^\s]+)',
                    # Pattern avec [tag]: [+] Site [tag]: https://...
                    r'\[\+\]\s*(.+?):\s*(https?://[^\s]+)',
                    # Pattern simple: [+] https://... (site dans l'URL)
                    r'\[\+\]\s*(https?://[^\s]+)',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        if len(match.groups()) == 2:
                            site_name = match.group(1).strip()
                            url = match.group(2).strip()
                        else:
                            # Pattern avec juste l'URL
                            url = match.group(1).strip()
                            # Extraire le nom du site depuis l'URL
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                site_name = parsed.netloc.replace('www.', '').split('.')[0].title()
                            except:
                                site_name = 'Unknown'
                        
                        # Nettoyer l'URL (enlever les caractères de fin parasites)
                        url = url.rstrip('.,;:!?)"\'')
                        
                        # Éviter les doublons
                        if url and url not in seen_urls and url.startswith('http'):
                            seen_urls.add(url)
                            found.append({
                                'site': site_name,
                                'url': url,
                                'status': 'Claimed',
                                'tags': []
                            })
                        break
        
        return found
    
    def _extract_sites_count(self, stdout: str) -> int:
        """Extrait le nombre de sites vérifiés."""
        # Pattern: "Checking X sites"
        match = re.search(r'Checking\s+(\d+)\s+sites', stdout)
        if match:
            return int(match.group(1))
        return 0
    
    def search_batch(
        self,
        usernames: List[str],
        mode: str = 'fast'
    ) -> Dict[str, Any]:
        """
        Recherche plusieurs usernames.
        
        Args:
            usernames: Liste de usernames
            mode: Mode de recherche
            
        Returns:
            dict: Résultats agrégés
        """
        results = {
            'success': True,
            'total': len(usernames),
            'found_total': 0,
            'results': {}
        }
        
        for username in usernames[:3]:  # Limiter à 3 pour éviter la surcharge
            result = self.search(username, mode=mode)
            results['results'][username] = result
            if result.get('success'):
                results['found_total'] += result.get('count', 0)
        
        return results
    
    def get_available_tags(self) -> Dict[str, List[str]]:
        """Retourne les tags disponibles pour filtrer."""
        return self.AVAILABLE_TAGS


# Fonction utilitaire pour usage direct
def search_username(
    username: str,
    mode: str = 'fast',
    tags: List[str] = None
) -> Dict[str, Any]:
    """
    Fonction raccourcie pour rechercher un username.
    
    Args:
        username: Username à rechercher
        mode: 'fast', 'normal', ou 'full'
        tags: Tags de filtrage optionnels
        
    Returns:
        dict: Résultats Maigret
    """
    runner = MaigretRunner()
    return runner.search(username, mode=mode, tags=tags)
