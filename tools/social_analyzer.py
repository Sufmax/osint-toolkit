"""
Module: Social Analyzer
Description: Recherche d'informations sur les profils sociaux via APIs publiques
RAM: ~3 Mo | Dépendances: requests (déjà présent)

APIs utilisées:
- Gravatar (via hash email)
- GitHub API (profil public)
- GitLab API (profil public)
"""

import logging
import hashlib
import re
from typing import Dict, Any, Optional, List
import requests

logger = logging.getLogger(__name__)


class SocialAnalyzer:
    """
    Analyse de présence sociale via APIs publiques.
    
    Recherche des informations associées à un email ou username
    sur différentes plateformes.
    """
    
    # APIs publiques
    APIS = {
        'gravatar': {
            'profile': 'https://www.gravatar.com/',
            'avatar': 'https://www.gravatar.com/avatar/'
        },
        'github': {
            'user': 'https://api.github.com/users/',
            'search': 'https://api.github.com/search/users'
        },
        'gitlab': {
            'user': 'https://gitlab.com/api/v4/users',
        }
    }
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,39}$')
    
    def __init__(self, timeout: int = 15):
        """
        Initialise l'analyseur.
        
        Args:
            timeout: Timeout pour les requêtes
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Toolkit/1.0 (Social Analyzer)',
            'Accept': 'application/json'
        })
    
    def analyze_email(self, email: str) -> Dict[str, Any]:
        """
        Analyse un email pour trouver les profils associés.
        
        Args:
            email: Adresse email à analyser
            
        Returns:
            dict: Profils trouvés sur différentes plateformes
        """
        email = email.strip().lower()
        
        if not self.EMAIL_PATTERN.match(email):
            return {
                'success': False,
                'error': 'Format email invalide'
            }
        
        result = {
            'success': True,
            'email': email,
            'email_hash': self._hash_email(email),
            'profiles': {},
            'found_count': 0
        }
        
        # Gravatar
        gravatar_result = self._check_gravatar(email)
        result['profiles']['gravatar'] = gravatar_result
        if gravatar_result.get('found'):
            result['found_count'] += 1
        
        # GitHub (recherche par email)
        github_result = self._search_github_email(email)
        result['profiles']['github'] = github_result
        if github_result.get('found'):
            result['found_count'] += 1
        
        return result
    
    def analyze_username(self, username: str, platforms: List[str] = None) -> Dict[str, Any]:
        """
        Analyse un username sur différentes plateformes.
        
        Args:
            username: Nom d'utilisateur à analyser
            platforms: Liste de plateformes (None = toutes)
            
        Returns:
            dict: Profils trouvés
        """
        username = username.strip()
        
        if not self.USERNAME_PATTERN.match(username):
            return {
                'success': False,
                'error': 'Format username invalide (1-39 caractères alphanumériques, _ ou -)'
            }
        
        result = {
            'success': True,
            'username': username,
            'profiles': {},
            'found_count': 0
        }
        
        if platforms is None:
            platforms = ['github', 'gitlab']
        
        for platform in platforms:
            if platform == 'github':
                gh_result = self._check_github_user(username)
                result['profiles']['github'] = gh_result
                if gh_result.get('found'):
                    result['found_count'] += 1
            
            elif platform == 'gitlab':
                gl_result = self._check_gitlab_user(username)
                result['profiles']['gitlab'] = gl_result
                if gl_result.get('found'):
                    result['found_count'] += 1
        
        return result
    
    def full_analysis(self, identifier: str) -> Dict[str, Any]:
        """
        Analyse complète - détecte si c'est un email ou username.
        
        Args:
            identifier: Email ou username
            
        Returns:
            dict: Résultat de l'analyse
        """
        identifier = identifier.strip()
        
        result = {
            'success': True,
            'identifier': identifier,
            'type': None,
            'profiles': {},
            'found_count': 0,
            'osint_summary': {}
        }
        
        if self.EMAIL_PATTERN.match(identifier.lower()):
            result['type'] = 'email'
            email_result = self.analyze_email(identifier)
            result['profiles'] = email_result.get('profiles', {})
            result['found_count'] = email_result.get('found_count', 0)
        
        elif self.USERNAME_PATTERN.match(identifier):
            result['type'] = 'username'
            username_result = self.analyze_username(identifier)
            result['profiles'] = username_result.get('profiles', {})
            result['found_count'] = username_result.get('found_count', 0)
        
        else:
            return {
                'success': False,
                'error': 'Identifiant non reconnu (email ou username attendu)'
            }
        
        # Générer un résumé OSINT
        result['osint_summary'] = self._generate_summary(result)
        
        return result
    
    def _hash_email(self, email: str) -> str:
        """Génère le hash MD5 de l'email (pour Gravatar)."""
        return hashlib.md5(email.encode('utf-8')).hexdigest()
    
    def _check_gravatar(self, email: str) -> Dict[str, Any]:
        """Vérifie la présence d'un profil Gravatar."""
        try:
            email_hash = self._hash_email(email)
            
            # Vérifier le profil JSON
            profile_url = f"{self.APIS['gravatar']['profile']}{email_hash}.json"
            
            response = self.session.get(
                profile_url,
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                # Pas de profil, mais vérifier l'avatar
                return self._check_gravatar_avatar(email_hash)
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            entry = data.get('entry', [{}])[0]
            
            return {
                'found': True,
                'has_profile': True,
                'profile_url': entry.get('profileUrl'),
                'display_name': entry.get('displayName'),
                'preferred_username': entry.get('preferredUsername'),
                'about': entry.get('aboutMe'),
                'location': entry.get('currentLocation'),
                'avatar_url': f"{self.APIS['gravatar']['avatar']}{email_hash}",
                'accounts': [
                    {
                        'name': acc.get('shortname'),
                        'url': acc.get('url'),
                        'username': acc.get('username')
                    }
                    for acc in entry.get('accounts', [])
                ],
                'urls': entry.get('urls', [])
            }
            
        except requests.RequestException as e:
            logger.warning(f"Gravatar error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError, IndexError) as e:
            logger.warning(f"Gravatar parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _check_gravatar_avatar(self, email_hash: str) -> Dict[str, Any]:
        """Vérifie si un avatar Gravatar existe (même sans profil)."""
        try:
            # Demander l'avatar avec d=404 pour avoir une 404 si pas d'avatar
            avatar_url = f"{self.APIS['gravatar']['avatar']}{email_hash}?d=404"
            
            response = self.session.head(
                avatar_url,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return {
                    'found': True,
                    'has_profile': False,
                    'has_avatar': True,
                    'avatar_url': f"{self.APIS['gravatar']['avatar']}{email_hash}"
                }
            
            return {'found': False}
            
        except requests.RequestException:
            return {'found': False}
    
    def _search_github_email(self, email: str) -> Dict[str, Any]:
        """Recherche un utilisateur GitHub par email."""
        try:
            response = self.session.get(
                self.APIS['github']['search'],
                params={'q': f'{email} in:email'},
                timeout=self.timeout
            )
            
            if response.status_code == 403:
                return {
                    'found': False,
                    'error': 'Rate limit GitHub atteint'
                }
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            
            if data.get('total_count', 0) == 0:
                return {'found': False}
            
            users = data.get('items', [])
            if not users:
                return {'found': False}
            
            # Prendre le premier résultat et récupérer les détails
            user = users[0]
            return self._check_github_user(user.get('login'))
            
        except requests.RequestException as e:
            logger.warning(f"GitHub search error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"GitHub parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _check_github_user(self, username: str) -> Dict[str, Any]:
        """Récupère les informations d'un profil GitHub."""
        try:
            response = self.session.get(
                f"{self.APIS['github']['user']}{username}",
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                return {'found': False}
            
            if response.status_code == 403:
                return {
                    'found': False,
                    'error': 'Rate limit GitHub atteint'
                }
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            
            return {
                'found': True,
                'platform': 'github',
                'username': data.get('login'),
                'profile_url': data.get('html_url'),
                'avatar_url': data.get('avatar_url'),
                'name': data.get('name'),
                'company': data.get('company'),
                'blog': data.get('blog'),
                'location': data.get('location'),
                'email': data.get('email'),
                'bio': data.get('bio'),
                'twitter': data.get('twitter_username'),
                'public_repos': data.get('public_repos'),
                'public_gists': data.get('public_gists'),
                'followers': data.get('followers'),
                'following': data.get('following'),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at')
            }
            
        except requests.RequestException as e:
            logger.warning(f"GitHub user error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"GitHub parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _check_gitlab_user(self, username: str) -> Dict[str, Any]:
        """Récupère les informations d'un profil GitLab."""
        try:
            response = self.session.get(
                self.APIS['gitlab']['user'],
                params={'username': username},
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                return {
                    'found': False,
                    'error': f'HTTP {response.status_code}'
                }
            
            data = response.json()
            
            if not data or len(data) == 0:
                return {'found': False}
            
            user = data[0]
            
            return {
                'found': True,
                'platform': 'gitlab',
                'username': user.get('username'),
                'profile_url': user.get('web_url'),
                'avatar_url': user.get('avatar_url'),
                'name': user.get('name'),
                'state': user.get('state'),
                'created_at': user.get('created_at')
            }
            
        except requests.RequestException as e:
            logger.warning(f"GitLab error: {e}")
            return {
                'found': False,
                'error': str(e)
            }
        except (ValueError, KeyError, IndexError) as e:
            logger.warning(f"GitLab parse error: {e}")
            return {
                'found': False,
                'error': 'Erreur parsing réponse'
            }
    
    def _generate_summary(self, result: Dict) -> Dict[str, Any]:
        """
        Génère un résumé OSINT des informations trouvées.
        """
        summary = {
            'platforms_found': [],
            'potential_real_name': None,
            'potential_location': None,
            'potential_company': None,
            'linked_accounts': [],
            'activity_score': 0
        }
        
        profiles = result.get('profiles', {})
        
        for platform, data in profiles.items():
            if data.get('found'):
                summary['platforms_found'].append(platform)
                
                # Extraire les informations communes
                if data.get('name') and not summary['potential_real_name']:
                    summary['potential_real_name'] = data.get('name')
                
                if data.get('location') and not summary['potential_location']:
                    summary['potential_location'] = data.get('location')
                
                if data.get('company') and not summary['potential_company']:
                    summary['potential_company'] = data.get('company')
                
                # Comptes liés (Gravatar)
                if platform == 'gravatar' and data.get('accounts'):
                    summary['linked_accounts'].extend(data.get('accounts', []))
                
                # Score d'activité (GitHub)
                if platform == 'github':
                    repos = data.get('public_repos', 0)
                    followers = data.get('followers', 0)
                    summary['activity_score'] = min(100, repos * 2 + followers)
        
        return summary


# Fonction utilitaire pour usage direct
def analyze_social(identifier: str) -> Dict[str, Any]:
    """
    Fonction raccourcie pour analyser un identifiant social.
    
    Args:
        identifier: Email ou username
        
    Returns:
        dict: Profils trouvés
    """
    analyzer = SocialAnalyzer()
    return analyzer.full_analysis(identifier)
