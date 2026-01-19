"""
Gestionnaire de sécurité pour l'application OSINT Toolkit.

Sécurité renforcée :
- Hashage bcrypt avec salt automatique
- Variable APP_PASSWORD obligatoire
- Protection contre timing attacks
"""
import os
import secrets
import logging
from functools import wraps
from flask import request, session, jsonify

# Bcrypt pour hashage sécurisé avec salt
import bcrypt

logger = logging.getLogger(__name__)


class SecurityManager:
    """Gère l'authentification et la sécurité."""
    
    def __init__(self, app=None):
        self.app = app
        self.password_hash = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialise avec l'application Flask."""
        self.app = app
        
        # 🔴 SÉCURITÉ: APP_PASSWORD est obligatoire
        password = os.environ.get('APP_PASSWORD')
        if not password:
            raise ValueError(
                "🔴 ERREUR CRITIQUE: La variable d'environnement APP_PASSWORD doit être définie.\n"
                "Exemple: export APP_PASSWORD='VotreMotDePasseSecurise123!'"
            )
        
        if len(password) < 8:
            logger.warning("⚠️ APP_PASSWORD trop court (< 8 caractères). Utilisez un mot de passe plus robuste.")
        
        # Hash le mot de passe avec bcrypt (salt automatique)
        self.password_hash = self._hash_password(password)
        logger.info("✅ Mot de passe hashé avec bcrypt")
    
    def _hash_password(self, password: str) -> bytes:
        """
        Hash le mot de passe avec bcrypt.
        
        Bcrypt inclut automatiquement :
        - Un salt unique de 22 caractères
        - Un facteur de coût (work factor) de 12 par défaut
        - Protection contre les attaques par rainbow tables
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    
    def verify_password(self, password: str) -> bool:
        """
        Vérifie si le mot de passe est correct.
        
        Utilise bcrypt.checkpw qui est résistant aux timing attacks.
        """
        if not self.password_hash:
            logger.error("SecurityManager non initialisé")
            return False
        
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)
        except (ValueError, TypeError) as e:
            logger.error(f"Erreur vérification mot de passe: {e}")
            return False
    
    def generate_session_token(self):
        """Génère un token de session sécurisé."""
        return secrets.token_urlsafe(32)
    
    def login_required(self, f):
        """Décorateur pour protéger les routes."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication required',
                    'code': 'AUTH_REQUIRED'
                }), 401
            return f(*args, **kwargs)
        return decorated_function
    
    def get_security_headers(self):
        """Retourne les headers de sécurité HTTP."""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "font-src 'self' data:; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data: https:;"
            )
        }