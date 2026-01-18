"""
Gestionnaire de sécurité pour l'application OSINT Toolkit.
"""
import os
import hashlib
import secrets
from functools import wraps
from flask import request, session, jsonify

class SecurityManager:
    """Gère l'authentification et la sécurité."""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialise avec l'application Flask."""
        self.app = app
        # Mot de passe par défaut (à changer!)
        self.password_hash = self._hash_password(
            os.environ.get('APP_PASSWORD', 'Mon#mdp3')
        )
    
    def _hash_password(self, password):
        """Hash le mot de passe avec SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password):
        """Vérifie si le mot de passe est correct."""
        return self._hash_password(password) == self.password_hash
    
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