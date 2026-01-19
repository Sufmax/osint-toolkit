"""
OSINT Toolkit - Application Flask principale
Plateforme légère d'outils OSINT pour Render.com
"""
# ⚠️ MONKEY PATCH EN PREMIER - AVANT TOUT AUTRE IMPORT!
from gevent import monkey
monkey.patch_all()

import os
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv

from utils import OSINTRunner, InputValidator, SecurityManager

# Charger les variables d'environnement
load_dotenv()

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== INITIALISATION ====================

app = Flask(__name__)

# Secret Key avec warning si non définie ou trop courte
secret_key = os.environ.get('SECRET_KEY', '')
if not secret_key or len(secret_key) < 16:
    secret_key = secrets.token_hex(32)
    logger.warning("⚠️ SECRET_KEY non définie ou trop courte, utilisation d'une clé générée")

app.config['SECRET_KEY'] = secret_key
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 heure
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# ============================================================
# CSRF Protection - Configuration pour API JSON
# ============================================================
# On garde CSRF actif pour les formulaires HTML classiques
# mais on l'exempte pour les routes API qui utilisent JSON
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[f"{os.environ.get('RATE_LIMIT_PER_MINUTE', '10')} per minute"],
    storage_uri="memory://"
)

# 🟠 CORS WebSocket - Configuration restreinte via variable d'environnement
# Par défaut: localhost uniquement. En production: spécifier les domaines autorisés
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5000')
if allowed_origins == '*':
    logger.warning("⚠️ CORS WebSocket: '*' est déconseillé en production!")
    cors_origins = "*"
else:
    # Parser la liste séparée par virgules
    cors_origins = [origin.strip() for origin in allowed_origins.split(',') if origin.strip()]
    logger.info(f"🔒 CORS WebSocket restreint à: {cors_origins}")

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins,
    async_mode='gevent',
    ping_timeout=60,
    ping_interval=25,
    manage_session=False,
    logger=False,
    engineio_logger=False
)

# Stockage des clients WebSocket authentifiés
authenticated_clients = {}

# Security Manager
security = SecurityManager(app)

# OSINT Runner
osint = OSINTRunner(socketio=socketio)

# ==================== MIDDLEWARE ====================

@app.after_request
def add_security_headers(response):
    """Ajoute les headers de sécurité à chaque réponse."""
    headers = security.get_security_headers()
    for key, value in headers.items():
        response.headers[key] = value
    return response

# 🟡 Note: Ce décorateur est défini localement car security.login_required est une méthode d'instance.
# Pour une refactorisation future, envisager de déplacer vers un module décorateurs dédié.
def login_required(f):
    """
    Décorateur pour protéger les routes REST.
    
    Retourne 401 si l'utilisateur n'est pas authentifié via session Flask.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({
                'success': False,
                'error': 'Authentification requise',
                'code': 'AUTH_REQUIRED'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

# ==================== GESTION ERREUR CSRF ====================

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Gère les erreurs CSRF de manière propre."""
    logger.warning(f"CSRF Error: {e.description}")
    return jsonify({
        'success': False,
        'error': 'Session expirée, veuillez rafraîchir la page',
        'code': 'CSRF_ERROR'
    }), 400

# ==================== ROUTES PRINCIPALES ====================

@app.route('/')
def index():
    """Page principale."""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check pour Render.com."""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'websocket': 'enabled',
        'clients_connected': len(authenticated_clients)
    })

# ============================================================
# ROUTES API - Exemptées du CSRF (utilisent JSON)
# ============================================================

@app.route('/api/auth/check', methods=['GET'])
@csrf.exempt
def check_auth():
    """Vérifie si l'utilisateur est authentifié."""
    return jsonify({
        'authenticated': session.get('authenticated', False)
    })

@app.route('/api/auth/login', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def login():
    """Authentification par mot de passe."""
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'Données manquantes'
        }), 400
    
    password = data.get('password', '')
    
    if security.verify_password(password):
        session['authenticated'] = True
        session['login_time'] = datetime.now().isoformat()
        session.permanent = True
        
        logger.info(f"✅ Login successful from {get_remote_address()}")
        return jsonify({
            'success': True,
            'message': 'Connexion réussie'
        })
    else:
        logger.warning(f"❌ Failed login attempt from {get_remote_address()}")
        return jsonify({
            'success': False,
            'error': 'Mot de passe incorrect'
        }), 401

@app.route('/api/auth/logout', methods=['POST'])
@csrf.exempt
def logout():
    """Déconnexion."""
    for sid in list(authenticated_clients.keys()):
        client_info = authenticated_clients.get(sid, {})
        if client_info.get('ip') == get_remote_address():
            del authenticated_clients[sid]
            logger.info(f"🔌 WebSocket client cleaned up: {sid}")
    
    session.clear()
    return jsonify({'success': True, 'message': 'Déconnexion réussie'})

@app.route('/api/tools', methods=['GET'])
@csrf.exempt
def get_tools():
    """Liste des outils disponibles."""
    tools = {
        'sherlock': {
            'id': 'sherlock',
            'name': {
                'fr': 'Recherche Username',
                'en': 'Username Search'
            },
            'description': {
                'fr': 'Recherche un pseudo sur 400+ réseaux sociaux et sites web.',
                'en': 'Search for a username across 400+ social networks and websites.'
            },
            'input_type': 'username',
            'input_placeholder': {
                'fr': 'Entrez un pseudo...',
                'en': 'Enter a username...'
            },
            'options': [
                {
                    'id': 'fast_mode',
                    'type': 'checkbox',
                    'label': {'fr': 'Mode rapide (20 sites)', 'en': 'Fast mode (20 sites)'},
                    'default': True
                }
            ]
        },
        'holehe': {
            'id': 'holehe',
            'name': {
                'fr': 'Email → Comptes',
                'en': 'Email → Accounts'
            },
            'description': {
                'fr': 'Vérifie si une adresse email est enregistrée sur 120+ services.',
                'en': 'Check if an email is registered on 120+ services.'
            },
            'input_type': 'email',
            'input_placeholder': {
                'fr': 'Entrez une adresse email...',
                'en': 'Enter an email address...'
            },
            'options': []
        },
        'email_validator': {
            'id': 'email_validator',
            'name': {
                'fr': 'Validation Email',
                'en': 'Email Validation'
            },
            'description': {
                'fr': 'Vérifie la syntaxe et l\'existence du domaine d\'un email.',
                'en': 'Verify email syntax and domain existence.'
            },
            'input_type': 'email',
            'input_placeholder': {
                'fr': 'Entrez une adresse email...',
                'en': 'Enter an email address...'
            },
            'options': [
                {
                    'id': 'check_dns',
                    'type': 'checkbox',
                    'label': {'fr': 'Vérifier DNS/MX', 'en': 'Check DNS/MX'},
                    'default': True
                }
            ]
        },
        'whois': {
            'id': 'whois',
            'name': {
                'fr': 'WHOIS Domaine',
                'en': 'Domain WHOIS'
            },
            'description': {
                'fr': 'Récupère les informations d\'enregistrement d\'un domaine.',
                'en': 'Retrieve domain registration information.'
            },
            'input_type': 'domain',
            'input_placeholder': {
                'fr': 'Entrez un nom de domaine...',
                'en': 'Enter a domain name...'
            },
            'options': []
        },
        'dns': {
            'id': 'dns',
            'name': {
                'fr': 'Lookup DNS',
                'en': 'DNS Lookup'
            },
            'description': {
                'fr': 'Récupère les enregistrements DNS (A, MX, TXT, NS...).',
                'en': 'Retrieve DNS records (A, MX, TXT, NS...).'
            },
            'input_type': 'domain',
            'input_placeholder': {
                'fr': 'Entrez un nom de domaine...',
                'en': 'Enter a domain name...'
            },
            'options': [
                {
                    'id': 'record_types',
                    'type': 'multiselect',
                    'label': {'fr': 'Types d\'enregistrements', 'en': 'Record types'},
                    'choices': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'],
                    'default': ['A', 'MX', 'NS', 'TXT']
                }
            ]
        },
        'phone': {
            'id': 'phone',
            'name': {
                'fr': 'Analyse Téléphone',
                'en': 'Phone Analysis'
            },
            'description': {
                'fr': 'Analyse et valide un numéro de téléphone (pays, opérateur, type).',
                'en': 'Analyze and validate a phone number (country, carrier, type).'
            },
            'input_type': 'phone',
            'input_placeholder': {
                'fr': 'Entrez un numéro (ex: +33612345678)...',
                'en': 'Enter a number (e.g. +33612345678)...'
            },
            'options': [
                {
                    'id': 'default_region',
                    'type': 'select',
                    'label': {'fr': 'Pays par défaut', 'en': 'Default country'},
                    'choices': ['FR', 'US', 'GB', 'DE', 'ES', 'IT', 'BE', 'CH', 'CA'],
                    'default': 'FR'
                }
            ]
        },
        'ip': {
            'id': 'ip',
            'name': {
                'fr': 'Lookup IP',
                'en': 'IP Lookup'
            },
            'description': {
                'fr': 'Récupère les informations WHOIS/ASN d\'une adresse IP.',
                'en': 'Retrieve WHOIS/ASN information for an IP address.'
            },
            'input_type': 'ip',
            'input_placeholder': {
                'fr': 'Entrez une adresse IP...',
                'en': 'Enter an IP address...'
            },
            'options': []
        },
        'wayback': {
            'id': 'wayback',
            'name': {
                'fr': 'Wayback Machine',
                'en': 'Wayback Machine'
            },
            'description': {
                'fr': 'Recherche les archives historiques d\'une URL (Internet Archive).',
                'en': 'Search historical archives of a URL (Internet Archive).'
            },
            'input_type': 'url',
            'input_placeholder': {
                'fr': 'Entrez une URL...',
                'en': 'Enter a URL...'
            },
            'options': [
                {
                    'id': 'limit',
                    'type': 'number',
                    'label': {'fr': 'Nombre de snapshots', 'en': 'Number of snapshots'},
                    'default': 20,
                    'min': 5,
                    'max': 50
                }
            ]
        },
        # ==================== NOUVEAUX OUTILS ====================
        'exif': {
            'id': 'exif',
            'name': {
                'fr': 'Analyse EXIF',
                'en': 'EXIF Analyzer'
            },
            'description': {
                'fr': 'Extrait les métadonnées EXIF d\'une image (GPS, caméra, date).',
                'en': 'Extract EXIF metadata from an image (GPS, camera, date).'
            },
            'input_type': 'text',
            'input_placeholder': {
                'fr': 'Chemin ou URL d\'une image...',
                'en': 'Path or URL to an image...'
            },
            'options': []
        },
        'subdomains': {
            'id': 'subdomains',
            'name': {
                'fr': 'Recherche Sous-domaines',
                'en': 'Subdomain Finder'
            },
            'description': {
                'fr': 'Découvre les sous-domaines via CT logs et APIs.',
                'en': 'Discover subdomains via CT logs and APIs.'
            },
            'input_type': 'domain',
            'input_placeholder': {
                'fr': 'Entrez un nom de domaine...',
                'en': 'Enter a domain name...'
            },
            'options': []
        },
        'ssl': {
            'id': 'ssl',
            'name': {
                'fr': 'Analyse SSL',
                'en': 'SSL Analyzer'
            },
            'description': {
                'fr': 'Analyse le certificat SSL/TLS d\'un serveur.',
                'en': 'Analyze SSL/TLS certificate of a server.'
            },
            'input_type': 'domain',
            'input_placeholder': {
                'fr': 'Entrez un hostname...',
                'en': 'Enter a hostname...'
            },
            'options': [
                {
                    'id': 'port',
                    'type': 'number',
                    'label': {'fr': 'Port', 'en': 'Port'},
                    'default': 443,
                    'min': 1,
                    'max': 65535
                }
            ]
        },
        'hash': {
            'id': 'hash',
            'name': {
                'fr': 'Recherche Hash',
                'en': 'Hash Lookup'
            },
            'description': {
                'fr': 'Vérifie un hash (MD5/SHA) dans les bases de menaces.',
                'en': 'Check a hash (MD5/SHA) against threat intelligence DBs.'
            },
            'input_type': 'text',
            'input_placeholder': {
                'fr': 'Entrez un hash MD5, SHA1 ou SHA256...',
                'en': 'Enter a MD5, SHA1 or SHA256 hash...'
            },
            'options': []
        },
        'mac': {
            'id': 'mac',
            'name': {
                'fr': 'Lookup MAC',
                'en': 'MAC Lookup'
            },
            'description': {
                'fr': 'Identifie le fabricant d\'un appareil via son adresse MAC.',
                'en': 'Identify device vendor from MAC address.'
            },
            'input_type': 'text',
            'input_placeholder': {
                'fr': 'Entrez une adresse MAC (AA:BB:CC:DD:EE:FF)...',
                'en': 'Enter a MAC address (AA:BB:CC:DD:EE:FF)...'
            },
            'options': []
        },
        'social': {
            'id': 'social',
            'name': {
                'fr': 'Analyse Sociale',
                'en': 'Social Analyzer'
            },
            'description': {
                'fr': 'Recherche des profils sociaux (Gravatar, GitHub, GitLab).',
                'en': 'Find social profiles (Gravatar, GitHub, GitLab).'
            },
            'input_type': 'text',
            'input_placeholder': {
                'fr': 'Entrez un email ou username...',
                'en': 'Enter an email or username...'
            },
            'options': []
        },
        'maigret': {
            'id': 'maigret',
            'name': {
                'fr': 'Maigret (3000+ sites)',
                'en': 'Maigret (3000+ sites)'
            },
            'description': {
                'fr': 'Recherche avancée de username sur 3000+ sites (fork de Sherlock).',
                'en': 'Advanced username search on 3000+ sites (Sherlock fork).'
            },
            'input_type': 'username',
            'input_placeholder': {
                'fr': 'Entrez un pseudo...',
                'en': 'Enter a username...'
            },
            'options': [
                {
                    'id': 'mode',
                    'type': 'select',
                    'label': {'fr': 'Mode de recherche', 'en': 'Search mode'},
                    'choices': ['fast', 'normal', 'full'],
                    'default': 'fast'
                },
                {
                    'id': 'top_sites',
                    'type': 'number',
                    'label': {'fr': 'Nombre de sites (mode fast)', 'en': 'Number of sites (fast mode)'},
                    'default': 50,
                    'min': 10,
                    'max': 200
                }
            ]
        }
    }
    
    return jsonify({
        'success': True,
        'tools': tools
    })

@app.route('/api/run/<tool>', methods=['POST'])
@csrf.exempt
@login_required
@limiter.limit("10 per minute")
def run_tool_sync(tool):
    """
    Exécute un outil OSINT (mode synchrone/fallback REST).
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'Données manquantes'
        }), 400
    
    value = data.get('value', '')
    options = data.get('options', {})
    
    validated, error = InputValidator.validate_for_tool(tool, value)
    if error:
        return jsonify({
            'success': False,
            'error': error
        }), 400
    
    try:
        result = osint.run(tool, validated, **options)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error running {tool}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Erreur interne: {str(e)}"
        }), 500

# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    """Client WebSocket connecté."""
    sid = request.sid
    
    if not session.get('authenticated'):
        logger.warning(f"🚫 WebSocket rejected (not authenticated): {sid}")
        return False
    
    authenticated_clients[sid] = {
        'connected_at': datetime.now().isoformat(),
        'ip': get_remote_address()
    }
    
    join_room(sid)
    logger.info(f"🟢 WebSocket connected: {sid}")
    emit('connected', {
        'sid': sid,
        'message': 'Connexion WebSocket établie'
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Client WebSocket déconnecté."""
    sid = request.sid
    
    if sid in authenticated_clients:
        del authenticated_clients[sid]
    
    leave_room(sid)
    logger.info(f"🔴 WebSocket disconnected: {sid}")

@socketio.on('ping')
def handle_ping():
    """Ping pour garder la connexion active."""
    emit('pong', {'timestamp': datetime.now().isoformat()})

@socketio.on('run_tool')
def handle_run_tool(data):
    """Exécute un outil OSINT via WebSocket (temps réel)."""
    sid = request.sid
    
    if sid not in authenticated_clients:
        emit('error', {
            'message': 'Session expirée, veuillez vous reconnecter',
            'code': 'SESSION_EXPIRED'
        })
        return
    
    tool = data.get('tool')
    value = data.get('value', '')
    options = data.get('options', {})
    
    validated, error = InputValidator.validate_for_tool(tool, value)
    if error:
        emit('error', {'message': error, 'tool': tool})
        return
    
    emit('started', {
        'tool': tool,
        'value': validated,
        'timestamp': datetime.now().isoformat()
    })
    
    try:
        result = osint.run(tool, validated, sid=sid, **options)
        emit('completed', {
            'tool': tool,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"WebSocket error running {tool}: {str(e)}")
        emit('error', {
            'tool': tool,
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        })

@socketio.on_error_default
def default_error_handler(e):
    """Gestion globale des erreurs WebSocket."""
    logger.error(f"WebSocket error: {str(e)}")
    emit('error', {'message': 'Erreur interne WebSocket'})

# ==================== ERROR HANDLERS ====================

@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Rate limit dépassé."""
    return jsonify({
        'success': False,
        'error': 'Trop de requêtes. Veuillez patienter.',
        'code': 'RATE_LIMIT'
    }), 429

@app.errorhandler(404)
def not_found(e):
    """Page non trouvée."""
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': 'Ressource non trouvée',
            'code': 'NOT_FOUND'
        }), 404
    return render_template('index.html')

@app.errorhandler(500)
def internal_error(e):
    """Erreur interne."""
    logger.error(f"Internal error: {str(e)}")
    return jsonify({
        'success': False,
        'error': 'Erreur interne du serveur',
        'code': 'INTERNAL_ERROR'
    }), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    logger.info("=" * 50)
    logger.info("🔍 OSINT Toolkit")
    logger.info("=" * 50)
    logger.info(f"🚀 Starting on port {port}")
    logger.info(f"📡 WebSocket enabled (gevent)")
    logger.info(f"🔧 Debug mode: {debug}")
    logger.info(f"🔒 Password protection: enabled")
    logger.info("=" * 50)
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        use_reloader=False
    )