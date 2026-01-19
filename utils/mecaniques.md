# 📘 OSINT Toolkit — Documentation Technique

**Version:** 1.1  
**Date:** 2026-01-19  
**Auteur:** Audit automatisé

---

## 1. Vue d'ensemble

### Architecture globale

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Browser)                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │ HTML/CSS SPA │───│ JavaScript   │───│ LocalStorage         │ │
│  │ (index.html) │   │ Vanilla      │   │ (historique/i18n)    │ │
│  └──────────────┘   └──────────────┘   └──────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTP / WebSocket
┌─────────────────────────────▼───────────────────────────────────┐
│                         FLASK SERVER                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │ app.py       │───│ Flask-       │───│ Flask-Limiter        │ │
│  │ (routes)     │   │ SocketIO     │   │ (rate limiting)      │ │
│  └──────────────┘   └──────────────┘   └──────────────────────┘ │
│                              │                                   │
│  ┌───────────────────────────▼──────────────────────────────────┤
│  │                     utils/                                    │
│  │  ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐ │
│  │  │ security.py    │ │ validators.py  │ │ osint_runner.py  │ │
│  │  │ (auth, headers)│ │ (input sanit.) │ │ (tools wrapper)  │ │
│  │  └────────────────┘ └────────────────┘ └────────┬─────────┘ │
│  └─────────────────────────────────────────────────┼───────────┘
└────────────────────────────────────────────────────┼────────────┘
                                                     │
┌────────────────────────────────────────────────────▼────────────┐
│                       OSINT TOOLS                                │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌───────┐ ┌────────────┐ │
│  │Sherlock │ │ Holehe  │ │dnspython │ │ whois │ │phonenumbers│ │
│  │(CLI)    │ │(CLI)    │ │(library) │ │(lib)  │ │(library)   │ │
│  └─────────┘ └─────────┘ └──────────┘ └───────┘ └────────────┘ │
│  ┌─────────────────┐  ┌────────────────────────────────────────┐│
│  │ waybackpy (API) │  │ ip-api.com (external HTTP API)         ││
│  └─────────────────┘  └────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Flux de données principal

1. **Authentification** : Mot de passe → SHA-256 → Session Flask
2. **Requête OSINT** : Input → Validation → OSINTRunner → Outil → Résultat
3. **Communication** : WebSocket (priorité) avec fallback REST API
4. **Stockage client** : LocalStorage (historique, langue)

---

## 2. Mécaniques principales

### 2.1 Module `app.py` — Application Flask

**Responsabilités :**
- Initialisation Flask avec gevent monkey-patching
- Configuration CSRF, rate limiting, sessions
- Routes REST API (`/api/*`)
- Événements WebSocket (`run_tool`, `progress`, `completed`)

**Mécanisme d'authentification :**
```python
# Session Flask avec cookie sécurisé
session['authenticated'] = True
session['login_time'] = datetime.now().isoformat()
session.permanent = True  # 24h TTL
```

**Mécanisme WebSocket :**
```python
# Stockage des clients authentifiés
authenticated_clients = {}  # sid -> {connected_at, ip}

# Vérification à chaque événement
if sid not in authenticated_clients:
    emit('error', {'code': 'SESSION_EXPIRED'})
    return
```

### 2.2 Module `osint_runner.py` — Exécution des outils

**Pattern Dispatcher :**
```python
def run(self, tool, value, sid=None, **options):
    tools = {
        'sherlock': self.run_sherlock,
        'holehe': self.run_holehe,
        # ...
    }
    return tools.get(tool)(value, sid=sid, **options)
```

**Outils et méthodes d'exécution :**

|| Outil | Type | Méthode |
||-------|------|---------|
|| Sherlock | CLI subprocess | `subprocess.run` avec parsing stdout (Windows-compatible) |
|| Holehe | CLI subprocess | `subprocess.run` avec parsing stdout |
|| Maigret | CLI subprocess | `subprocess.run` avec `--no-progressbar --no-color` |
|| Email Validator | Library | `email_validator.validate_email()` |
|| WHOIS | Library | `whois.whois()` |
|| DNS | Library | `dns.resolver.resolve()` |
|| Phone | Library | `phonenumbers.parse()` |
|| IP | HTTP API | `requests.get('https://ipinfo.io/')` (HTTPS) |
|| Wayback | Library | `WaybackMachineCDXServerAPI` |

**Notes importantes pour Windows :**
- Utilisation de `encoding='utf-8'` et `errors='replace'` dans subprocess
- Normalisation des fins de ligne (`\r\n` → `\n`)
- Options `--no-progressbar` et `--no-color` pour Maigret (évite les erreurs d'affichage)
- Parsing stdout + stderr combinés (certains outils écrivent sur stderr)

### 2.3 Module `validators.py` — Validation des entrées

**Patterns regex utilisés :**
```python
PATTERNS = {
    'username': r'^[a-zA-Z0-9_.-]{1,50}$',
    'domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'ip': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}...',
    'phone': r'^[\d\s\-\+\(\)]{6,20}$'
}
```

**Sanitization :**
```python
def sanitize_string(cls, value, max_length=200):
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)  # Supprime caractères de contrôle
    return value.strip()[:max_length]
```

### 2.4 Module `security.py` — Sécurité

**Hachage mot de passe :**
```python
def _hash_password(self, password):
    return hashlib.sha256(password.encode()).hexdigest()
```

**Headers de sécurité :**
```python
{
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'..."
}
```

### 2.5 Frontend `index.html` — SPA JavaScript

**État global :**
```javascript
const state = {
    lang: localStorage.getItem('osint_lang') || 'fr',
    authenticated: false,
    currentTool: null,
    tools: {},
    searchInProgress: false,
    currentResults: null,
    history: JSON.parse(localStorage.getItem('osint_history') || '[]'),
    socketConnected: false
};
```

**Stratégie de connexion WebSocket :**
1. Chargement dynamique avec fallbacks CDN
2. Connexion post-authentification
3. Fallback automatique vers REST API si WebSocket indisponible

---

## 3. Intégrations API

### 3.1 APIs externes

| Service | Endpoint | Auth | Rate Limit | Utilisation |
|---------|----------|------|------------|-------------|
| ip-api.com | `http://ip-api.com/json/{ip}` | Aucune | 45 req/min | Géolocalisation IP |
| Wayback Machine | CDX Server API | Aucune | Non documenté | Archives web |

### 3.2 APIs internes

| Route | Méthode | Auth | Rate Limit | Description |
|-------|---------|------|------------|-------------|
| `/api/auth/check` | GET | Non | — | Vérifie session |
| `/api/auth/login` | POST | Non | 5/min | Authentification |
| `/api/auth/logout` | POST | Non | — | Déconnexion |
| `/api/tools` | GET | Non | — | Liste des outils |
| `/api/run/<tool>` | POST | Oui | 10/min | Exécution outil |

### 3.3 Événements WebSocket

| Événement Client → Serveur | Payload |
|----------------------------|---------|
| `run_tool` | `{tool, value, options}` |
| `ping` | — |

| Événement Serveur → Client | Payload |
|----------------------------|---------|
| `connected` | `{sid, message}` |
| `started` | `{tool, value, timestamp}` |
| `progress` | `{tool, message, progress, result}` |
| `completed` | `{tool, result, timestamp}` |
| `error` | `{message, code}` |

---

## 4. Points critiques

### 🔴 Critique — Hashage mot de passe non sécurisé

**Fichier :** `utils/security.py:26-28`

```python
def _hash_password(self, password):
    return hashlib.sha256(password.encode()).hexdigest()
```

**Problème :** SHA-256 sans sel (salt) est vulnérable aux attaques par rainbow tables et force brute. Un attaquant peut précalculer des hashes pour des mots de passe courants.

**Solution :**
```python
import bcrypt

def _hash_password(self, password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(self, password):
    return bcrypt.checkpw(password.encode(), self.password_hash.encode())
```

---

### 🔴 Critique — Mot de passe par défaut en production

**Fichier :** `utils/security.py:22-24` et `.env:2`

```python
self.password_hash = self._hash_password(
    os.environ.get('APP_PASSWORD', 'Mon#mdp3')  # Valeur par défaut dangereuse
)
```

**Problème :** Si `APP_PASSWORD` n'est pas définie, le système utilise un mot de passe codé en dur, connu publiquement via le code source.

**Solution :**
```python
password = os.environ.get('APP_PASSWORD')
if not password:
    raise ValueError("APP_PASSWORD environment variable must be set")
self.password_hash = self._hash_password(password)
```

---

### 🔴 Critique — Fichier `.env` versionné

**Fichier :** `.env`

```env
APP_PASSWORD=Mon#MOT@dePass26
SECRET_KEY=
```

**Problème :** Le fichier `.env` contient des secrets et ne devrait jamais être versionné (Git). Le mot de passe réel est exposé.

**Solution :**
1. Ajouter `.env` au `.gitignore`
2. Créer un `.env.example` avec des valeurs factices
3. Utiliser un gestionnaire de secrets en production

---

### 🔴 Critique — API IP non sécurisée (HTTP)

**Fichier :** `utils/osint_runner.py:570-578`

```python
response = requests.get(
    f'http://ip-api.com/json/{ip_address}',  # HTTP non chiffré !
    ...
)
```

**Problème :** L'utilisation de HTTP expose les requêtes à l'interception (MITM). Les données de géolocalisation peuvent être falsifiées.

**Solution :**
```python
# Utiliser l'API HTTPS (requiert clé API gratuite)
response = requests.get(
    f'https://pro.ip-api.com/json/{ip_address}',
    params={'key': os.environ.get('IPAPI_KEY'), ...}
)
# Ou utiliser une alternative HTTPS native comme ipinfo.io
```

---

### 🟠 Important — Injection de commande potentielle (Sherlock)

**Fichier :** `utils/osint_runner.py:116-127`

```python
cmd = [
    "sherlock",
    username,  # Valeur utilisateur
    "--json", output_file,
    ...
]
```

**Problème :** Bien que `subprocess.Popen` avec liste évite l'injection shell classique, le username est passé directement à Sherlock qui pourrait l'interpréter de manière inattendue.

**Solution :**
```python
# Validation plus stricte en amont
if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
    return {'success': False, 'error': 'Invalid username format'}

# Échapper explicitement
import shlex
username = shlex.quote(username)
```

---

### 🟠 Important — CORS trop permissif

**Fichier :** `app.py:68-77`

```python
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Autorise toutes les origines !
    ...
)
```

**Problème :** `cors_allowed_origins="*"` permet à n'importe quel site d'établir une connexion WebSocket, exposant à des attaques CSRF via WebSocket.

**Solution :**
```python
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5000').split(',')
socketio = SocketIO(app, cors_allowed_origins=allowed_origins, ...)
```

---

### 🟠 Important — Absence de timeout sur subprocess

**Fichier :** `utils/osint_runner.py:130-135`

```python
process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
# Pas de timeout sur la boucle de lecture !
for line in iter(process.stdout.readline, ''):
```

**Problème :** Si Sherlock reste bloqué, le processus ne sera jamais terminé et consommera des ressources indéfiniment.

**Solution :**
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Process timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(timeout)  # Définir le timeout

try:
    for line in iter(process.stdout.readline, ''):
        # ...
finally:
    signal.alarm(0)  # Désactiver l'alarme
```

---

### 🟠 Important — Exception `bare except`

**Fichier :** `utils/osint_runner.py:450, 457`

```python
try:
    txt_records = results['records'].get('TXT', [])
    spf = [r for r in txt_records if 'v=spf1' in r]
    security['spf'] = spf[0] if spf else None
except:  # Capture TOUTES les exceptions !
    security['spf'] = None
```

**Problème :** Les `except:` sans type capturent même `KeyboardInterrupt` et `SystemExit`, masquant des erreurs critiques.

**Solution :**
```python
except (KeyError, IndexError, TypeError) as e:
    logger.debug(f"SPF lookup failed: {e}")
    security['spf'] = None
```

---

### 🟡 Mineur — Commentaire de debug laissé

**Fichier :** `utils/osint_runner.py:119`

```python
cmd = [
    "sherlock",
    username,
    #"--timeout", str(timeout),  # Code commenté en production
    "--json", output_file,
]
```

**Problème :** Le timeout Sherlock est désactivé, probablement pour debug. Cela peut causer des requêtes infinies.

**Solution :** Réactiver la ligne ou documenter pourquoi elle est désactivée.

---

### 🟡 Mineur — CSP avec `unsafe-inline`

**Fichier :** `utils/security.py:58-65`

```python
'Content-Security-Policy': (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "  # Vulnérable XSS
    "style-src 'self' 'unsafe-inline'; "
    ...
)
```

**Problème :** `unsafe-inline` affaiblit la protection CSP contre les attaques XSS.

**Solution :** Utiliser des nonces ou hashes pour les scripts inline :
```python
"script-src 'self' 'nonce-{random_nonce}';"
```

---

### 🟡 Mineur — Pas de gestion de version d'API

**Fichier :** `app.py`

**Problème :** Les routes API ne sont pas versionnées (`/api/tools` au lieu de `/api/v1/tools`), ce qui complique les évolutions futures.

**Solution :**
```python
@app.route('/api/v1/tools')
def get_tools_v1():
    # ...
```

---

## 5. Dette technique

### 5.1 Dépendances à risque

| Package | Version | Problème | Recommandation |
|---------|---------|----------|----------------|
| `gevent-websocket` | 0.10.1 | Non maintenu depuis 2017 | Migrer vers `python-socketio` natif |
| `dnspython` | 2.0.0 | Version ancienne fixée pour compatibilité ipwhois | Tester avec version récente |
| `holehe` | ≥1.61 | Dépend de services tiers instables | Prévoir fallback/cache |
| `sherlock-project` | ≥0.14.0 | CLI avec dépendances lourdes | Envisager alternative API |

### 5.2 Code obsolète/redondant

**Double définition de `login_required` :**
- `app.py:98-109` — Décorateur local
- `utils/security.py:38-48` — Méthode SecurityManager

**Solution :** Supprimer la duplication, utiliser uniquement la version dans `security.py`.

---

**Import inutilisé :**
```python
# utils/osint_runner.py
import ipaddress  # Utilisé
from ipwhois import ...  # NON UTILISÉ (supprimé pour ip-api.com)
```

Le package `ipwhois` est dans `requirements.txt` mais n'est plus utilisé.

---

**Gestion d'erreur inconsistante :**
```python
# Certaines fonctions retournent {'success': False, 'error': ...}
# D'autres lèvent des exceptions
# Standardiser le pattern
```

### 5.3 Mauvaises pratiques

**Stockage en mémoire des clients WebSocket :**
```python
authenticated_clients = {}  # Perdu au redémarrage !
```
Problème en cas de déploiement multi-instance. Solution : Redis ou base de données.

---

**Pas de logging structuré :**
```python
logger.info(f"✅ Login successful from {get_remote_address()}")  # Emoji dans logs
```
Utiliser un format structuré (JSON) pour faciliter l'analyse.

---

**Frontend monolithique :**
Tout le JavaScript est dans `index.html` (~500+ lignes). Difficile à maintenir et tester.

---

## 6. Recommandations

### Priorité 1 — Sécurité (Impact élevé, risque immédiat)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | Migrer vers bcrypt pour le hashage | 1h | 🔴 Critique |
| 2 | Supprimer `.env` du dépôt Git | 15min | 🔴 Critique |
| 3 | Forcer la définition de `APP_PASSWORD` | 30min | 🔴 Critique |
| 4 | Remplacer HTTP par HTTPS pour ip-api | 1h | 🔴 Critique |
| 5 | Restreindre CORS WebSocket | 30min | 🟠 Important |

### Priorité 2 — Stabilité (Impact moyen)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 6 | Ajouter timeout sur subprocess | 2h | 🟠 Important |
| 7 | Remplacer `except:` par exceptions typées | 1h | 🟠 Important |
| 8 | Réactiver `--timeout` Sherlock | 15min | 🟡 Mineur |
| 9 | Supprimer `ipwhois` de requirements | 5min | 🟡 Mineur |

### Priorité 3 — Maintenabilité (Impact faible, amélioration continue)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 10 | Extraire JS dans fichiers séparés | 4h | 🟡 Mineur |
| 11 | Versionner l'API (`/api/v1/`) | 2h | 🟡 Mineur |
| 12 | Standardiser format de réponse erreur | 2h | 🟡 Mineur |
| 13 | Ajouter tests unitaires | 8h+ | 🟠 Important |
| 14 | Documenter avec OpenAPI/Swagger | 4h | 🟡 Mineur |

---

## Annexe — Checklist de déploiement sécurisé

- [ ] `APP_PASSWORD` défini et complexe (12+ caractères)
- [ ] `SECRET_KEY` générée aléatoirement (32+ caractères)
- [ ] `FLASK_DEBUG=false` en production
- [ ] `.env` non versionné (dans `.gitignore`)
- [ ] HTTPS activé (via reverse proxy ou Render)
- [ ] `ALLOWED_ORIGINS` restreint aux domaines légitimes
- [ ] Rate limiting ajusté selon usage (`RATE_LIMIT_PER_MINUTE`)
- [ ] Logs configurés pour analyse (niveau INFO minimum)
- [ ] Sauvegardes configurées (si base de données ajoutée)

---

*Document généré automatiquement. Dernière mise à jour : 2026-01-18*
