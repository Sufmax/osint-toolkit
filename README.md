# 🔍 OSINT Toolkit

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/Deploy-Render.com-purple.svg)](https://render.com)
[![Windows](https://img.shields.io/badge/Windows-Compatible-blue.svg)]()

**Plateforme web légère d'outils OSINT (Open Source Intelligence)** conçue pour fonctionner sur des environnements à ressources limitées comme le plan gratuit de Render.com.

> **Version 1.1** — Compatibilité Windows améliorée, corrections Sherlock/Maigret

![OSINT Toolkit Screenshot](https://via.placeholder.com/800x400/3b82f6/ffffff?text=OSINT+Toolkit)

---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Outils disponibles](#-outils-disponibles)
- [Prérequis](#-prérequis)
- [Installation locale](#-installation-locale)
- [Déploiement sur Render.com](#-déploiement-sur-rendercom)
- [Configuration](#%EF%B8%8F-configuration)
- [Utilisation](#-utilisation)
- [Sécurité](#-sécurité)
- [Architecture](#-architecture)
- [Dépannage](#-dépannage)
- [Contribution](#-contribution)
- [Licence](#-licence)
- [Avertissement légal](#%EF%B8%8F-avertissement-légal)

---

## ✨ Fonctionnalités

### Interface
- 🌐 **Interface bilingue** (Français / English)
- 🎨 **Design professionnel** light mode avec accents bleus
- 📱 **Responsive** — compatible mobile, tablette, desktop
- ⚡ **Résultats en temps réel** via WebSocket
- 📊 **Export des résultats** en JSON et CSV
- 📜 **Historique local** des 20 dernières recherches

### Sécurité
- 🔐 **Authentification par mot de passe** obligatoire
- 🛡️ **Rate limiting** — 10 requêtes/minute par défaut
- 🔒 **Headers de sécurité HTTP** (CSP, XSS, etc.)
- ✅ **Validation et sanitization** des entrées utilisateur

### Technique
- 🪶 **Ultra-léger** — fonctionne avec 512 Mo RAM
- 🚀 **Déploiement simple** sur Render.com (plan gratuit)
- 🔌 **WebSocket avec fallback** REST automatique
- 📦 **100% Python** — aucune dépendance système complexe
- 💻 **Compatible Windows/Linux/macOS** — gestion native des encodages

---

## 🛠 Outils disponibles

### Outils principaux

| Outil | Description | Entrée |
|-------|-------------|--------|
| 👤 **Recherche Username** | Recherche un pseudo sur 400+ réseaux sociaux (Sherlock) | Username |
| 📧 **Email → Comptes** | Vérifie si un email est enregistré sur 120+ services (Holehe) | Email |
| ✉️ **Validation Email** | Vérifie la syntaxe et l'existence du domaine | Email |
| 🌐 **WHOIS Domaine** | Récupère les informations d'enregistrement d'un domaine | Domaine |
| 🔗 **Lookup DNS** | Récupère les enregistrements DNS (A, MX, TXT, NS...) | Domaine |
| 📱 **Analyse Téléphone** | Valide et analyse un numéro (pays, opérateur, type) | Téléphone |
| 🖥️ **Lookup IP** | Récupère les informations WHOIS/ASN d'une adresse IP | IP |
| 📜 **Wayback Machine** | Recherche les archives historiques d'une URL | URL |

### Nouveaux outils légers (v1.1)

|| Outil | Description | Entrée | RAM |
||-------|-------------|--------|-----|
|| 🖼️ **EXIF Analyzer** | Extraction métadonnées images (GPS, caméra, date) | Image/URL | ~5 Mo |
|| 🔍 **Subdomain Finder** | Découverte sous-domaines via CT logs | Domaine | ~2 Mo |
|| 🔐 **SSL Analyzer** | Analyse certificats SSL/TLS | Hostname | ~2 Mo |
|| 🔬 **Hash Lookup** | Vérification hashes vs threat intel (MalwareBazaar, VT) | MD5/SHA | ~2 Mo |
|| 📡 **MAC Lookup** | Identification fabricant via adresse MAC | MAC | ~1 Mo |
|| 👥 **Social Analyzer** | Recherche profils (Gravatar, GitHub, GitLab) | Email/Username | ~3 Mo |
|| 🕵️ **Maigret** | Recherche avancée sur 3000+ sites (modes fast/normal/full) | Username | ~50 Mo |

> 💡 **Note** : Maigret propose 3 modes de recherche :
> - **fast** : Top 50 sites (rapide, ~10s)
> - **normal** : 500 sites (moyen, ~1min)
> - **full** : 3000+ sites (complet, ~5min)

> 📖 Voir [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) pour la documentation complète des nouveaux outils.

---

## 📌 Prérequis

- **Python 3.10+** (3.11 recommandé)
- **pip** (gestionnaire de paquets Python)
- **Git** (pour le déploiement)
- Compte [Render.com](https://render.com) (gratuit) pour le déploiement en ligne

### Compatibilité OS

| OS | Status | Notes |
|----|--------|-------|
| 💻 **Windows 10/11** | ✅ Compatible | Encodage UTF-8 géré automatiquement |
| 🐧 **Linux** | ✅ Compatible | Recommandé pour production |
| 🍎 **macOS** | ✅ Compatible | Intel et Apple Silicon |

---

## 💻 Installation locale

### 1. Cloner le repository

```bash
git clone https://github.com/VOTRE_USER/osint-toolkit.git
cd osint-toolkit
```

### 2. Créer l'environnement virtuel

```bash
# Linux / macOS
python3.11 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configurer les variables d'environnement

```bash
# Copier le fichier exemple
cp .env.example .env

# Éditer le fichier .env
nano .env  # ou votre éditeur préféré
```

Contenu de `.env` :
```env
APP_PASSWORD=VotreMotDePasseSecurise123!
SECRET_KEY=une-cle-secrete-aleatoire-longue
FLASK_DEBUG=true
RATE_LIMIT_PER_MINUTE=10
```

### 5. Lancer l'application

```bash
python app.py
```

L'application sera accessible sur : **http://localhost:5000**

---

## 🚀 Déploiement sur Render.com

### Étape 1 : Préparer le repository

```bash
# S'assurer que tous les fichiers sont commités
git add .
git commit -m "Ready for deployment"
git push origin main
```

### Étape 2 : Créer le service sur Render

1. Connectez-vous à [render.com](https://render.com)
2. Cliquez sur **New** → **Web Service**
3. Connectez votre repository GitHub/GitLab
4. Configurez le service :

| Paramètre | Valeur |
|-----------|--------|
| **Name** | `osint-toolkit` |
| **Region** | `Frankfurt (EU)` ou `Oregon (US)` |
| **Branch** | `main` |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 --bind 0.0.0.0:$PORT app:app` |
| **Instance Type** | `Free` |

### Étape 3 : Variables d'environnement

Dans l'onglet **Environment**, ajoutez :

| Variable | Valeur |
|----------|--------|
| `APP_PASSWORD` | `VotreMotDePasseSecurise!` |
| `SECRET_KEY` | *(cliquez sur "Generate")* |
| `PYTHON_VERSION` | `3.11.0` |

### Étape 4 : Déployer

Cliquez sur **Create Web Service**. Le déploiement prend environ 3-5 minutes.

Votre application sera accessible sur : `https://osint-toolkit.onrender.com`

> ⚠️ **Important** : Le plan gratuit met le service en veille après 15 minutes d'inactivité. Le premier accès après une période d'inactivité peut prendre 30-60 secondes.

---

## ⚙️ Configuration

### Variables d'environnement

| Variable | Description | Défaut | Requis |
|----------|-------------|--------|--------|
| `APP_PASSWORD` | Mot de passe d'accès à l'interface | `Mon#mdp3` | ✅ Oui |
| `SECRET_KEY` | Clé secrète Flask (sessions, CSRF) | Générée | ✅ Oui |
| `FLASK_DEBUG` | Mode debug (désactiver en prod) | `false` | Non |
| `RATE_LIMIT_PER_MINUTE` | Nombre max de requêtes/minute | `10` | Non |
| `PORT` | Port d'écoute | `5000` | Non |

### Changer le mot de passe

#### En local
Éditez le fichier `.env` :
```env
APP_PASSWORD=NouveauMotDePasse!
```

#### Sur Render.com
1. Dashboard → Votre service → **Environment**
2. Modifiez la variable `APP_PASSWORD`
3. Cliquez **Save Changes**
4. Le service redémarre automatiquement

---

## 📖 Utilisation

### 1. Connexion

Accédez à l'URL de votre instance et entrez le mot de passe configuré.

### 2. Sélectionner un outil

Cliquez sur l'une des cartes d'outil dans la grille principale.

### 3. Effectuer une recherche

1. Entrez la valeur à rechercher (username, email, domaine, etc.)
2. *(Optionnel)* Ouvrez les **Paramètres avancés** pour personnaliser
3. Cliquez sur **Rechercher**

### 4. Consulter les résultats

Les résultats s'affichent en temps réel dans un tableau structuré.

### 5. Exporter

Utilisez les boutons **JSON** ou **CSV** pour télécharger les résultats.

### Options avancées par outil

| Outil | Options |
|-------|---------|
| **Username** | Mode rapide (20 sites) ou complet (400+ sites) |
| **Email Validation** | Vérification DNS/MX activable |
| **DNS Lookup** | Sélection des types d'enregistrements |
| **Téléphone** | Pays par défaut (FR, US, GB, etc.) |
| **Wayback** | Nombre de snapshots à récupérer |

---

## 🔒 Sécurité

### Mesures implémentées

| Mesure | Description |
|--------|-------------|
| **Authentification** | Mot de passe requis dès la première connexion |
| **Rate Limiting** | 10 requêtes/minute (configurable) |
| **CSRF Protection** | Token CSRF sur les formulaires |
| **Input Validation** | Validation et sanitization de toutes les entrées |
| **Security Headers** | CSP, X-Frame-Options, X-XSS-Protection, etc. |
| **Session Secure** | Cookies sécurisés avec expiration |

### Bonnes pratiques

1. **Changez le mot de passe par défaut** immédiatement après le déploiement
2. **Utilisez un mot de passe fort** (12+ caractères, mixte)
3. **Générez une SECRET_KEY unique** pour chaque instance
4. **Désactivez FLASK_DEBUG** en production
5. **Surveillez les logs** pour détecter les abus

### Headers de sécurité HTTP

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; ...
```

---

## 🏗 Architecture

```
osint-toolkit/
├── app.py                  # Application Flask principale
├── requirements.txt        # Dépendances Python
├── Procfile               # Configuration Render/Gunicorn
├── render.yaml            # Déploiement automatisé Render
├── .env.example           # Template variables d'environnement
├── .gitignore             # Fichiers ignorés par Git
├── README.md              # Documentation
├── TOOLS_REFERENCE.md     # Référence des nouveaux outils
├── LICENSE                # Licence MIT
│
├── templates/
│   └── index.html         # Interface SPA (HTML + CSS + JS)
│
├── static/                # Fichiers statiques (si séparés)
│   ├── style.css
│   └── app.js
│
├── tools/                 # Nouveaux outils OSINT légers
│   ├── __init__.py        # Export des modules
│   ├── exif_analyzer.py   # Extraction métadonnées EXIF
│   ├── subdomain_finder.py # Découverte sous-domaines
│   ├── ssl_analyzer.py    # Analyse certificats SSL
│   ├── hash_lookup.py     # Threat intelligence hashes
│   ├── mac_lookup.py      # Identification fabricant MAC
│   └── social_analyzer.py # Profils sociaux
│
└── utils/
    ├── __init__.py        # Export des modules
    ├── security.py        # Authentification et sécurité
    ├── validators.py      # Validation des entrées
    └── osint_runner.py    # Wrapper des outils OSINT
```

### Stack technique

|| Couche | Technologie |
||--------|-------------|
|| **Backend** | Python 3.10+, Flask 3.0 |
|| **WebSocket** | Flask-SocketIO, Gevent |
|| **Frontend** | HTML5, CSS3, JavaScript vanilla |
|| **Sécurité** | Flask-WTF, Flask-Limiter |
|| **OSINT** | Sherlock, Maigret, Holehe, dnspython, phonenumbers, etc. |

### Flux de données

```
┌─────────┐     ┌─────────┐     ┌──────────┐
│ Client  │────▶│  Flask  │────▶│  OSINT   │
│ Browser │◀────│  Server │◀────│  Tools   │
└─────────┘     └─────────┘     └──────────┘
     │               │
     │  WebSocket    │  Rate Limit
     │  (temps réel) │  Validation
     ▼               ▼
┌─────────┐     ┌─────────┐
│ LocalSt │     │ Session │
│ (hist.) │     │ (auth)  │
└─────────┘     └─────────┘
```

---

## 🔧 Dépannage

### Problèmes courants

#### ❌ Erreur d'installation des dépendances

```bash
ERROR: Cannot install ... conflicting dependencies
```

**Solution** : Utilisez la version corrigée de `requirements.txt` avec `dnspython==2.0.0`

```bash
rm -rf venv
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### ❌ Le build échoue sur Render

**Solution** : Ajoutez `PYTHON_VERSION=3.11.0` dans les variables d'environnement

#### ❌ WebSocket ne fonctionne pas

**Symptôme** : Les résultats n'apparaissent pas en temps réel

**Solutions** :
1. Vérifiez que le Start Command utilise `geventwebsocket`
2. Le fallback REST API devrait fonctionner automatiquement
3. Vérifiez les logs Render pour les erreurs

#### ❌ Timeout sur les recherches

**Symptôme** : La recherche ne termine jamais

**Solutions** :
1. Activez le **Mode rapide** pour Sherlock (20 sites au lieu de 400)
2. Réduisez le nombre de snapshots pour Wayback
3. Vérifiez votre connexion internet

#### ❌ Erreur 429 (Rate Limit)

**Symptôme** : "Trop de requêtes"

**Solution** : Attendez 1 minute ou augmentez `RATE_LIMIT_PER_MINUTE`

#### ❌ Erreur 401 (Non authentifié)

**Solutions** :
1. Vérifiez le mot de passe
2. Effacez les cookies du navigateur
3. Vérifiez que `APP_PASSWORD` est bien défini

#### ❌ Sherlock/Holehe/Maigret non trouvé

```bash
FileNotFoundError: sherlock not found
```

**Solution** : Vérifiez que l'installation est complète

```bash
pip install sherlock-project holehe maigret
sherlock --version
holehe --help
maigret --version
```

#### ❌ Aucun profil trouvé (Sherlock/Maigret)

**Symptôme** : La recherche termine mais affiche "Aucun profil trouvé"

**Solutions** :
1. Vérifiez que le username existe sur au moins un réseau social
2. Essayez en mode **full** pour Maigret (plus de sites)
3. Vérifiez les logs pour des erreurs de connexion
4. Certains sites peuvent être temporairement inaccessibles

#### ❌ Erreurs d'affichage sur Windows (Maigret)

**Symptôme** : Erreurs liées à `colorama` ou `alive_progress`

**Solution** : Déjà corrigé dans v1.1 avec les options `--no-progressbar --no-color`

### Logs de débogage

#### En local

```bash
# Activer le mode debug
export FLASK_DEBUG=true
python app.py
```

#### Sur Render

Dashboard → Votre service → **Logs**

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment participer :

### 1. Fork le repository

```bash
git clone https://github.com/VOTRE_USER/osint-toolkit.git
cd osint-toolkit
```

### 2. Créer une branche

```bash
git checkout -b feature/ma-nouvelle-fonctionnalite
```

### 3. Faire vos modifications

```bash
# Éditer les fichiers
# Tester localement
python app.py
```

### 4. Commiter et pusher

```bash
git add .
git commit -m "feat: description de la fonctionnalité"
git push origin feature/ma-nouvelle-fonctionnalite
```

### 5. Ouvrir une Pull Request

Sur GitHub, cliquez sur **Compare & Pull Request**

### Conventions de commit

```
feat: nouvelle fonctionnalité
fix: correction de bug
docs: documentation
style: formatage (pas de changement de code)
refactor: refactorisation
test: ajout de tests
chore: maintenance
```

### Idées de contribution

- [ ] Ajouter de nouveaux outils OSINT
- [ ] Améliorer l'interface utilisateur
- [ ] Ajouter des traductions (ES, DE, IT...)
- [ ] Écrire des tests unitaires
- [ ] Optimiser les performances
- [ ] Améliorer la documentation

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

```
MIT License

Copyright (c) 2024 OSINT Toolkit

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Avertissement légal

### Utilisation responsable

Cet outil est fourni **à des fins éducatives et de recherche légitime uniquement**.

L'OSINT (Open Source Intelligence) consiste à collecter des informations disponibles publiquement. Cependant, l'utilisation de ces outils doit respecter :

- ✅ Les lois locales et internationales
- ✅ Les conditions d'utilisation des services interrogés
- ✅ Le respect de la vie privée des personnes
- ✅ Le RGPD et autres réglementations sur les données personnelles

### Ce qui est interdit

- ❌ Harcèlement ou stalking
- ❌ Usurpation d'identité
- ❌ Accès non autorisé à des systèmes
- ❌ Collecte massive de données personnelles
- ❌ Toute activité illégale

### Responsabilité

Les auteurs de cet outil **déclinent toute responsabilité** quant à l'utilisation qui en est faite. L'utilisateur est seul responsable de s'assurer que son utilisation est conforme aux lois en vigueur dans sa juridiction.

---

## 🙏 Remerciements

Ce projet utilise les outils open source suivants :

- [Sherlock](https://github.com/sherlock-project/sherlock) — Recherche de usernames (400+ sites)
- [Maigret](https://github.com/soxoj/maigret) — Recherche avancée de usernames (3000+ sites)
- [Holehe](https://github.com/megadose/holehe) — Email to accounts
- [email-validator](https://github.com/JoshData/python-email-validator) — Validation d'email
- [python-whois](https://github.com/richardpenman/whois) — WHOIS lookup
- [dnspython](https://www.dnspython.org/) — DNS toolkit
- [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) — Phone parsing
- [waybackpy](https://github.com/akamhy/waybackpy) — Wayback Machine API
- [ipinfo.io](https://ipinfo.io/) — IP Geolocation API (HTTPS)

---

## 📞 Contact

- **Issues** : [GitHub Issues](https://github.com/Sufmax/osint-toolkit/issues)
- **Discussions** : [GitHub Discussions](https://github.com/Sufmax/osint-toolkit/discussions)

---

<p align="center">
  Fait avec ❤️ pour la communauté OSINT
</p>

<p align="center">
  <a href="#-osint-toolkit">⬆️ Retour en haut</a>
</p>
