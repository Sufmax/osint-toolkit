# 🔧 OSINT Toolkit - Référence des Outils

Ce document détaille les 6 nouveaux outils OSINT légers ajoutés au toolkit.

---

## 📊 Vue d'ensemble

| Outil | RAM | Dépendances | API Key |
|-------|-----|-------------|---------|
| EXIF Analyzer | ~5 Mo | exifread | ❌ Non |
| Subdomain Finder | ~2 Mo | requests | ❌ Non |
| SSL Analyzer | ~2 Mo | ssl (builtin) | ❌ Non |
| Hash Lookup | ~2 Mo | requests | ⚪ Optionnel (VirusTotal) |
| MAC Lookup | ~1 Mo | requests | ❌ Non |
| Social Analyzer | ~3 Mo | requests | ❌ Non |
| Maigret | ~50 Mo | maigret | ❌ Non |

**Total RAM estimée** : ~65 Mo (chargement paresseux)

---

## 🖼️ EXIF Analyzer

### Description
Extrait les métadonnées EXIF des images (JPEG, TIFF) pour révéler des informations cachées : coordonnées GPS, modèle de caméra, date de prise de vue, logiciel utilisé.

### Usage

```python
from tools import ExifAnalyzer

analyzer = ExifAnalyzer()

# Depuis un fichier local
result = analyzer.analyze("photo.jpg")

# Depuis une URL
result = analyzer.analyze_url("https://example.com/image.jpg")
```

### Sortie

```json
{
  "success": true,
  "file": "photo.jpg",
  "has_exif": true,
  "gps": {
    "latitude": 48.8584,
    "longitude": 2.2945,
    "altitude": 35.0,
    "google_maps_url": "https://www.google.com/maps?q=48.8584,2.2945"
  },
  "camera": {
    "make": "Apple",
    "model": "iPhone 15 Pro",
    "software": "iOS 17.2"
  },
  "datetime": {
    "original": "2024:01:15 14:30:00",
    "digitized": "2024:01:15 14:30:00"
  },
  "osint_score": 85,
  "osint_notes": ["GPS coordinates found - high value for geolocation"]
}
```

### Cas d'usage OSINT
- Géolocalisation de photos
- Identification du matériel photographique
- Vérification de l'authenticité d'une image
- Analyse de la timeline d'événements

---

## 🔍 Subdomain Finder

### Description
Découvre les sous-domaines d'un domaine via plusieurs sources : Certificate Transparency logs (crt.sh), HackerTarget, ThreatCrowd. Utilise le parallélisme pour des résultats rapides.

### Usage

```python
from tools import SubdomainFinder

finder = SubdomainFinder()
result = finder.find("example.com")
```

### Sortie

```json
{
  "success": true,
  "domain": "example.com",
  "subdomains": [
    {"subdomain": "www.example.com", "sources": ["crt.sh", "hackertarget"]},
    {"subdomain": "api.example.com", "sources": ["crt.sh"]},
    {"subdomain": "mail.example.com", "sources": ["threatcrowd"]}
  ],
  "count": 3,
  "sources_used": ["crt.sh", "hackertarget", "threatcrowd"]
}
```

### APIs utilisées
- **crt.sh** : Certificate Transparency logs (gratuit, illimité)
- **HackerTarget** : Subdomain finder (gratuit, 100 req/jour)
- **ThreatCrowd** : Threat intelligence (gratuit)

---

## 🔐 SSL Analyzer

### Description
Analyse les certificats SSL/TLS d'un serveur pour évaluer la sécurité : validité, chaîne de certificats, algorithmes, vulnérabilités potentielles.

### Usage

```python
from tools import SSLAnalyzer

analyzer = SSLAnalyzer()
result = analyzer.analyze("example.com", port=443)
```

### Sortie

```json
{
  "success": true,
  "hostname": "example.com",
  "port": 443,
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "CN=R3, O=Let's Encrypt",
    "serial_number": "04:AB:CD:...",
    "not_before": "2024-01-01T00:00:00",
    "not_after": "2024-04-01T00:00:00",
    "days_until_expiry": 45,
    "is_expired": false,
    "san": ["example.com", "www.example.com"]
  },
  "security": {
    "score": 85,
    "grade": "A",
    "issues": [],
    "tls_version": "TLSv1.3"
  }
}
```

### Vérifications de sécurité
- Expiration du certificat
- Correspondance du hostname
- Algorithme de signature (SHA-256 minimum)
- Longueur de clé RSA (2048+ bits)
- Version TLS supportée

---

## 🔬 Hash Lookup

### Description
Recherche un hash de fichier (MD5, SHA1, SHA256) dans les bases de threat intelligence pour identifier les malwares connus.

### Usage

```python
from tools import HashLookup

lookup = HashLookup()

# Recherche basique (MalwareBazaar uniquement)
result = lookup.lookup("44d88612fea8a8f36de82e1278abb02f")

# Avec VirusTotal (nécessite API key)
lookup = HashLookup(vt_api_key="your_api_key")
result = lookup.lookup("44d88612fea8a8f36de82e1278abb02f")

# Calculer le hash d'un fichier
hashes = lookup.hash_file("suspicious_file.exe")
```

### Sortie

```json
{
  "success": true,
  "hash": "44d88612fea8a8f36de82e1278abb02f",
  "hash_type": "md5",
  "is_malicious": true,
  "threat_score": 80,
  "sources": {
    "malwarebazaar": {
      "found": true,
      "malware_family": "Emotet",
      "tags": ["exe", "trojan", "banker"],
      "first_seen": "2023-01-15"
    }
  },
  "detections": [
    {
      "source": "MalwareBazaar",
      "malware_family": "Emotet",
      "tags": ["exe", "trojan", "banker"]
    }
  ]
}
```

### APIs utilisées
- **MalwareBazaar** : Base de samples malveillants (gratuit, sans clé)
- **VirusTotal** : Multi-scanner antivirus (optionnel, clé gratuite disponible)

### Configuration VirusTotal

```env
# Dans .env
VT_API_KEY=your_virustotal_api_key
```

---

## 📡 MAC Lookup

### Description
Identifie le fabricant d'un appareil réseau à partir de son adresse MAC via l'OUI (Organizationally Unique Identifier).

### Usage

```python
from tools import MACLookup

lookup = MACLookup()

# Formats supportés
result = lookup.lookup("AA:BB:CC:DD:EE:FF")
result = lookup.lookup("AA-BB-CC-DD-EE-FF")
result = lookup.lookup("AABB.CCDD.EEFF")
result = lookup.lookup("AABBCCDDEEFF")

# Lookup batch
results = lookup.lookup_batch([
    "00:1A:2B:3C:4D:5E",
    "B8:27:EB:12:34:56"
])
```

### Sortie

```json
{
  "success": true,
  "mac_address": "B8:27:EB:12:34:56",
  "mac_normalized": "b827eb123456",
  "oui": "B827EB",
  "vendor": "Raspberry Pi Foundation",
  "oui_analysis": {
    "oui": "B8:27:EB",
    "is_multicast": false,
    "is_local": false,
    "address_type": "Universally Administered (UAA)",
    "note": "Adresse fabricant standard"
  }
}
```

### Analyse OUI
- **UAA** : Adresse attribuée par le fabricant
- **LAA** : Adresse locale/virtuelle (possiblement modifiée)
- **Multicast** : Adresse de groupe

### APIs utilisées
- **macvendors.com** : Lookup gratuit (2 req/sec)
- **maclookup.app** : Fallback avec infos détaillées

---

## 👤 Social Analyzer

### Description
Recherche des profils sociaux associés à un email ou username via APIs publiques : Gravatar, GitHub, GitLab.

### Usage

```python
from tools import SocialAnalyzer

analyzer = SocialAnalyzer()

# Analyse automatique (détecte email ou username)
result = analyzer.full_analysis("john.doe@example.com")
result = analyzer.full_analysis("johndoe")

# Analyse spécifique
result = analyzer.analyze_email("john.doe@example.com")
result = analyzer.analyze_username("johndoe", platforms=["github", "gitlab"])
```

### Sortie (email)

```json
{
  "success": true,
  "identifier": "john.doe@example.com",
  "type": "email",
  "found_count": 2,
  "profiles": {
    "gravatar": {
      "found": true,
      "has_profile": true,
      "display_name": "John Doe",
      "location": "Paris, France",
      "avatar_url": "https://www.gravatar.com/avatar/...",
      "accounts": [
        {"name": "twitter", "url": "https://twitter.com/johndoe"}
      ]
    },
    "github": {
      "found": true,
      "username": "johndoe",
      "name": "John Doe",
      "company": "ACME Corp",
      "location": "Paris",
      "public_repos": 42,
      "followers": 150
    }
  },
  "osint_summary": {
    "platforms_found": ["gravatar", "github"],
    "potential_real_name": "John Doe",
    "potential_location": "Paris, France",
    "potential_company": "ACME Corp",
    "linked_accounts": [{"name": "twitter", "url": "..."}],
    "activity_score": 75
  }
}
```

### Plateformes supportées
- **Gravatar** : Profil global + comptes liés
- **GitHub** : Profil développeur (repos, followers, etc.)
- **GitLab** : Profil développeur

### Rate Limits
- GitHub : 60 req/heure (sans auth)
- GitLab : 60 req/heure
- Gravatar : Illimité

---

## 🔌 Intégration via OSINTRunner

Tous les outils sont accessibles via le dispatcher central :

```python
from utils.osint_runner import OSINTRunner

runner = OSINTRunner()

# Lister tous les outils
tools = runner.get_available_tools()

# Exécuter un outil
result = runner.run("exif", "/path/to/image.jpg")
result = runner.run("subdomains", "example.com")
result = runner.run("ssl", "example.com", port=443)
result = runner.run("hash", "44d88612fea8a8f36de82e1278abb02f")
result = runner.run("mac", "AA:BB:CC:DD:EE:FF")
result = runner.run("social", "john@example.com")
```

---

## ⚙️ Configuration

### Variables d'environnement optionnelles

```env
# VirusTotal API Key (pour Hash Lookup avancé)
VT_API_KEY=your_virustotal_api_key
```

### Timeouts par défaut

| Outil | Timeout |
|-------|---------|
| EXIF Analyzer | 30s (download) |
| Subdomain Finder | 15s par source |
| SSL Analyzer | 10s |
| Hash Lookup | 15s |
| MAC Lookup | 10s |
| Social Analyzer | 15s |

---

## 🚀 Performance

### Optimisations
- **Chargement paresseux** : Les modules ne sont importés qu'à l'utilisation
- **Sessions réutilisées** : Connection pooling HTTP
- **Parallélisme** : ThreadPoolExecutor pour les requêtes multiples
- **Timeout agressifs** : Évite les blocages

### Empreinte mémoire
- Au repos : ~15 Mo pour tous les modules
- En exécution : +5-10 Mo par outil actif
- Compatible avec les contraintes Render.com (512 Mo)

---

## 📝 Notes légales

Ces outils interrogent des APIs publiques et des informations accessibles librement. Leur utilisation doit respecter :

- Les conditions d'utilisation des APIs
- Les lois sur la protection des données (RGPD)
- Le droit à la vie privée

**Usage responsable uniquement.**

---

## 🕵️ Maigret

### Description
Maigret est un fork avancé de Sherlock qui recherche des comptes d'utilisateurs sur plus de 3000 sites. Il offre des fonctionnalités supplémentaires comme le parsing de profils, la recherche par tags et le support des sites Tor/I2P.

### Usage

```python
from tools import MaigretRunner

runner = MaigretRunner(timeout=120)

# Recherche rapide (50 top sites)
result = runner.search("johndoe", mode="fast")

# Recherche normale (500 sites)
result = runner.search("johndoe", mode="normal")

# Recherche complète (3000+ sites)
result = runner.search("johndoe", mode="full")

# Recherche avec tags (filtrage par catégorie/pays)
result = runner.search("johndoe", tags=["photo", "fr"])
```

### Sortie

```json
{
  "success": true,
  "username": "johndoe",
  "mode": "fast",
  "found": [
    {
      "site": "Instagram",
      "url": "https://instagram.com/johndoe",
      "status": "Claimed",
      "tags": ["photo", "social"]
    },
    {
      "site": "Twitter",
      "url": "https://twitter.com/johndoe",
      "status": "Claimed",
      "tags": ["social"]
    }
  ],
  "count": 2,
  "duration_seconds": 15.4,
  "sites_checked": 50
}
```

### Modes de recherche

| Mode | Sites | Durée approximative | Usage |
|------|-------|---------------------|-------|
| `fast` | ~50 | 15-30s | Tests rapides |
| `normal` | ~500 | 1-2min | Recherche standard |
| `full` | 3000+ | 5-10min | Recherche exhaustive |

### Tags disponibles

**Catégories** : `social`, `photo`, `video`, `music`, `coding`, `tech`, `gaming`, `dating`, `forum`, `blog`, `shopping`

**Pays** : `us`, `ru`, `cn`, `de`, `fr`, `uk`, `br`

### Différences avec Sherlock

| Fonctionnalité | Sherlock | Maigret |
|----------------|----------|---------|
| Sites supportés | ~400 | 3000+ |
| Parsing de profils | ❌ | ✅ |
| Recherche par tags | ❌ | ✅ |
| Support Tor/I2P | ❌ | ✅ |
| Rapports HTML/PDF | ❌ | ✅ |
| Recherche récursive | ❌ | ✅ |
