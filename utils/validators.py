"""
Validateurs d'entrée pour les outils OSINT.
"""
import re
from email_validator import validate_email, EmailNotValidError

class InputValidator:
    """Valide et sanitize les entrées utilisateur."""
    
    # Patterns de validation
    PATTERNS = {
        'username': re.compile(r'^[a-zA-Z0-9_.-]{1,50}$'),
        'domain': re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ),
        'ip': re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ),
        'ipv6': re.compile(
            r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
            r'^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|'
            r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$'
        ),
        'url': re.compile(
            r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?$'
        ),
        'phone': re.compile(r'^[\d\s\-\+\(\)]{6,20}$')
    }
    
    @classmethod
    def sanitize_string(cls, value, max_length=200):
        """Nettoie une chaîne de caractères."""
        if not isinstance(value, str):
            return None
        # Supprimer les caractères de contrôle
        value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        # Limiter la longueur
        return value.strip()[:max_length]
    
    @classmethod
    def validate_username(cls, username):
        """Valide un nom d'utilisateur."""
        username = cls.sanitize_string(username, 50)
        if not username:
            return None, "Le nom d'utilisateur est requis"
        if not cls.PATTERNS['username'].match(username):
            return None, "Format invalide (lettres, chiffres, _.- uniquement)"
        return username, None
    
    @classmethod
    def validate_email(cls, email):
        """Valide une adresse email."""
        email = cls.sanitize_string(email, 254)
        if not email:
            return None, "L'adresse email est requise"
        try:
            result = validate_email(email, check_deliverability=False)
            return result.email, None
        except EmailNotValidError as e:
            return None, str(e)
    
    @classmethod
    def validate_domain(cls, domain):
        """Valide un nom de domaine."""
        domain = cls.sanitize_string(domain, 253)
        if not domain:
            return None, "Le domaine est requis"
        # Retirer le protocole si présent
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]  # Retirer le path
        domain = domain.lower()
        if not cls.PATTERNS['domain'].match(domain):
            return None, "Format de domaine invalide"
        return domain, None
    
    @classmethod
    def validate_ip(cls, ip):
        """Valide une adresse IP (v4 ou v6)."""
        ip = cls.sanitize_string(ip, 45)
        if not ip:
            return None, "L'adresse IP est requise"
        if cls.PATTERNS['ip'].match(ip):
            return ip, None
        if cls.PATTERNS['ipv6'].match(ip):
            return ip, None
        return None, "Format d'adresse IP invalide"
    
    @classmethod
    def validate_phone(cls, phone, default_region='FR'):
        """Valide un numéro de téléphone."""
        phone = cls.sanitize_string(phone, 20)
        if not phone:
            return None, "Le numéro de téléphone est requis"
        if not cls.PATTERNS['phone'].match(phone):
            return None, "Format de numéro invalide"
        return phone, None
    
    @classmethod
    def validate_url(cls, url):
        """Valide une URL."""
        url = cls.sanitize_string(url, 2000)
        if not url:
            return None, "L'URL est requise"
        # Ajouter le protocole si manquant
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        if not cls.PATTERNS['url'].match(url):
            return None, "Format d'URL invalide"
        return url, None
    
    @classmethod
    def validate_for_tool(cls, tool, value, **options):
        """
        Valide une entrée selon l'outil sélectionné.
        
        Returns:
            tuple: (validated_value, error_message)
        """
        validators = {
            'sherlock': cls.validate_username,
            'holehe': cls.validate_email,
            'email_validator': cls.validate_email,
            'whois': cls.validate_domain,
            'dns': cls.validate_domain,
            'phone': cls.validate_phone,
            'ip': cls.validate_ip,
            'wayback': cls.validate_url
        }
        
        validator = validators.get(tool)
        if not validator:
            return None, f"Outil inconnu: {tool}"
        
        return validator(value)