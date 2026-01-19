"""
Module: EXIF Analyzer
Description: Extraction de métadonnées EXIF depuis images (GPS, caméra, date)
RAM: ~5 Mo | Dépendances: exifread (pure Python, sans dépendances)

Formats supportés: JPEG, TIFF, PNG, WebP, HEIC, RAW
"""

import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import io
import base64

logger = logging.getLogger(__name__)


class ExifAnalyzer:
    """
    Analyseur de métadonnées EXIF pour images.
    
    Extrait les informations suivantes:
    - Données GPS (latitude, longitude, altitude)
    - Informations caméra (make, model, software)
    - Date/heure de prise de vue
    - Paramètres techniques (ISO, exposition, ouverture)
    """
    
    # Tags EXIF importants pour OSINT
    OSINT_TAGS = {
        'GPS': [
            'GPS GPSLatitude', 'GPS GPSLatitudeRef',
            'GPS GPSLongitude', 'GPS GPSLongitudeRef',
            'GPS GPSAltitude', 'GPS GPSAltitudeRef',
            'GPS GPSTimeStamp', 'GPS GPSDateStamp'
        ],
        'Camera': [
            'Image Make', 'Image Model', 'Image Software',
            'EXIF LensModel', 'EXIF LensMake'
        ],
        'DateTime': [
            'EXIF DateTimeOriginal', 'EXIF DateTimeDigitized',
            'Image DateTime'
        ],
        'Technical': [
            'EXIF ISOSpeedRatings', 'EXIF ExposureTime',
            'EXIF FNumber', 'EXIF FocalLength',
            'EXIF Flash', 'EXIF WhiteBalance'
        ]
    }
    
    def __init__(self):
        """Initialise l'analyseur avec lazy loading d'exifread."""
        self._exifread = None
    
    def _load_exifread(self):
        """Charge exifread à la demande (lazy loading pour économiser RAM)."""
        if self._exifread is None:
            try:
                import exifread
                self._exifread = exifread
                logger.debug("ExifRead chargé avec succès")
            except ImportError:
                raise ImportError(
                    "Le module 'exifread' est requis. "
                    "Installez-le avec: pip install exifread"
                )
        return self._exifread
    
    def analyze_file(self, file_path: str, extract_thumbnail: bool = False) -> Dict[str, Any]:
        """
        Analyse un fichier image et extrait ses métadonnées EXIF.
        
        Args:
            file_path: Chemin vers le fichier image
            extract_thumbnail: Extraire la miniature embarquée
            
        Returns:
            dict: Métadonnées structurées
        """
        exifread = self._load_exifread()
        
        try:
            with open(file_path, 'rb') as f:
                return self._process_file(f, extract_thumbnail)
        except FileNotFoundError:
            return {
                'success': False,
                'error': f"Fichier non trouvé: {file_path}"
            }
        except Exception as e:
            logger.error(f"Erreur analyse EXIF: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def analyze_bytes(self, image_data: bytes, extract_thumbnail: bool = False) -> Dict[str, Any]:
        """
        Analyse des données image en mémoire.
        
        Args:
            image_data: Données binaires de l'image
            extract_thumbnail: Extraire la miniature embarquée
            
        Returns:
            dict: Métadonnées structurées
        """
        self._load_exifread()
        
        try:
            f = io.BytesIO(image_data)
            return self._process_file(f, extract_thumbnail)
        except Exception as e:
            logger.error(f"Erreur analyse EXIF bytes: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _process_file(self, file_handle, extract_thumbnail: bool) -> Dict[str, Any]:
        """Traite un fichier et extrait les métadonnées."""
        exifread = self._exifread
        
        # Extraction des tags EXIF
        tags = exifread.process_file(
            file_handle,
            details=True,
            extract_thumbnail=extract_thumbnail
        )
        
        if not tags:
            return {
                'success': True,
                'has_exif': False,
                'message': "Aucune donnée EXIF trouvée"
            }
        
        result = {
            'success': True,
            'has_exif': True,
            'gps': self._extract_gps(tags),
            'camera': self._extract_camera(tags),
            'datetime': self._extract_datetime(tags),
            'technical': self._extract_technical(tags),
            'raw_tags_count': len(tags)
        }
        
        # Extraction miniature si demandée
        if extract_thumbnail and 'JPEGThumbnail' in tags:
            thumb_data = tags['JPEGThumbnail']
            result['thumbnail'] = {
                'available': True,
                'size_bytes': len(thumb_data),
                'base64': base64.b64encode(thumb_data).decode('utf-8')
            }
        
        # Calcul score OSINT (quantité d'infos utiles)
        result['osint_score'] = self._calculate_osint_score(result)
        
        return result
    
    def _extract_gps(self, tags: Dict) -> Optional[Dict[str, Any]]:
        """Extrait et convertit les coordonnées GPS."""
        lat = tags.get('GPS GPSLatitude')
        lat_ref = tags.get('GPS GPSLatitudeRef')
        lon = tags.get('GPS GPSLongitude')
        lon_ref = tags.get('GPS GPSLongitudeRef')
        
        if not all([lat, lon]):
            return None
        
        try:
            lat_decimal = self._gps_to_decimal(lat.values, str(lat_ref))
            lon_decimal = self._gps_to_decimal(lon.values, str(lon_ref))
            
            gps_data = {
                'latitude': lat_decimal,
                'longitude': lon_decimal,
                'latitude_raw': str(lat),
                'longitude_raw': str(lon),
                'google_maps_url': f"https://www.google.com/maps?q={lat_decimal},{lon_decimal}"
            }
            
            # Altitude si disponible
            alt = tags.get('GPS GPSAltitude')
            if alt:
                alt_ref = tags.get('GPS GPSAltitudeRef')
                altitude = float(alt.values[0])
                if alt_ref and str(alt_ref) == '1':
                    altitude = -altitude
                gps_data['altitude_meters'] = altitude
            
            # Timestamp GPS
            gps_time = tags.get('GPS GPSTimeStamp')
            gps_date = tags.get('GPS GPSDateStamp')
            if gps_time and gps_date:
                gps_data['gps_datetime'] = f"{gps_date} {gps_time}"
            
            return gps_data
            
        except (ValueError, TypeError, IndexError) as e:
            logger.warning(f"Erreur parsing GPS: {e}")
            return {
                'error': 'Données GPS invalides',
                'latitude_raw': str(lat),
                'longitude_raw': str(lon)
            }
    
    def _gps_to_decimal(self, coords, ref: str) -> float:
        """Convertit les coordonnées GPS en décimales."""
        degrees = float(coords[0])
        minutes = float(coords[1])
        seconds = float(coords[2])
        
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        
        if ref in ['S', 'W']:
            decimal = -decimal
        
        return round(decimal, 6)
    
    def _extract_camera(self, tags: Dict) -> Dict[str, Any]:
        """Extrait les informations sur l'appareil photo."""
        camera = {}
        
        make = tags.get('Image Make')
        if make:
            camera['make'] = str(make).strip()
        
        model = tags.get('Image Model')
        if model:
            camera['model'] = str(model).strip()
        
        software = tags.get('Image Software')
        if software:
            camera['software'] = str(software).strip()
        
        lens_model = tags.get('EXIF LensModel')
        if lens_model:
            camera['lens_model'] = str(lens_model).strip()
        
        return camera if camera else None
    
    def _extract_datetime(self, tags: Dict) -> Optional[Dict[str, Any]]:
        """Extrait les informations de date/heure."""
        datetime_info = {}
        
        # Date originale de prise de vue
        original = tags.get('EXIF DateTimeOriginal')
        if original:
            datetime_info['original'] = str(original)
            try:
                dt = datetime.strptime(str(original), '%Y:%m:%d %H:%M:%S')
                datetime_info['original_iso'] = dt.isoformat()
                datetime_info['original_timestamp'] = int(dt.timestamp())
            except ValueError:
                pass
        
        # Date de numérisation
        digitized = tags.get('EXIF DateTimeDigitized')
        if digitized and str(digitized) != str(original):
            datetime_info['digitized'] = str(digitized)
        
        # Date de modification
        modified = tags.get('Image DateTime')
        if modified and str(modified) != str(original):
            datetime_info['modified'] = str(modified)
        
        return datetime_info if datetime_info else None
    
    def _extract_technical(self, tags: Dict) -> Dict[str, Any]:
        """Extrait les paramètres techniques de la photo."""
        tech = {}
        
        iso = tags.get('EXIF ISOSpeedRatings')
        if iso:
            tech['iso'] = int(str(iso))
        
        exposure = tags.get('EXIF ExposureTime')
        if exposure:
            tech['exposure_time'] = str(exposure)
        
        aperture = tags.get('EXIF FNumber')
        if aperture:
            tech['aperture'] = f"f/{float(aperture.values[0])}"
        
        focal = tags.get('EXIF FocalLength')
        if focal:
            tech['focal_length_mm'] = float(focal.values[0])
        
        flash = tags.get('EXIF Flash')
        if flash:
            flash_val = int(str(flash).split()[0]) if ' ' in str(flash) else 0
            tech['flash_fired'] = bool(flash_val & 1)
        
        return tech if tech else None
    
    def _calculate_osint_score(self, result: Dict) -> int:
        """
        Calcule un score OSINT basé sur les données disponibles.
        
        Score max: 100
        - GPS avec coordonnées: +40
        - Infos caméra complètes: +20
        - Date/heure originale: +20
        - Données techniques: +10
        - Miniature disponible: +10
        """
        score = 0
        
        if result.get('gps') and result['gps'].get('latitude'):
            score += 40
        
        camera = result.get('camera')
        if camera:
            if camera.get('make') and camera.get('model'):
                score += 20
            elif camera.get('make') or camera.get('model'):
                score += 10
        
        if result.get('datetime') and result['datetime'].get('original'):
            score += 20
        
        if result.get('technical'):
            score += 10
        
        if result.get('thumbnail', {}).get('available'):
            score += 10
        
        return score


# Fonction utilitaire pour usage direct
def analyze_image(file_path: str, extract_thumbnail: bool = False) -> Dict[str, Any]:
    """
    Fonction raccourcie pour analyser une image.
    
    Args:
        file_path: Chemin vers l'image
        extract_thumbnail: Extraire la miniature
        
    Returns:
        dict: Métadonnées EXIF structurées
    """
    analyzer = ExifAnalyzer()
    return analyzer.analyze_file(file_path, extract_thumbnail)
