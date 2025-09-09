#!/usr/bin/env python3
"""
EXIF Metadata Extraction Module for Elbanna Recon v1.0

This module provides comprehensive EXIF metadata extraction and analysis from image files.
Features:
- Support for multiple image formats (JPEG, TIFF, RAW, etc.)
- GPS coordinates extraction and conversion
- Camera and shooting parameter analysis
- Date/time information extraction
- Image quality and technical metadata
- Security-focused metadata analysis

Author: Yousef Osama
"""

import os
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import re

# Try to import required libraries
EXIFREAD_AVAILABLE = False
PILLOW_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    pass

try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    pass


class ExifAnalyzer:
    """
    EXIF metadata extraction and analysis engine.
    """
    
    # Supported image file extensions
    SUPPORTED_EXTENSIONS = {
        '.jpg', '.jpeg', '.jpe', '.jfif',  # JPEG formats
        '.tif', '.tiff',                   # TIFF formats
        '.dng', '.cr2', '.nef', '.arw',    # RAW formats
        '.orf', '.rw2', '.pef', '.srw',    # More RAW formats
        '.png',                            # PNG (limited EXIF)
        '.webp'                            # WebP (limited EXIF)
    }
    
    # Critical EXIF tags for security analysis
    PRIVACY_TAGS = {
        'GPS GPSLatitude', 'GPS GPSLongitude', 'GPS GPSAltitude',
        'GPS GPSTimeStamp', 'GPS GPSDateStamp', 'GPS GPSMapDatum',
        'Image Software', 'Image Artist', 'Image Copyright',
        'Image XPAuthor', 'Image XPComment', 'Image XPKeywords',
        'EXIF UserComment', 'EXIF CameraOwnerName'
    }
    
    def __init__(self):
        """Initialize the EXIF analyzer."""
        self.preferred_library = None
        
        # Determine the best available library
        if PILLOW_AVAILABLE:
            self.preferred_library = 'pillow'
        elif EXIFREAD_AVAILABLE:
            self.preferred_library = 'exifread'
    
    def is_supported_format(self, file_path: str) -> bool:
        """
        Check if the file format is supported for EXIF extraction.
        
        Args:
            file_path: Path to the image file
            
        Returns:
            True if format is supported, False otherwise
        """
        if not os.path.exists(file_path):
            return False
        
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in self.SUPPORTED_EXTENSIONS
    
    def dms_to_decimal(self, dms_tuple: Tuple, hemisphere: str) -> float:
        """
        Convert DMS (Degrees, Minutes, Seconds) to decimal degrees.
        
        Args:
            dms_tuple: Tuple of (degrees, minutes, seconds)
            hemisphere: 'N', 'S', 'E', or 'W'
            
        Returns:
            Decimal degrees as float
        """
        try:
            if len(dms_tuple) != 3:
                return 0.0
            
            degrees = float(dms_tuple[0])
            minutes = float(dms_tuple[1])
            seconds = float(dms_tuple[2])
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            
            # Apply hemisphere
            if hemisphere.upper() in ['S', 'W']:
                decimal = -decimal
            
            return decimal
            
        except (ValueError, ZeroDivisionError, TypeError):
            return 0.0
    
    def extract_gps_pillow(self, exif_data: dict) -> Dict[str, Any]:
        """
        Extract GPS information using Pillow.
        
        Args:
            exif_data: EXIF data from Pillow
            
        Returns:
            GPS information dictionary
        """
        gps_info = {
            'has_gps': False,
            'latitude': None,
            'longitude': None,
            'altitude': None,
            'timestamp': None,
            'raw_gps_data': {}
        }
        
        # Get GPS IFD
        gps_ifd = exif_data.get('GPSInfo', {})
        if not gps_ifd:
            return gps_info
        
        gps_info['has_gps'] = True
        
        # Store raw GPS data
        for key, value in gps_ifd.items():
            tag_name = GPSTAGS.get(key, key)
            gps_info['raw_gps_data'][tag_name] = str(value)
        
        try:
            # Extract latitude
            if 1 in gps_ifd and 2 in gps_ifd:  # GPSLatitude and GPSLatitudeRef
                lat_dms = gps_ifd[1]
                lat_ref = gps_ifd[2]
                gps_info['latitude'] = self.dms_to_decimal(lat_dms, lat_ref)
            
            # Extract longitude
            if 3 in gps_ifd and 4 in gps_ifd:  # GPSLongitude and GPSLongitudeRef
                lon_dms = gps_ifd[3]
                lon_ref = gps_ifd[4]
                gps_info['longitude'] = self.dms_to_decimal(lon_dms, lon_ref)
            
            # Extract altitude
            if 6 in gps_ifd:  # GPSAltitude
                altitude_rational = gps_ifd[6]
                if hasattr(altitude_rational, 'numerator') and hasattr(altitude_rational, 'denominator'):
                    gps_info['altitude'] = float(altitude_rational.numerator) / float(altitude_rational.denominator)
                else:
                    gps_info['altitude'] = float(altitude_rational)
            
            # Extract timestamp
            if 7 in gps_ifd and 29 in gps_ifd:  # GPSTimeStamp and GPSDateStamp
                time_stamp = gps_ifd[7]
                date_stamp = gps_ifd[29]
                
                if len(time_stamp) >= 3:
                    hours = int(time_stamp[0])
                    minutes = int(time_stamp[1])
                    seconds = int(time_stamp[2])
                    
                    gps_info['timestamp'] = f"{date_stamp} {hours:02d}:{minutes:02d}:{seconds:02d} UTC"
        
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            # GPS data is present but parsing failed
            gps_info['parsing_error'] = str(e)
        
        return gps_info
    
    def extract_gps_exifread(self, tags: dict) -> Dict[str, Any]:
        """
        Extract GPS information using exifread.
        
        Args:
            tags: EXIF tags from exifread
            
        Returns:
            GPS information dictionary
        """
        gps_info = {
            'has_gps': False,
            'latitude': None,
            'longitude': None,
            'altitude': None,
            'timestamp': None,
            'raw_gps_data': {}
        }
        
        # Check for GPS tags
        gps_tags = {k: v for k, v in tags.items() if k.startswith('GPS')}
        if not gps_tags:
            return gps_info
        
        gps_info['has_gps'] = True
        
        # Store raw GPS data
        for key, value in gps_tags.items():
            gps_info['raw_gps_data'][key] = str(value)
        
        try:
            # Extract latitude
            if 'GPS GPSLatitude' in tags and 'GPS GPSLatitudeRef' in tags:
                lat_tag = tags['GPS GPSLatitude']
                lat_ref = str(tags['GPS GPSLatitudeRef'])
                
                # Parse DMS from string like "[40, 42, 51]"
                lat_values = str(lat_tag).strip('[]').split(', ')
                if len(lat_values) >= 3:
                    lat_dms = [float(x.split('/')[0]) / float(x.split('/')[1]) if '/' in x else float(x) 
                              for x in lat_values[:3]]
                    gps_info['latitude'] = self.dms_to_decimal(lat_dms, lat_ref)
            
            # Extract longitude
            if 'GPS GPSLongitude' in tags and 'GPS GPSLongitudeRef' in tags:
                lon_tag = tags['GPS GPSLongitude']
                lon_ref = str(tags['GPS GPSLongitudeRef'])
                
                lon_values = str(lon_tag).strip('[]').split(', ')
                if len(lon_values) >= 3:
                    lon_dms = [float(x.split('/')[0]) / float(x.split('/')[1]) if '/' in x else float(x) 
                              for x in lon_values[:3]]
                    gps_info['longitude'] = self.dms_to_decimal(lon_dms, lon_ref)
            
            # Extract altitude
            if 'GPS GPSAltitude' in tags:
                alt_tag = str(tags['GPS GPSAltitude'])
                if '/' in alt_tag:
                    parts = alt_tag.split('/')
                    gps_info['altitude'] = float(parts[0]) / float(parts[1])
                else:
                    gps_info['altitude'] = float(alt_tag)
            
            # Extract timestamp
            if 'GPS GPSTimeStamp' in tags and 'GPS GPSDateStamp' in tags:
                time_tag = str(tags['GPS GPSTimeStamp'])
                date_tag = str(tags['GPS GPSDateStamp'])
                gps_info['timestamp'] = f"{date_tag} {time_tag} UTC"
        
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            gps_info['parsing_error'] = str(e)
        
        return gps_info
    
    def analyze_camera_settings(self, tags: dict, is_pillow: bool = True) -> Dict[str, Any]:
        """
        Analyze camera settings and shooting parameters.
        
        Args:
            tags: EXIF tags dictionary
            is_pillow: Whether tags are from Pillow (True) or exifread (False)
            
        Returns:
            Camera settings analysis
        """
        settings = {
            'camera_make': None,
            'camera_model': None,
            'lens_model': None,
            'focal_length': None,
            'aperture': None,
            'iso_speed': None,
            'exposure_time': None,
            'flash': None,
            'white_balance': None,
            'exposure_mode': None,
            'metering_mode': None,
            'shooting_mode': None
        }
        
        if is_pillow:
            # Pillow format
            settings['camera_make'] = tags.get('Make', '').strip()
            settings['camera_model'] = tags.get('Model', '').strip()
            settings['lens_model'] = tags.get('LensModel', '').strip()
            
            # Focal length
            if 'FocalLength' in tags:
                focal = tags['FocalLength']
                if hasattr(focal, 'numerator') and hasattr(focal, 'denominator'):
                    settings['focal_length'] = f"{float(focal.numerator) / float(focal.denominator):.1f}mm"
                else:
                    settings['focal_length'] = f"{float(focal):.1f}mm"
            
            # Aperture
            if 'FNumber' in tags:
                aperture = tags['FNumber']
                if hasattr(aperture, 'numerator') and hasattr(aperture, 'denominator'):
                    f_stop = float(aperture.numerator) / float(aperture.denominator)
                    settings['aperture'] = f"f/{f_stop:.1f}"
                else:
                    settings['aperture'] = f"f/{float(aperture):.1f}"
            
            # ISO
            settings['iso_speed'] = tags.get('ISOSpeedRatings', tags.get('ISO', None))
            
            # Exposure time
            if 'ExposureTime' in tags:
                exposure = tags['ExposureTime']
                if hasattr(exposure, 'numerator') and hasattr(exposure, 'denominator'):
                    exp_val = float(exposure.numerator) / float(exposure.denominator)
                    if exp_val >= 1:
                        settings['exposure_time'] = f"{exp_val:.1f}s"
                    else:
                        settings['exposure_time'] = f"1/{int(1/exp_val)}s"
                else:
                    settings['exposure_time'] = str(exposure)
        
        else:
            # exifread format
            settings['camera_make'] = str(tags.get('Image Make', '')).strip()
            settings['camera_model'] = str(tags.get('Image Model', '')).strip()
            settings['lens_model'] = str(tags.get('EXIF LensModel', '')).strip()
            
            # Parse other settings from exifread format
            if 'EXIF FocalLength' in tags:
                focal_str = str(tags['EXIF FocalLength'])
                if '/' in focal_str:
                    parts = focal_str.split('/')
                    focal_val = float(parts[0]) / float(parts[1])
                    settings['focal_length'] = f"{focal_val:.1f}mm"
                else:
                    settings['focal_length'] = f"{float(focal_str):.1f}mm"
            
            if 'EXIF FNumber' in tags:
                aperture_str = str(tags['EXIF FNumber'])
                if '/' in aperture_str:
                    parts = aperture_str.split('/')
                    f_stop = float(parts[0]) / float(parts[1])
                    settings['aperture'] = f"f/{f_stop:.1f}"
        
        # Clean up empty values
        settings = {k: v for k, v in settings.items() if v and str(v).strip()}
        
        return settings
    
    def analyze_privacy_exposure(self, tags: dict, gps_info: dict) -> Dict[str, Any]:
        """
        Analyze potential privacy exposures in EXIF data.
        
        Args:
            tags: EXIF tags dictionary
            gps_info: GPS information dictionary
            
        Returns:
            Privacy analysis results
        """
        privacy_analysis = {
            'privacy_score': 0,  # 0-10, lower is better for privacy
            'exposures': [],
            'recommendations': [],
            'sensitive_tags_found': {}
        }
        
        # Check for GPS data
        if gps_info.get('has_gps') and gps_info.get('latitude') and gps_info.get('longitude'):
            privacy_analysis['privacy_score'] += 5
            privacy_analysis['exposures'].append('GPS coordinates reveal exact location')
            privacy_analysis['recommendations'].append('Remove GPS data before sharing')
        
        # Check for other sensitive information
        tag_keys = tags.keys() if hasattr(tags, 'keys') else []
        
        for tag_key in tag_keys:
            tag_str = str(tag_key).lower()
            tag_value = str(tags[tag_key]).strip()
            
            if not tag_value:
                continue
            
            # Software information
            if 'software' in tag_str or 'creator' in tag_str:
                privacy_analysis['privacy_score'] += 1
                privacy_analysis['sensitive_tags_found']['software'] = tag_value
                privacy_analysis['exposures'].append(f'Software information: {tag_value}')
            
            # User/author information
            if any(word in tag_str for word in ['author', 'artist', 'owner', 'creator']):
                privacy_analysis['privacy_score'] += 2
                privacy_analysis['sensitive_tags_found']['author'] = tag_value
                privacy_analysis['exposures'].append(f'Author/creator information: {tag_value}')
            
            # Comments and descriptions
            if any(word in tag_str for word in ['comment', 'description', 'keyword']):
                privacy_analysis['privacy_score'] += 1
                privacy_analysis['sensitive_tags_found']['comments'] = tag_value
                privacy_analysis['exposures'].append(f'User comments/keywords found')
            
            # Copyright information
            if 'copyright' in tag_str:
                privacy_analysis['sensitive_tags_found']['copyright'] = tag_value
        
        # Generate recommendations
        if privacy_analysis['privacy_score'] > 3:
            privacy_analysis['recommendations'].append('Consider using EXIF removal tools before sharing')
        
        if privacy_analysis['privacy_score'] > 6:
            privacy_analysis['recommendations'].append('High privacy risk - remove all metadata')
        
        if not privacy_analysis['recommendations']:
            privacy_analysis['recommendations'].append('Low privacy risk detected')
        
        # Cap score at 10
        privacy_analysis['privacy_score'] = min(privacy_analysis['privacy_score'], 10)
        
        return privacy_analysis
    
    def extract_exif_pillow(self, file_path: str) -> Dict[str, Any]:
        """
        Extract EXIF data using Pillow library.
        
        Args:
            file_path: Path to the image file
            
        Returns:
            EXIF data dictionary
        """
        try:
            with Image.open(file_path) as img:
                # Get basic image info
                image_info = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'width': img.width,
                    'height': img.height
                }
                
                # Get EXIF data
                exif_data = img.getexif()
                
                if not exif_data:
                    return {
                        'method': 'pillow',
                        'image_info': image_info,
                        'has_exif': False,
                        'tags': {},
                        'tag_count': 0
                    }
                
                # Convert numeric tags to readable names
                readable_tags = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, f'Tag_{tag_id}')
                    readable_tags[tag_name] = value
                
                # Extract GPS data
                gps_info = self.extract_gps_pillow(exif_data)
                
                # Analyze camera settings
                camera_settings = self.analyze_camera_settings(readable_tags, is_pillow=True)
                
                # Analyze privacy exposure
                privacy_analysis = self.analyze_privacy_exposure(readable_tags, gps_info)
                
                return {
                    'method': 'pillow',
                    'image_info': image_info,
                    'has_exif': True,
                    'tags': readable_tags,
                    'tag_count': len(readable_tags),
                    'gps_info': gps_info,
                    'camera_settings': camera_settings,
                    'privacy_analysis': privacy_analysis
                }
                
        except Exception as e:
            return {
                'method': 'pillow',
                'error': f'Pillow extraction failed: {str(e)}',
                'has_exif': False
            }
    
    def extract_exif_exifread(self, file_path: str) -> Dict[str, Any]:
        """
        Extract EXIF data using exifread library.
        
        Args:
            file_path: Path to the image file
            
        Returns:
            EXIF data dictionary
        """
        try:
            with open(file_path, 'rb') as f:
                tags = exifread.process_file(f, details=True)
            
            if not tags:
                return {
                    'method': 'exifread',
                    'has_exif': False,
                    'tags': {},
                    'tag_count': 0
                }
            
            # Convert tags to string dictionary
            readable_tags = {}
            for key, value in tags.items():
                readable_tags[key] = str(value)
            
            # Extract GPS data
            gps_info = self.extract_gps_exifread(tags)
            
            # Analyze camera settings
            camera_settings = self.analyze_camera_settings(readable_tags, is_pillow=False)
            
            # Analyze privacy exposure
            privacy_analysis = self.analyze_privacy_exposure(readable_tags, gps_info)
            
            # Get basic image info (limited with exifread)
            image_info = {}
            if 'EXIF ExifImageWidth' in tags:
                image_info['exif_width'] = str(tags['EXIF ExifImageWidth'])
            if 'EXIF ExifImageLength' in tags:
                image_info['exif_height'] = str(tags['EXIF ExifImageLength'])
            
            return {
                'method': 'exifread',
                'image_info': image_info,
                'has_exif': True,
                'tags': readable_tags,
                'tag_count': len(readable_tags),
                'gps_info': gps_info,
                'camera_settings': camera_settings,
                'privacy_analysis': privacy_analysis
            }
            
        except Exception as e:
            return {
                'method': 'exifread',
                'error': f'exifread extraction failed: {str(e)}',
                'has_exif': False
            }
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive EXIF analysis on an image file.
        
        Args:
            file_path: Path to the image file
            
        Returns:
            Complete EXIF analysis results
        """
        start_time = time.perf_counter()
        
        # Basic file validation
        if not os.path.exists(file_path):
            return {
                'file_path': file_path,
                'error': 'File not found',
                'duration': 0
            }
        
        if not self.is_supported_format(file_path):
            return {
                'file_path': file_path,
                'error': f'Unsupported file format. Supported: {", ".join(self.SUPPORTED_EXTENSIONS)}',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        # Get file stats
        file_stats = os.stat(file_path)
        file_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': file_stats.st_size,
            'file_size_mb': round(file_stats.st_size / (1024 * 1024), 2),
            'modified_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
            'extension': os.path.splitext(file_path)[1].lower()
        }
        
        # Try to extract EXIF data
        result = None
        
        if self.preferred_library == 'pillow':
            result = self.extract_exif_pillow(file_path)
            # Fallback to exifread if Pillow fails and it's available
            if result.get('error') and EXIFREAD_AVAILABLE:
                result = self.extract_exif_exifread(file_path)
        elif self.preferred_library == 'exifread':
            result = self.extract_exif_exifread(file_path)
            # Fallback to Pillow if exifread fails and it's available
            if result.get('error') and PILLOW_AVAILABLE:
                result = self.extract_exif_pillow(file_path)
        else:
            result = {
                'error': 'No EXIF extraction library available. Install Pillow or exifread.',
                'has_exif': False
            }
        
        # Combine file info with EXIF results
        result.update(file_info)
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result


def run_exif_metadata(image_path: str) -> Dict[str, Any]:
    """
    Extract EXIF metadata from an image file with comprehensive analysis.
    
    Args:
        image_path: Path to the image file
    
    Returns:
        Dictionary with EXIF metadata analysis:
        - "file_path": path to the analyzed file
        - "file_name": name of the file
        - "file_size": size in bytes
        - "file_size_mb": size in megabytes
        - "extension": file extension
        - "has_exif": boolean indicating if EXIF data exists
        - "method": extraction method used ('pillow' or 'exifread')
        - "tags": dictionary of all EXIF tags
        - "tag_count": number of EXIF tags found
        - "gps_info": GPS data analysis including coordinates
        - "camera_settings": camera and shooting parameters
        - "privacy_analysis": privacy exposure assessment
        - "image_info": basic image information
        - "duration": analysis duration in seconds
        - "error": error message if extraction failed
    """
    if not image_path or not image_path.strip():
        return {
            'image_path': image_path,
            'error': 'Image path cannot be empty',
            'duration': 0
        }
    
    # Initialize EXIF analyzer
    analyzer = ExifAnalyzer()
    
    # Check if any extraction library is available
    if not (PILLOW_AVAILABLE or EXIFREAD_AVAILABLE):
        return {
            'image_path': image_path,
            'error': 'No EXIF extraction library available. Install with: pip install Pillow exifread',
            'available_libraries': [],
            'duration': 0
        }
    
    # Perform EXIF analysis
    result = analyzer.analyze_file(image_path.strip())
    
    return result


def format_exif_summary(result: Dict[str, Any]) -> str:
    """
    Format EXIF analysis results for display.
    
    Args:
        result: EXIF analysis result dictionary
        
    Returns:
        Formatted string with EXIF information
    """
    if result.get('error'):
        return f"Error analyzing {result.get('file_path', 'unknown')}: {result['error']}"
    
    lines = []
    lines.append(f"File: {result.get('file_name', 'Unknown')}")
    lines.append(f"Path: {result.get('file_path', 'Unknown')}")
    lines.append(f"Size: {result.get('file_size_mb', 0):.2f} MB ({result.get('file_size', 0):,} bytes)")
    lines.append(f"Format: {result.get('extension', 'Unknown').upper()}")
    
    if result.get('image_info'):
        img_info = result['image_info']
        if 'width' in img_info and 'height' in img_info:
            lines.append(f"Dimensions: {img_info['width']}x{img_info['height']} pixels")
        if 'format' in img_info:
            lines.append(f"Image Format: {img_info['format']}")
    
    lines.append(f"Extraction Method: {result.get('method', 'Unknown')}")
    
    # EXIF information
    if result.get('has_exif'):
        lines.append(f"EXIF Tags: {result.get('tag_count', 0)} found")
        
        # Camera settings
        camera = result.get('camera_settings', {})
        if camera.get('camera_make') or camera.get('camera_model'):
            camera_name = f"{camera.get('camera_make', '')} {camera.get('camera_model', '')}".strip()
            lines.append(f"Camera: {camera_name}")
        
        if camera.get('lens_model'):
            lines.append(f"Lens: {camera['lens_model']}")
        
        # Shooting parameters
        params = []
        if camera.get('focal_length'):
            params.append(f"Focal: {camera['focal_length']}")
        if camera.get('aperture'):
            params.append(f"Aperture: {camera['aperture']}")
        if camera.get('exposure_time'):
            params.append(f"Shutter: {camera['exposure_time']}")
        if camera.get('iso_speed'):
            params.append(f"ISO: {camera['iso_speed']}")
        
        if params:
            lines.append(f"Settings: {' | '.join(params)}")
        
        # GPS information
        gps = result.get('gps_info', {})
        if gps.get('has_gps'):
            if gps.get('latitude') and gps.get('longitude'):
                lines.append(f"GPS: {gps['latitude']:.6f}, {gps['longitude']:.6f}")
                if gps.get('altitude'):
                    lines.append(f"Altitude: {gps['altitude']:.1f}m")
            else:
                lines.append("GPS: Present but parsing failed")
        else:
            lines.append("GPS: No location data")
        
        # Privacy analysis
        privacy = result.get('privacy_analysis', {})
        if privacy:
            score = privacy.get('privacy_score', 0)
            lines.append(f"Privacy Score: {score}/10 {'(HIGH RISK)' if score > 6 else '(MEDIUM RISK)' if score > 3 else '(LOW RISK)'}")
            
            if privacy.get('exposures'):
                lines.append("Privacy Exposures:")
                for exposure in privacy['exposures'][:3]:  # Show first 3
                    lines.append(f"  - {exposure}")
    else:
        lines.append("EXIF Data: No metadata found")
    
    lines.append(f"Analysis Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python exif_metadata.py <image_path>")
        print("Example: python exif_metadata.py photo.jpg")
        print("\nSupported formats:", ", ".join(sorted(ExifAnalyzer.SUPPORTED_EXTENSIONS)))
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    print(f"Analyzing EXIF metadata for: {image_path}")
    print("-" * 60)
    
    result = run_exif_metadata(image_path)
    formatted_output = format_exif_summary(result)
    
    print(formatted_output)
    
    # Show detailed tags if requested
    if '--tags' in sys.argv and not result.get('error') and result.get('has_exif'):
        print("\nDetailed EXIF Tags:")
        print("-" * 30)
        tags = result.get('tags', {})
        for name, value in sorted(tags.items()):
            # Truncate very long values
            value_str = str(value)
            if len(value_str) > 100:
                value_str = value_str[:97] + '...'
            print(f"{name}: {value_str}")
    
    # Show GPS details if requested
    if '--gps' in sys.argv and not result.get('error'):
        gps_info = result.get('gps_info', {})
        if gps_info.get('has_gps'):
            print("\nGPS Details:")
            print("-" * 20)
            for key, value in gps_info.items():
                if key != 'raw_gps_data':
                    print(f"{key}: {value}")
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
