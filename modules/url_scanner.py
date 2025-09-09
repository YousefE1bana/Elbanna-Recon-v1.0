#!/usr/bin/env python3
"""
URL Scanner Module for Elbanna Recon v1.0

This module provides comprehensive URL analysis including basic HTTP information
and optional VirusTotal security scanning.
Features:
- HTTP header analysis and status code checking
- Content type and length detection
- Redirect chain following
- VirusTotal integration for security assessment
- Response time measurement
- Basic security headers detection

Author: Yousef Osama
"""

import time
import re
import base64
import hashlib
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional, List
import json

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class URLScanner:
    """
    URL analysis and security scanning engine.
    """
    
    # User agent for requests
    USER_AGENT = "Elbanna-Recon-v1.0-URLScanner"
    
    # VirusTotal API endpoints
    VT_API_V3_BASE = "https://www.virustotal.com/api/v3"
    VT_API_V2_BASE = "https://www.virustotal.com/vtapi/v2"
    
    # Request timeout settings
    DEFAULT_TIMEOUT = 10
    VT_TIMEOUT = 30
    
    # Security headers to check
    SECURITY_HEADERS = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
        'feature-policy'
    ]
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize the URL scanner.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = None
        
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': self.USER_AGENT
            })
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize URL format.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL string
        """
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def analyze_basic_info(self, url: str) -> Dict[str, Any]:
        """
        Perform basic URL analysis using HTTP requests.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with basic URL information
        """
        if not REQUESTS_AVAILABLE:
            return {
                'error': 'requests library not available. Install with: pip install requests'
            }
        
        start_time = time.perf_counter()
        normalized_url = self.normalize_url(url)
        
        try:
            # Parse URL components
            parsed = urlparse(normalized_url)
            
            # Make request with redirects
            response = self.session.get(
                normalized_url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True
            )
            
            # Get response timing
            response_time = time.perf_counter() - start_time
            
            # Analyze response
            basic_info = {
                'url': normalized_url,
                'final_url': response.url,
                'status_code': response.status_code,
                'status_text': response.reason,
                'response_time': round(response_time * 1000, 2),  # in milliseconds
                'headers': dict(response.headers),
                'content_type': response.headers.get('content-type', 'Unknown'),
                'content_length': response.headers.get('content-length'),
                'server': response.headers.get('server', 'Unknown'),
                'redirected': normalized_url != response.url,
                'redirect_count': len(response.history),
                'redirect_chain': [r.url for r in response.history] + [response.url],
                'is_https': response.url.startswith('https://'),
                'domain': urlparse(response.url).netloc,
                'path': urlparse(response.url).path,
                'query': urlparse(response.url).query,
                'encoding': response.encoding,
                'error': None
            }
            
            # Analyze security headers
            security_headers = {}
            for header in self.SECURITY_HEADERS:
                if header in response.headers:
                    security_headers[header] = response.headers[header]
            
            basic_info['security_headers'] = security_headers
            basic_info['security_score'] = len(security_headers)
            
            # Try to get content length from actual content if not in headers
            if not basic_info['content_length']:
                try:
                    # Read first chunk to get content length estimate
                    chunk = next(response.iter_content(1024), b'')
                    if chunk:
                        basic_info['content_length_estimated'] = len(chunk)
                except:
                    pass
            
            # Analyze URL structure for potential security issues
            security_analysis = self.analyze_url_security(normalized_url, response)
            basic_info.update(security_analysis)
            
            return basic_info
            
        except requests.exceptions.Timeout:
            return {
                'url': normalized_url,
                'error': f'Request timed out after {self.timeout} seconds',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except requests.exceptions.ConnectionError:
            return {
                'url': normalized_url,
                'error': 'Connection error - unable to reach the URL',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': normalized_url,
                'error': f'Request error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except Exception as e:
            return {
                'url': normalized_url,
                'error': f'Unexpected error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
    
    def analyze_url_security(self, url: str, response) -> Dict[str, Any]:
        """
        Analyze URL for potential security issues.
        
        Args:
            url: URL to analyze
            response: HTTP response object
            
        Returns:
            Dictionary with security analysis
        """
        security_flags = []
        
        # Check for HTTP vs HTTPS
        if not url.startswith('https://'):
            security_flags.append('non_https')
        
        # Check for suspicious URL patterns
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP address
            r'[a-z0-9]{32}',  # MD5-like string
            r'[a-z0-9]{40}',  # SHA1-like string
            r'bit\.ly|tinyurl|t\.co',  # URL shorteners
            r'\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                security_flags.append(f'suspicious_pattern_{pattern}')
        
        # Check response headers for security issues
        if response:
            # Missing security headers
            if 'strict-transport-security' not in response.headers:
                security_flags.append('missing_hsts')
            
            if 'x-frame-options' not in response.headers:
                security_flags.append('missing_frame_options')
            
            # Check for potentially dangerous content types
            content_type = response.headers.get('content-type', '').lower()
            if 'application/octet-stream' in content_type:
                security_flags.append('binary_content')
            elif 'application/zip' in content_type or 'application/x-' in content_type:
                security_flags.append('executable_content')
        
        return {
            'security_flags': security_flags,
            'security_risk_level': 'high' if len(security_flags) > 3 else 'medium' if len(security_flags) > 1 else 'low'
        }
    
    def query_virustotal_v3(self, url: str, api_key: str) -> Dict[str, Any]:
        """
        Query VirusTotal API v3 for URL analysis.
        
        Args:
            url: URL to analyze
            api_key: VirusTotal API key
            
        Returns:
            VirusTotal analysis results
        """
        try:
            # Encode URL for VirusTotal API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            # Query VirusTotal
            vt_url = f"{self.VT_API_V3_BASE}/urls/{url_id}"
            headers = {
                'x-apikey': api_key,
                'User-Agent': self.USER_AGENT
            }
            
            response = self.session.get(vt_url, headers=headers, timeout=self.VT_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Parse scan results
                scan_results = attributes.get('last_analysis_stats', {})
                scan_engines = attributes.get('last_analysis_results', {})
                
                # Count detections
                malicious_count = scan_results.get('malicious', 0)
                suspicious_count = scan_results.get('suspicious', 0)
                total_scans = sum(scan_results.values())
                
                # Get detailed detection info
                detections = []
                for engine, result in scan_engines.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        detections.append({
                            'engine': engine,
                            'category': result.get('category'),
                            'result': result.get('result')
                        })
                
                return {
                    'vt_available': True,
                    'scan_date': attributes.get('last_analysis_date'),
                    'total_scans': total_scans,
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'clean_count': scan_results.get('harmless', 0) + scan_results.get('undetected', 0),
                    'detection_ratio': f"{malicious_count + suspicious_count}/{total_scans}",
                    'detections': detections[:10],  # Limit to first 10 detections
                    'reputation': attributes.get('reputation', 0),
                    'categories': attributes.get('categories', {}),
                    'vt_error': None
                }
            elif response.status_code == 404:
                return {
                    'vt_available': True,
                    'vt_error': 'URL not found in VirusTotal database',
                    'scan_date': None,
                    'total_scans': 0,
                    'detection_ratio': '0/0'
                }
            else:
                return {
                    'vt_available': True,
                    'vt_error': f'VirusTotal API error: {response.status_code} - {response.text}',
                    'scan_date': None,
                    'total_scans': 0,
                    'detection_ratio': '0/0'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'vt_available': True,
                'vt_error': f'VirusTotal request failed: {str(e)}',
                'scan_date': None,
                'total_scans': 0,
                'detection_ratio': '0/0'
            }
        except Exception as e:
            return {
                'vt_available': True,
                'vt_error': f'VirusTotal analysis error: {str(e)}',
                'scan_date': None,
                'total_scans': 0,
                'detection_ratio': '0/0'
            }
    
    def comprehensive_scan(self, url: str, virustotal_api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis.
        
        Args:
            url: URL to analyze
            virustotal_api_key: Optional VirusTotal API key
            
        Returns:
            Comprehensive analysis results
        """
        start_time = time.perf_counter()
        
        # Basic URL analysis
        basic_info = self.analyze_basic_info(url)
        
        # If basic analysis failed, return early
        if basic_info.get('error'):
            basic_info['duration'] = round(time.perf_counter() - start_time, 3)
            basic_info['vt_available'] = False
            return basic_info
        
        # VirusTotal analysis (if API key provided)
        if virustotal_api_key and virustotal_api_key.strip():
            vt_results = self.query_virustotal_v3(url, virustotal_api_key.strip())
            basic_info.update(vt_results)
        else:
            basic_info.update({
                'vt_available': False,
                'vt_error': 'No VirusTotal API key provided',
                'total_scans': 0,
                'detection_ratio': 'N/A'
            })
        
        # Add timing information
        basic_info['duration'] = round(time.perf_counter() - start_time, 3)
        
        return basic_info


def run_url_scanner(url: str, virustotal_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform comprehensive URL analysis with optional VirusTotal integration.
    
    Args:
        url: URL to analyze
        virustotal_api_key: Optional VirusTotal API key for security scanning
    
    Returns:
        Dictionary with URL analysis results:
        - "url": original URL
        - "final_url": final URL after redirects
        - "status_code": HTTP status code
        - "status_text": HTTP status text
        - "response_time": response time in milliseconds
        - "headers": HTTP response headers
        - "content_type": content type
        - "content_length": content length
        - "server": server information
        - "redirected": boolean indicating if URL was redirected
        - "redirect_count": number of redirects
        - "redirect_chain": list of URLs in redirect chain
        - "is_https": boolean indicating HTTPS usage
        - "domain": extracted domain
        - "security_headers": dictionary of security headers found
        - "security_score": number of security headers present
        - "security_flags": list of potential security issues
        - "security_risk_level": assessed risk level (low/medium/high)
        - "vt_available": boolean indicating if VirusTotal was used
        - "total_scans": VirusTotal total scan count
        - "malicious_count": VirusTotal malicious detections
        - "suspicious_count": VirusTotal suspicious detections
        - "detection_ratio": VirusTotal detection ratio string
        - "detections": list of VirusTotal detection details
        - "duration": analysis duration in seconds
        - "error": error message or None
    """
    if not url or not url.strip():
        return {
            'url': url,
            'error': 'URL cannot be empty',
            'duration': 0,
            'vt_available': False
        }
    
    # Initialize URL scanner
    scanner = URLScanner()
    
    # Perform comprehensive scan
    result = scanner.comprehensive_scan(url.strip(), virustotal_api_key)
    
    return result


def format_scan_summary(result: Dict[str, Any]) -> str:
    """
    Format URL scan results for display.
    
    Args:
        result: URL scan result dictionary
        
    Returns:
        Formatted string with scan information
    """
    if result.get('error'):
        return f"Error scanning {result.get('url', 'unknown')}: {result['error']}"
    
    lines = []
    lines.append(f"URL: {result.get('url', 'Unknown')}")
    
    if result.get('final_url') != result.get('url'):
        lines.append(f"Final URL: {result.get('final_url')}")
    
    lines.append(f"Status: {result.get('status_code')} {result.get('status_text', '')}")
    lines.append(f"Response Time: {result.get('response_time', 0)}ms")
    lines.append(f"Content Type: {result.get('content_type', 'Unknown')}")
    
    if result.get('content_length'):
        lines.append(f"Content Length: {result.get('content_length')} bytes")
    
    lines.append(f"Server: {result.get('server', 'Unknown')}")
    lines.append(f"HTTPS: {'Yes' if result.get('is_https') else 'No'}")
    
    if result.get('redirected'):
        lines.append(f"Redirects: {result.get('redirect_count', 0)}")
    
    # Security information
    security_score = result.get('security_score', 0)
    lines.append(f"Security Headers: {security_score}/8")
    lines.append(f"Risk Level: {result.get('security_risk_level', 'unknown').title()}")
    
    # VirusTotal information
    if result.get('vt_available') and not result.get('vt_error'):
        lines.append(f"VirusTotal: {result.get('detection_ratio', 'N/A')} detections")
        if result.get('malicious_count', 0) > 0:
            lines.append(f"⚠️ Malicious detections found!")
    elif result.get('vt_error'):
        lines.append(f"VirusTotal: {result.get('vt_error')}")
    else:
        lines.append("VirusTotal: Not checked (no API key)")
    
    lines.append(f"Scan Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python url_scanner.py <url> [virustotal_api_key]")
        print("Example: python url_scanner.py https://google.com")
        print("Example: python url_scanner.py https://google.com your_vt_api_key")
        sys.exit(1)
    
    url = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Scanning URL: {url}")
    if api_key:
        print("VirusTotal API key provided - will include security analysis")
    print("-" * 60)
    
    result = run_url_scanner(url, api_key)
    formatted_output = format_scan_summary(result)
    
    print(formatted_output)
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        print(json.dumps(result, indent=2, default=str))
