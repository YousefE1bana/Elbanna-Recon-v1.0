#!/usr/bin/env python3
"""
Header Info Module for Elbanna Recon v1.0

This module provides detailed HTTP header analysis and response information.
Features:
- Efficient HEAD request analysis with GET fallback
- Comprehensive header parsing and categorization
- Cookie analysis and security assessment
- Redirect chain tracking
- Server and technology fingerprinting
- Security header evaluation

Author: Yousef Osama
"""

import time
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional, List
import re

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class HeaderAnalyzer:
    """
    HTTP header analysis and information extraction engine.
    """
    
    # User agent for requests
    USER_AGENT = "Elbanna-Recon-v1.0-HeaderAnalyzer"
    
    # Request timeout settings
    DEFAULT_TIMEOUT = 10
    
    # Security headers to analyze
    SECURITY_HEADERS = {
        'strict-transport-security': 'HSTS',
        'content-security-policy': 'CSP',
        'x-frame-options': 'Frame Protection',
        'x-content-type-options': 'MIME Type Protection',
        'x-xss-protection': 'XSS Protection',
        'referrer-policy': 'Referrer Policy',
        'permissions-policy': 'Permissions Policy',
        'feature-policy': 'Feature Policy'
    }
    
    # Server technology patterns
    SERVER_PATTERNS = {
        'apache': r'apache',
        'nginx': r'nginx',
        'iis': r'microsoft-iis|iis',
        'cloudflare': r'cloudflare',
        'aws': r'awselb|amazonalb',
        'google': r'gws|gfe',
        'fastly': r'fastly',
        'akamai': r'akamai'
    }
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize the header analyzer.
        
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
    
    def analyze_cookies(self, cookies) -> Dict[str, Any]:
        """
        Analyze cookies for security and information.
        
        Args:
            cookies: Request cookies object
            
        Returns:
            Cookie analysis results
        """
        cookie_analysis = {
            'total_cookies': len(cookies),
            'cookies': [],
            'security_flags': {
                'secure_cookies': 0,
                'httponly_cookies': 0,
                'samesite_cookies': 0
            },
            'session_cookies': 0,
            'persistent_cookies': 0
        }
        
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
                'expires': cookie.expires,
                'max_age': getattr(cookie, 'max_age', None)
            }
            
            # Check for SameSite attribute
            if hasattr(cookie, 'samesite') and cookie.samesite:
                cookie_info['samesite'] = cookie.samesite
                cookie_analysis['security_flags']['samesite_cookies'] += 1
            
            # Count security flags
            if cookie.secure:
                cookie_analysis['security_flags']['secure_cookies'] += 1
            
            if cookie_info['httponly']:
                cookie_analysis['security_flags']['httponly_cookies'] += 1
            
            # Determine cookie type
            if cookie.expires or cookie_info['max_age']:
                cookie_analysis['persistent_cookies'] += 1
            else:
                cookie_analysis['session_cookies'] += 1
            
            cookie_analysis['cookies'].append(cookie_info)
        
        return cookie_analysis
    
    def identify_server_technology(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Identify server technology from headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Server technology analysis
        """
        technology = {
            'server': headers.get('server', 'Unknown'),
            'powered_by': headers.get('x-powered-by', 'Unknown'),
            'technologies': [],
            'cdn': None,
            'load_balancer': None
        }
        
        # Analyze server header
        server_header = headers.get('server', '').lower()
        for tech, pattern in self.SERVER_PATTERNS.items():
            if re.search(pattern, server_header, re.IGNORECASE):
                technology['technologies'].append(tech)
        
        # Check for CDN indicators
        cdn_headers = [
            'cf-ray',  # Cloudflare
            'x-served-by',  # Fastly
            'x-cache',  # Various CDNs
            'x-amz-cf-id',  # Amazon CloudFront
            'x-azure-ref'  # Azure CDN
        ]
        
        for header in cdn_headers:
            if header in headers:
                if 'cf-' in header:
                    technology['cdn'] = 'Cloudflare'
                elif 'amz' in header:
                    technology['cdn'] = 'Amazon CloudFront'
                elif 'azure' in header:
                    technology['cdn'] = 'Azure CDN'
                elif header == 'x-served-by':
                    technology['cdn'] = 'Fastly'
                else:
                    technology['cdn'] = 'Unknown CDN'
                break
        
        # Check for load balancer indicators
        lb_headers = ['x-forwarded-for', 'x-real-ip', 'x-forwarded-proto']
        if any(header in headers for header in lb_headers):
            technology['load_balancer'] = 'Detected'
        
        return technology
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze security headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Security analysis results
        """
        security_analysis = {
            'score': 0,
            'max_score': len(self.SECURITY_HEADERS),
            'headers_found': {},
            'headers_missing': [],
            'recommendations': []
        }
        
        # Check each security header
        for header, name in self.SECURITY_HEADERS.items():
            if header in headers:
                security_analysis['score'] += 1
                security_analysis['headers_found'][header] = {
                    'name': name,
                    'value': headers[header][:100] + '...' if len(headers[header]) > 100 else headers[header]
                }
            else:
                security_analysis['headers_missing'].append({
                    'header': header,
                    'name': name
                })
        
        # Generate recommendations
        if security_analysis['score'] < 4:
            security_analysis['recommendations'].append('Consider implementing basic security headers')
        
        if 'strict-transport-security' not in headers:
            security_analysis['recommendations'].append('Implement HSTS for secure connections')
        
        if 'content-security-policy' not in headers:
            security_analysis['recommendations'].append('Add Content Security Policy to prevent XSS')
        
        if 'x-frame-options' not in headers:
            security_analysis['recommendations'].append('Add X-Frame-Options to prevent clickjacking')
        
        return security_analysis
    
    def categorize_headers(self, headers: Dict[str, str]) -> Dict[str, List[Dict[str, str]]]:
        """
        Categorize headers by type.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Categorized headers
        """
        categories = {
            'security': [],
            'caching': [],
            'content': [],
            'server': [],
            'custom': []
        }
        
        # Security headers
        for header in self.SECURITY_HEADERS.keys():
            if header in headers:
                categories['security'].append({
                    'name': header,
                    'value': headers[header]
                })
        
        # Caching headers
        caching_headers = [
            'cache-control', 'expires', 'etag', 'last-modified',
            'if-modified-since', 'if-none-match', 'pragma'
        ]
        for header in caching_headers:
            if header in headers:
                categories['caching'].append({
                    'name': header,
                    'value': headers[header]
                })
        
        # Content headers
        content_headers = [
            'content-type', 'content-length', 'content-encoding',
            'content-disposition', 'content-language', 'content-range'
        ]
        for header in content_headers:
            if header in headers:
                categories['content'].append({
                    'name': header,
                    'value': headers[header]
                })
        
        # Server headers
        server_headers = [
            'server', 'x-powered-by', 'x-aspnet-version',
            'x-served-by', 'x-cache', 'via'
        ]
        for header in server_headers:
            if header in headers:
                categories['server'].append({
                    'name': header,
                    'value': headers[header]
                })
        
        # Custom/Other headers (starting with X- or uncommon)
        for header, value in headers.items():
            header_lower = header.lower()
            if (header_lower.startswith('x-') and 
                header_lower not in [h['name'] for h in categories['security']] and
                header_lower not in [h['name'] for h in categories['server']]):
                categories['custom'].append({
                    'name': header,
                    'value': value
                })
        
        return categories
    
    def analyze_headers(self, url: str, use_get_fallback: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive header analysis.
        
        Args:
            url: URL to analyze
            use_get_fallback: Whether to fallback to GET if HEAD fails
            
        Returns:
            Comprehensive header analysis
        """
        if not REQUESTS_AVAILABLE:
            return {
                'error': 'requests library not available. Install with: pip install requests'
            }
        
        start_time = time.perf_counter()
        normalized_url = self.normalize_url(url)
        
        try:
            # First try HEAD request for efficiency
            response = self.session.head(
                normalized_url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # If HEAD didn't work well, try GET
            if (response.status_code in [405, 501] or 
                not response.headers) and use_get_fallback:
                
                response = self.session.get(
                    normalized_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True  # Don't download body
                )
                # Close the response to free resources
                response.close()
            
            # Measure response time
            response_time = time.perf_counter() - start_time
            
            # Convert headers to dict for easier processing
            headers_dict = dict(response.headers)
            
            # Analyze components
            cookie_analysis = self.analyze_cookies(response.cookies)
            technology_info = self.identify_server_technology(headers_dict)
            security_analysis = self.analyze_security_headers(headers_dict)
            categorized_headers = self.categorize_headers(headers_dict)
            
            # Build redirect chain
            redirect_chain = []
            for resp in response.history:
                redirect_chain.append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'location': resp.headers.get('location', '')
                })
            
            # Add final response
            redirect_chain.append({
                'url': response.url,
                'status_code': response.status_code,
                'location': None
            })
            
            return {
                'url': normalized_url,
                'final_url': response.url,
                'status_code': response.status_code,
                'status_text': response.reason,
                'response_time': round(response_time * 1000, 2),  # milliseconds
                'headers': headers_dict,
                'header_count': len(headers_dict),
                'cookies': cookie_analysis,
                'technology': technology_info,
                'security': security_analysis,
                'categorized_headers': categorized_headers,
                'redirect_chain': redirect_chain,
                'redirect_count': len(response.history),
                'method_used': 'GET' if use_get_fallback and (response.status_code not in [405, 501]) else 'HEAD',
                'content_length': headers_dict.get('content-length'),
                'content_type': headers_dict.get('content-type', 'Unknown'),
                'server': headers_dict.get('server', 'Unknown'),
                'date': headers_dict.get('date'),
                'duration': round(time.perf_counter() - start_time, 3),
                'error': None
            }
            
        except requests.exceptions.Timeout:
            return {
                'url': normalized_url,
                'error': f'Request timed out after {self.timeout} seconds',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        except requests.exceptions.ConnectionError:
            return {
                'url': normalized_url,
                'error': 'Connection error - unable to reach the URL',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': normalized_url,
                'error': f'Request error: {str(e)}',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        except Exception as e:
            return {
                'url': normalized_url,
                'error': f'Unexpected error: {str(e)}',
                'duration': round(time.perf_counter() - start_time, 3)
            }


def run_header_info(url: str) -> Dict[str, Any]:
    """
    Analyze HTTP headers and return comprehensive header information.
    
    Args:
        url: URL to analyze
    
    Returns:
        Dictionary with header analysis results:
        - "url": original URL
        - "final_url": final URL after redirects
        - "status_code": HTTP status code
        - "status_text": HTTP status text
        - "response_time": response time in milliseconds
        - "headers": dictionary of all HTTP headers
        - "header_count": total number of headers
        - "cookies": detailed cookie analysis
        - "technology": server technology identification
        - "security": security header analysis
        - "categorized_headers": headers organized by category
        - "redirect_chain": list of redirects with status codes
        - "redirect_count": number of redirects
        - "method_used": HTTP method used (HEAD or GET)
        - "content_length": content length from headers
        - "content_type": content type
        - "server": server information
        - "date": response date
        - "duration": analysis duration in seconds
        - "error": error message or None
    """
    if not url or not url.strip():
        return {
            'url': url,
            'error': 'URL cannot be empty',
            'duration': 0
        }
    
    # Initialize header analyzer
    analyzer = HeaderAnalyzer()
    
    # Perform header analysis
    result = analyzer.analyze_headers(url.strip())
    
    return result


def format_header_summary(result: Dict[str, Any]) -> str:
    """
    Format header analysis results for display.
    
    Args:
        result: Header analysis result dictionary
        
    Returns:
        Formatted string with header information
    """
    if result.get('error'):
        return f"Error analyzing {result.get('url', 'unknown')}: {result['error']}"
    
    lines = []
    lines.append(f"URL: {result.get('url', 'Unknown')}")
    
    if result.get('final_url') != result.get('url'):
        lines.append(f"Final URL: {result.get('final_url')}")
    
    lines.append(f"Status: {result.get('status_code')} {result.get('status_text', '')}")
    lines.append(f"Response Time: {result.get('response_time', 0)}ms")
    lines.append(f"Method Used: {result.get('method_used', 'Unknown')}")
    
    # Header information
    lines.append(f"Total Headers: {result.get('header_count', 0)}")
    lines.append(f"Server: {result.get('server', 'Unknown')}")
    lines.append(f"Content Type: {result.get('content_type', 'Unknown')}")
    
    if result.get('content_length'):
        lines.append(f"Content Length: {result.get('content_length')} bytes")
    
    # Cookie information
    cookies = result.get('cookies', {})
    if cookies.get('total_cookies', 0) > 0:
        lines.append(f"Cookies: {cookies['total_cookies']} total")
        secure_cookies = cookies.get('security_flags', {}).get('secure_cookies', 0)
        lines.append(f"  - Secure: {secure_cookies}/{cookies['total_cookies']}")
    
    # Security information
    security = result.get('security', {})
    security_score = security.get('score', 0)
    max_score = security.get('max_score', 8)
    lines.append(f"Security Headers: {security_score}/{max_score}")
    
    if security.get('recommendations'):
        lines.append("Security Recommendations:")
        for rec in security['recommendations'][:3]:  # Show first 3
            lines.append(f"  - {rec}")
    
    # Technology information
    tech = result.get('technology', {})
    if tech.get('technologies'):
        lines.append(f"Technologies: {', '.join(tech['technologies'])}")
    
    if tech.get('cdn'):
        lines.append(f"CDN: {tech['cdn']}")
    
    # Redirect information
    if result.get('redirect_count', 0) > 0:
        lines.append(f"Redirects: {result.get('redirect_count')}")
    
    lines.append(f"Analysis Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python header_info.py <url>")
        print("Example: python header_info.py https://google.com")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"Analyzing headers for: {url}")
    print("-" * 60)
    
    result = run_header_info(url)
    formatted_output = format_header_summary(result)
    
    print(formatted_output)
    
    # Show detailed headers if requested
    if '--headers' in sys.argv and not result.get('error'):
        print("\nDetailed Headers:")
        print("-" * 30)
        for name, value in result.get('headers', {}).items():
            print(f"{name}: {value}")
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
