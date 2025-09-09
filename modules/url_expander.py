#!/usr/bin/env python3
"""
URL Expander Module for Elbanna Recon v1.0

This module provides comprehensive URL expansion and redirect chain analysis.
Features:
- Manual redirect following with detailed step tracking
- Support for various redirect types (301, 302, 303, 307, 308)
- Security analysis of redirect chains
- Domain reputation and safety checks
- Performance metrics and timing analysis
- Detection of malicious or suspicious redirects

Author: Yousef Osama
"""

import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import re

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class URLExpander:
    """
    URL expansion and redirect chain analysis engine.
    """
    
    # User agent for requests
    USER_AGENT = "Elbanna-Recon-v1.0-URLExpander"
    
    # Request timeout settings
    DEFAULT_TIMEOUT = 10
    
    # Redirect status codes
    REDIRECT_CODES = {
        301: 'Moved Permanently',
        302: 'Found',
        303: 'See Other',
        307: 'Temporary Redirect',
        308: 'Permanent Redirect'
    }
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = {
        'url_shorteners': [
            r'bit\.ly', r'tinyurl\.com', r'short\.link', r'ow\.ly', r't\.co',
            r'goo\.gl', r'tiny\.cc', r'is\.gd', r'buff\.ly', r'rebrand\.ly',
            r'clickme\.net', r'short\.me', r'bc\.vc', r'lnk\.to'
        ],
        'suspicious_domains': [
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free TLDs
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-zA-Z0-9]{20,}\.com',  # Very long subdomain
            r'.*-[0-9]{4,}\..*'  # Domain with many numbers
        ],
        'phishing_indicators': [
            r'secure.*update', r'verify.*account', r'suspended.*account',
            r'login.*required', r'confirm.*identity', r'urgent.*action',
            r'account.*locked', r'payment.*failed', r'click.*here'
        ]
    }
    
    # Common URL shortener services
    URL_SHORTENERS = {
        'bit.ly': 'Bitly',
        'tinyurl.com': 'TinyURL',
        't.co': 'Twitter',
        'goo.gl': 'Google (deprecated)',
        'ow.ly': 'Hootsuite',
        'short.link': 'Short.link',
        'tiny.cc': 'Tiny.cc',
        'is.gd': 'is.gd',
        'buff.ly': 'Buffer'
    }
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize the URL expander.
        
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
    
    def analyze_url_security(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for security concerns.
        
        Args:
            url: URL to analyze
            
        Returns:
            Security analysis results
        """
        security_analysis = {
            'risk_level': 'low',
            'flags': [],
            'warnings': [],
            'url_type': 'normal',
            'reputation_score': 100  # 0-100, higher is better
        }
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Check for URL shorteners
        for pattern in self.SUSPICIOUS_PATTERNS['url_shorteners']:
            if re.search(pattern, domain):
                security_analysis['url_type'] = 'url_shortener'
                security_analysis['flags'].append('url_shortener')
                security_analysis['reputation_score'] -= 10
                break
        
        # Check for suspicious domains
        for pattern in self.SUSPICIOUS_PATTERNS['suspicious_domains']:
            if re.search(pattern, domain):
                security_analysis['flags'].append('suspicious_domain')
                security_analysis['warnings'].append(f'Suspicious domain pattern: {domain}')
                security_analysis['reputation_score'] -= 20
                if security_analysis['risk_level'] == 'low':
                    security_analysis['risk_level'] = 'medium'
        
        # Check for phishing indicators
        full_url = url.lower()
        for pattern in self.SUSPICIOUS_PATTERNS['phishing_indicators']:
            if re.search(pattern, full_url):
                security_analysis['flags'].append('phishing_indicator')
                security_analysis['warnings'].append(f'Potential phishing indicator detected')
                security_analysis['reputation_score'] -= 30
                security_analysis['risk_level'] = 'high'
        
        # Check for HTTP vs HTTPS
        if parsed_url.scheme == 'http':
            security_analysis['flags'].append('insecure_protocol')
            security_analysis['warnings'].append('URL uses insecure HTTP protocol')
            security_analysis['reputation_score'] -= 5
        
        # Check for suspicious query parameters
        if query:
            suspicious_params = ['redirect', 'goto', 'url', 'link', 'continue', 'return']
            for param in suspicious_params:
                if param in query:
                    security_analysis['flags'].append('suspicious_parameters')
                    security_analysis['warnings'].append('URL contains redirect parameters')
                    security_analysis['reputation_score'] -= 10
                    break
        
        # Check for very long URLs (potential obfuscation)
        if len(url) > 200:
            security_analysis['flags'].append('long_url')
            security_analysis['warnings'].append('Unusually long URL (potential obfuscation)')
            security_analysis['reputation_score'] -= 10
        
        # Check for URL encoding obfuscation
        if '%' in url and url.count('%') > 5:
            security_analysis['flags'].append('url_encoding')
            security_analysis['warnings'].append('Heavy URL encoding detected')
            security_analysis['reputation_score'] -= 15
        
        # Determine final risk level based on score
        if security_analysis['reputation_score'] < 50:
            security_analysis['risk_level'] = 'high'
        elif security_analysis['reputation_score'] < 75:
            security_analysis['risk_level'] = 'medium'
        
        return security_analysis
    
    def identify_url_shortener(self, url: str) -> Optional[str]:
        """
        Identify if URL is from a known shortener service.
        
        Args:
            url: URL to check
            
        Returns:
            Shortener service name or None
        """
        domain = urlparse(url).netloc.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return self.URL_SHORTENERS.get(domain)
    
    def make_request(self, url: str, method: str = 'HEAD') -> Dict[str, Any]:
        """
        Make HTTP request with error handling.
        
        Args:
            url: URL to request
            method: HTTP method ('HEAD' or 'GET')
            
        Returns:
            Request result with response information
        """
        start_time = time.perf_counter()
        
        try:
            if method.upper() == 'HEAD':
                response = self.session.head(
                    url,
                    allow_redirects=False,
                    timeout=self.timeout
                )
            else:
                response = self.session.get(
                    url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    stream=True  # Don't download body
                )
                # Close the response to free resources
                response.close()
            
            response_time = time.perf_counter() - start_time
            
            return {
                'success': True,
                'status_code': response.status_code,
                'status_text': response.reason,
                'headers': dict(response.headers),
                'location': response.headers.get('Location'),
                'server': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type'),
                'content_length': response.headers.get('Content-Length'),
                'response_time': round(response_time * 1000, 2),  # milliseconds
                'method_used': method,
                'final_url': response.url
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': f'Request timed out after {self.timeout} seconds',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error - unable to reach the URL',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
    
    def expand_url(self, short_url: str, max_redirects: int = 10) -> Dict[str, Any]:
        """
        Expand URL by following redirects manually.
        
        Args:
            short_url: URL to expand
            max_redirects: Maximum number of redirects to follow
            
        Returns:
            Complete URL expansion analysis
        """
        if not REQUESTS_AVAILABLE:
            return {
                'error': 'requests library not available. Install with: pip install requests'
            }
        
        start_time = time.perf_counter()
        current_url = self.normalize_url(short_url)
        
        result = {
            'original_url': short_url,
            'final_url': None,
            'redirect_chain': [],
            'total_redirects': 0,
            'success': False,
            'security_analysis': {},
            'shortener_services': [],
            'performance_metrics': {
                'total_time': 0,
                'average_response_time': 0,
                'fastest_response': float('inf'),
                'slowest_response': 0
            }
        }
        
        response_times = []
        
        for redirect_count in range(max_redirects + 1):
            # Analyze current URL security
            url_security = self.analyze_url_security(current_url)
            
            # Check if it's a known URL shortener
            shortener = self.identify_url_shortener(current_url)
            if shortener and shortener not in result['shortener_services']:
                result['shortener_services'].append(shortener)
            
            # Make request (try HEAD first, fallback to GET if needed)
            request_result = self.make_request(current_url, 'HEAD')
            
            # If HEAD failed or returned 405, try GET
            if (not request_result.get('success') or 
                request_result.get('status_code') == 405):
                request_result = self.make_request(current_url, 'GET')
            
            # Record response time
            if request_result.get('response_time'):
                response_times.append(request_result['response_time'])
            
            # Add to redirect chain
            chain_entry = {
                'step': redirect_count + 1,
                'url': current_url,
                'shortener_service': shortener,
                'security_analysis': url_security,
                **request_result
            }
            
            result['redirect_chain'].append(chain_entry)
            
            # Check for errors
            if not request_result.get('success'):
                result['error'] = request_result.get('error')
                break
            
            status_code = request_result.get('status_code')
            
            # Check if this is a redirect
            if status_code in self.REDIRECT_CODES:
                location = request_result.get('location')
                
                if not location:
                    result['error'] = f'Redirect response {status_code} without Location header'
                    break
                
                # Resolve relative URLs
                if location.startswith('/'):
                    current_url = urljoin(current_url, location)
                elif location.startswith('http'):
                    current_url = location
                else:
                    # Relative URL
                    current_url = urljoin(current_url, location)
                
                result['total_redirects'] += 1
                
                # Check for redirect loops
                urls_in_chain = [entry['url'] for entry in result['redirect_chain']]
                if current_url in urls_in_chain:
                    result['error'] = f'Redirect loop detected: {current_url}'
                    break
                
            else:
                # Final destination reached
                result['final_url'] = current_url
                result['success'] = True
                break
        
        else:
            # Loop completed without break (max redirects reached)
            result['error'] = f'Maximum redirects ({max_redirects}) exceeded'
            result['final_url'] = current_url
        
        # Calculate performance metrics
        if response_times:
            result['performance_metrics'] = {
                'total_time': round(time.perf_counter() - start_time, 3),
                'average_response_time': round(sum(response_times) / len(response_times), 2),
                'fastest_response': round(min(response_times), 2),
                'slowest_response': round(max(response_times), 2),
                'total_requests': len(response_times)
            }
        
        # Overall security analysis
        all_flags = []
        all_warnings = []
        risk_levels = []
        
        for entry in result['redirect_chain']:
            security = entry.get('security_analysis', {})
            all_flags.extend(security.get('flags', []))
            all_warnings.extend(security.get('warnings', []))
            risk_levels.append(security.get('risk_level', 'low'))
        
        # Determine overall risk
        if 'high' in risk_levels:
            overall_risk = 'high'
        elif 'medium' in risk_levels:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        result['security_analysis'] = {
            'overall_risk': overall_risk,
            'unique_flags': list(set(all_flags)),
            'all_warnings': all_warnings,
            'chain_length': len(result['redirect_chain']),
            'uses_shorteners': bool(result['shortener_services']),
            'mixed_protocols': self._check_mixed_protocols(result['redirect_chain'])
        }
        
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result
    
    def _check_mixed_protocols(self, chain: List[Dict[str, Any]]) -> bool:
        """Check if redirect chain mixes HTTP and HTTPS."""
        protocols = set()
        for entry in chain:
            url = entry.get('url', '')
            if url.startswith('http://'):
                protocols.add('http')
            elif url.startswith('https://'):
                protocols.add('https')
        
        return len(protocols) > 1


def run_url_expander(short_url: str, max_redirects: int = 10) -> Dict[str, Any]:
    """
    Expand URL by following redirects and analyzing the chain.
    
    Args:
        short_url: URL to expand and analyze
        max_redirects: Maximum number of redirects to follow (default: 10)
    
    Returns:
        Dictionary with URL expansion results:
        - "original_url": the input URL
        - "final_url": final destination URL after all redirects
        - "redirect_chain": list of all URLs in the redirect chain with details
        - "total_redirects": number of redirects encountered
        - "success": boolean indicating if expansion was successful
        - "security_analysis": overall security assessment of the chain
        - "shortener_services": list of URL shortener services detected
        - "performance_metrics": timing and performance data
        - "duration": total analysis duration in seconds
        - "error": error message if expansion failed
        
        Each redirect chain entry includes:
        - step, url, status_code, headers, response_time
        - security_analysis with risk assessment
        - shortener_service identification
    """
    if not short_url or not short_url.strip():
        return {
            'original_url': short_url,
            'error': 'URL cannot be empty',
            'duration': 0
        }
    
    if max_redirects < 0 or max_redirects > 50:
        return {
            'original_url': short_url,
            'error': 'max_redirects must be between 0 and 50',
            'duration': 0
        }
    
    # Initialize URL expander
    expander = URLExpander()
    
    # Perform URL expansion
    result = expander.expand_url(short_url.strip(), max_redirects)
    
    return result


def format_url_expander_summary(result: Dict[str, Any]) -> str:
    """
    Format URL expansion results for display.
    
    Args:
        result: URL expansion result dictionary
        
    Returns:
        Formatted string with expansion information
    """
    if result.get('error'):
        return f"Error expanding {result.get('original_url', 'unknown')}: {result['error']}"
    
    lines = []
    lines.append(f"Original URL: {result.get('original_url', 'Unknown')}")
    lines.append(f"Final URL: {result.get('final_url', 'Unknown')}")
    lines.append(f"Total Redirects: {result.get('total_redirects', 0)}")
    lines.append(f"Success: {'Yes' if result.get('success') else 'No'}")
    
    # Security information
    security = result.get('security_analysis', {})
    risk_level = security.get('overall_risk', 'unknown')
    lines.append(f"Security Risk: {risk_level.upper()}")
    
    if security.get('unique_flags'):
        lines.append(f"Security Flags: {', '.join(security['unique_flags'])}")
    
    # Shortener services
    shorteners = result.get('shortener_services', [])
    if shorteners:
        lines.append(f"URL Shorteners: {', '.join(shorteners)}")
    
    # Performance metrics
    performance = result.get('performance_metrics', {})
    if performance.get('total_requests'):
        lines.append(f"Total Requests: {performance['total_requests']}")
        lines.append(f"Average Response Time: {performance.get('average_response_time', 0)}ms")
        lines.append(f"Fastest Response: {performance.get('fastest_response', 0)}ms")
        lines.append(f"Slowest Response: {performance.get('slowest_response', 0)}ms")
    
    # Warnings
    warnings = security.get('all_warnings', [])
    if warnings:
        lines.append("Security Warnings:")
        for warning in warnings[:3]:  # Show first 3
            lines.append(f"  - {warning}")
    
    lines.append(f"Analysis Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python url_expander.py <url> [max_redirects]")
        print("Example: python url_expander.py https://bit.ly/example")
        print("Example: python url_expander.py https://t.co/abcd1234 5")
        sys.exit(1)
    
    url = sys.argv[1]
    max_redirects = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    print(f"Expanding URL: {url}")
    print(f"Max redirects: {max_redirects}")
    print("-" * 80)
    
    result = run_url_expander(url, max_redirects)
    formatted_output = format_url_expander_summary(result)
    
    print(formatted_output)
    
    # Show redirect chain if requested
    if '--chain' in sys.argv and not result.get('error'):
        print(f"\nRedirect Chain:")
        print("-" * 40)
        for entry in result.get('redirect_chain', []):
            step = entry.get('step', 0)
            url = entry.get('url', 'N/A')
            status = entry.get('status_code', 'N/A')
            response_time = entry.get('response_time', 0)
            print(f"{step}. {url}")
            print(f"   Status: {status} | Response Time: {response_time}ms")
            
            shortener = entry.get('shortener_service')
            if shortener:
                print(f"   Service: {shortener}")
            
            security = entry.get('security_analysis', {})
            if security.get('flags'):
                print(f"   Flags: {', '.join(security['flags'])}")
            print()
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
