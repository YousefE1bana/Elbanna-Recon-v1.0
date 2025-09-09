#!/usr/bin/env python3
"""
IP Lookup Module for Elbanna Recon v1.0

This module provides IP geolocation and ASN information lookup using public APIs.
Features:
- IP geolocation using ip-api.com
- ASN (Autonomous System Number) information
- ISP and organization details
- Reverse DNS lookup fallback
- Rate limiting awareness
- Comprehensive error handling

Author: Yousef Osama
"""

import socket
import time
import ipaddress
from typing import Dict, Any, Optional

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class IPLookup:
    """
    IP geolocation and information lookup engine.
    """
    
    # API configuration
    API_BASE_URL = "http://ip-api.com/json"
    API_FIELDS = "status,country,regionName,city,isp,org,as,query,lat,lon,timezone"
    API_TIMEOUT = 10  # seconds
    RATE_LIMIT_DELAY = 1.5  # seconds between requests
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the IP lookup engine.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.last_request_time = 0
    
    def validate_ip(self, ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid IP address, False otherwise
        """
        try:
            # Parse as IPv4 or IPv6
            ipaddress.ip_address(ip.strip())
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def respect_rate_limit(self):
        """
        Implement basic rate limiting to avoid being blocked by the API.
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.RATE_LIMIT_DELAY:
            sleep_time = self.RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with reverse DNS information
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                'ip': ip,
                'hostname': hostname,
                'method': 'reverse_dns',
                'error': None
            }
        except (socket.herror, socket.gaierror, OSError) as e:
            return {
                'ip': ip,
                'hostname': None,
                'method': 'reverse_dns',
                'error': f'Reverse DNS lookup failed: {str(e)}'
            }
    
    def api_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform IP lookup using ip-api.com service.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with geolocation and ASN information
        """
        if not REQUESTS_AVAILABLE:
            return {
                'ip': ip,
                'error': 'requests library not available. Install with: pip install requests',
                'method': 'api_lookup'
            }
        
        # Respect rate limiting
        self.respect_rate_limit()
        
        # Construct API URL
        url = f"{self.API_BASE_URL}/{ip}"
        params = {
            'fields': self.API_FIELDS
        }
        
        try:
            # Make API request
            response = requests.get(
                url, 
                params=params, 
                timeout=self.timeout,
                headers={
                    'User-Agent': 'Elbanna-Recon-v1.0'
                }
            )
            
            # Check response status
            response.raise_for_status()
            
            # Parse JSON response
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'ip': data.get('query', ip),
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'asn': data.get('as'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'method': 'api_lookup',
                    'error': None
                }
            else:
                # API returned failure status
                error_msg = data.get('message', 'Unknown API error')
                return {
                    'ip': ip,
                    'error': f'API lookup failed: {error_msg}',
                    'method': 'api_lookup'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'ip': ip,
                'error': f'Network error: {str(e)}',
                'method': 'api_lookup'
            }
        except ValueError as e:
            return {
                'ip': ip,
                'error': f'JSON parsing error: {str(e)}',
                'method': 'api_lookup'
            }
        except Exception as e:
            return {
                'ip': ip,
                'error': f'Unexpected error: {str(e)}',
                'method': 'api_lookup'
            }
    
    def comprehensive_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform comprehensive IP lookup with API and fallback methods.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Dictionary with all available IP information
        """
        start_time = time.perf_counter()
        
        # Validate IP address
        if not self.validate_ip(ip):
            return {
                'ip': ip,
                'error': 'Invalid IP address format',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        # Try API lookup first
        result = self.api_lookup(ip)
        
        # If API lookup failed, try reverse DNS as fallback
        if result.get('error'):
            dns_result = self.reverse_dns_lookup(ip)
            
            # Combine results
            result.update({
                'hostname': dns_result.get('hostname'),
                'fallback_method': 'reverse_dns',
                'api_error': result.get('error')
            })
            
            # If reverse DNS worked, update error status
            if not dns_result.get('error'):
                result['error'] = f"API failed, fallback to reverse DNS successful"
        else:
            # API worked, also try to get hostname via reverse DNS
            dns_result = self.reverse_dns_lookup(ip)
            if not dns_result.get('error'):
                result['hostname'] = dns_result.get('hostname')
        
        # Add timing information
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result


def run_ip_lookup(ip: str, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Lookup IP geolocation and ASN information using public APIs.
    
    Args:
        ip: IP address to lookup
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with IP lookup results:
        - "ip": IP address queried
        - "country": Country name
        - "region": Region/state name
        - "city": City name
        - "isp": Internet Service Provider
        - "organization": Organization name
        - "asn": Autonomous System Number information
        - "latitude": Geographic latitude
        - "longitude": Geographic longitude
        - "timezone": Timezone information
        - "hostname": Reverse DNS hostname (if available)
        - "method": Lookup method used
        - "duration": Lookup duration in seconds
        - "error": Error message or None
    """
    if not ip or not ip.strip():
        return {
            'ip': ip,
            'error': 'IP address cannot be empty',
            'duration': 0
        }
    
    # Initialize IP lookup engine
    ip_lookup = IPLookup(timeout=timeout)
    
    # Perform comprehensive lookup
    result = ip_lookup.comprehensive_lookup(ip.strip())
    
    return result


def format_ip_info(result: Dict[str, Any]) -> str:
    """
    Format IP lookup results for display.
    
    Args:
        result: IP lookup result dictionary
        
    Returns:
        Formatted string with IP information
    """
    if result.get('error'):
        return f"Error looking up {result.get('ip', 'unknown')}: {result['error']}"
    
    lines = []
    lines.append(f"IP Address: {result.get('ip', 'Unknown')}")
    
    if result.get('hostname'):
        lines.append(f"Hostname: {result['hostname']}")
    
    if result.get('country'):
        location_parts = []
        if result.get('city'):
            location_parts.append(result['city'])
        if result.get('region'):
            location_parts.append(result['region'])
        if result.get('country'):
            location_parts.append(result['country'])
        
        if location_parts:
            lines.append(f"Location: {', '.join(location_parts)}")
    
    if result.get('latitude') and result.get('longitude'):
        lines.append(f"Coordinates: {result['latitude']}, {result['longitude']}")
    
    if result.get('timezone'):
        lines.append(f"Timezone: {result['timezone']}")
    
    if result.get('isp'):
        lines.append(f"ISP: {result['isp']}")
    
    if result.get('organization'):
        lines.append(f"Organization: {result['organization']}")
    
    if result.get('asn'):
        lines.append(f"ASN: {result['asn']}")
    
    lines.append(f"Lookup Method: {result.get('method', 'unknown')}")
    lines.append(f"Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ip_lookup.py <ip_address> [timeout]")
        print("Example: python ip_lookup.py 8.8.8.8")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    
    print(f"Looking up IP: {ip_address}")
    print("-" * 50)
    
    result = run_ip_lookup(ip_address, timeout)
    formatted_output = format_ip_info(result)
    
    print(formatted_output)
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2))
