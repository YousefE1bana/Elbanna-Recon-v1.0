"""
WHOIS Lookup Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

WHOIS domain information lookup with comprehensive parsing and multiple query methods.
"""

import os
import sys
import time
import subprocess
import re
from datetime import datetime
from typing import Dict, Any, Optional, Union, List

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import python_whois
    PYTHON_WHOIS_AVAILABLE = True
except ImportError:
    PYTHON_WHOIS_AVAILABLE = False


class WhoisLookup:
    """
    WHOIS domain information lookup with multiple query methods and parsing.
    """
    
    def __init__(self):
        """Initialize the WHOIS lookup engine."""
        self.common_date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%d-%m-%Y',
            '%d/%m/%Y',
            '%m/%d/%Y',
            '%Y/%m/%d',
            '%d.%m.%Y',
            '%Y.%m.%d',
            '%d-%b-%Y',
            '%d %b %Y',
            '%b %d %Y',
            '%Y-%b-%d',
            '%d-%B-%Y',
            '%d %B %Y',
            '%B %d %Y',
            '%Y-%B-%d'
        ]
    
    def normalize_domain(self, domain: str) -> str:
        """
        Normalize domain format for WHOIS lookup.
        
        Args:
            domain: Domain to normalize
            
        Returns:
            Normalized domain string
        """
        domain = domain.lower().strip()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove trailing dots
        domain = domain.rstrip('.')
        
        return domain
    
    def validate_domain(self, domain: str) -> bool:
        """
        Validate domain format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > 253:
            return False
        
        # Basic domain regex
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def parse_date(self, date_str: Union[str, datetime, List]) -> Optional[str]:
        """
        Parse various date formats to ISO string.
        
        Args:
            date_str: Date string, datetime object, or list of dates
            
        Returns:
            ISO formatted date string or None
        """
        if not date_str:
            return None
        
        # Handle datetime objects
        if isinstance(date_str, datetime):
            return date_str.strftime('%Y-%m-%d')
        
        # Handle lists (take first valid date)
        if isinstance(date_str, list):
            for date_item in date_str:
                result = self.parse_date(date_item)
                if result:
                    return result
            return None
        
        # Handle strings
        if not isinstance(date_str, str):
            return None
        
        date_str = date_str.strip()
        if not date_str:
            return None
        
        # Try each date format
        for fmt in self.common_date_formats:
            try:
                parsed_date = datetime.strptime(date_str, fmt)
                return parsed_date.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        # Try parsing with additional cleanup
        # Remove common prefixes/suffixes
        cleaned = re.sub(r'^\w+:\s*', '', date_str)  # Remove "Created: " etc
        cleaned = re.sub(r'\s*\([^)]*\)$', '', cleaned)  # Remove timezone info in parentheses
        cleaned = re.sub(r'\s*UTC$', '', cleaned)  # Remove UTC suffix
        cleaned = re.sub(r'\s*GMT$', '', cleaned)  # Remove GMT suffix
        
        for fmt in self.common_date_formats:
            try:
                parsed_date = datetime.strptime(cleaned, fmt)
                return parsed_date.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        return None
    
    def parse_whois_text(self, whois_text: str) -> Dict[str, Any]:
        """
        Parse raw WHOIS text to extract structured information.
        
        Args:
            whois_text: Raw WHOIS response text
            
        Returns:
            Dictionary with parsed WHOIS information
        """
        if not whois_text:
            return {}
        
        parsed = {
            'registrar': None,
            'creation_date': None,
            'expiry_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant_org': None,
            'registrant_country': None,
            'admin_email': None,
            'tech_email': None
        }
        
        lines = whois_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Split on colon
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if not value:
                    continue
                
                # Registrar patterns
                if any(pattern in key for pattern in ['registrar', 'sponsor']):
                    if not parsed['registrar']:
                        parsed['registrar'] = value
                
                # Creation date patterns
                elif any(pattern in key for pattern in ['creat', 'registered']):
                    if not parsed['creation_date']:
                        parsed['creation_date'] = self.parse_date(value)
                
                # Expiry date patterns
                elif any(pattern in key for pattern in ['expir', 'expire']):
                    if not parsed['expiry_date']:
                        parsed['expiry_date'] = self.parse_date(value)
                
                # Updated date patterns
                elif any(pattern in key for pattern in ['updat', 'modif', 'changed']):
                    if not parsed['updated_date']:
                        parsed['updated_date'] = self.parse_date(value)
                
                # Name servers
                elif any(pattern in key for pattern in ['name server', 'nserver', 'nameserver']):
                    if value not in parsed['name_servers']:
                        parsed['name_servers'].append(value)
                
                # Status
                elif 'status' in key:
                    if value not in parsed['status']:
                        parsed['status'].append(value)
                
                # Organization
                elif any(pattern in key for pattern in ['organization', 'registrant org', 'org']):
                    if not parsed['registrant_org']:
                        parsed['registrant_org'] = value
                
                # Country
                elif 'country' in key:
                    if not parsed['registrant_country']:
                        parsed['registrant_country'] = value
                
                # Admin email
                elif 'admin' in key and 'email' in key:
                    if not parsed['admin_email']:
                        parsed['admin_email'] = value
                
                # Tech email
                elif 'tech' in key and 'email' in key:
                    if not parsed['tech_email']:
                        parsed['tech_email'] = value
        
        return parsed
    
    def whois_via_library(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup using python-whois library.
        
        Args:
            domain: Domain to lookup
            
        Returns:
            Dictionary with WHOIS results
        """
        try:
            if WHOIS_AVAILABLE:
                # Use 'whois' library
                result = whois.whois(domain)
                
                return {
                    'raw_text': str(result.text) if hasattr(result, 'text') else str(result),
                    'registrar': getattr(result, 'registrar', None),
                    'creation_date': self.parse_date(getattr(result, 'creation_date', None)),
                    'expiry_date': self.parse_date(getattr(result, 'expiration_date', None)),
                    'updated_date': self.parse_date(getattr(result, 'updated_date', None)),
                    'name_servers': getattr(result, 'name_servers', []) or [],
                    'status': getattr(result, 'status', []) or [],
                    'method': 'whois_library'
                }
            
            elif PYTHON_WHOIS_AVAILABLE:
                # Use 'python-whois' library
                result = python_whois.get_whois(domain)
                
                return {
                    'raw_text': result.get('raw', ''),
                    'registrar': result.get('registrar', None),
                    'creation_date': self.parse_date(result.get('creation_date', None)),
                    'expiry_date': self.parse_date(result.get('expiration_date', None)),
                    'updated_date': self.parse_date(result.get('updated_date', None)),
                    'name_servers': result.get('name_servers', []) or [],
                    'status': result.get('status', []) or [],
                    'method': 'python_whois_library'
                }
            
            else:
                return {'error': 'No WHOIS library available'}
        
        except Exception as e:
            return {'error': f'Library WHOIS failed: {str(e)}'}
    
    def whois_via_subprocess(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup using system whois command.
        
        Args:
            domain: Domain to lookup
            
        Returns:
            Dictionary with WHOIS results
        """
        try:
            # Try to find whois command
            whois_cmd = None
            
            # Common whois command locations
            possible_cmds = ['whois', '/usr/bin/whois', '/bin/whois', 'whois.exe']
            
            for cmd in possible_cmds:
                try:
                    subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
                    whois_cmd = cmd
                    break
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            if not whois_cmd:
                return {'error': 'System whois command not found'}
            
            # Execute whois command
            result = subprocess.run(
                [whois_cmd, domain],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return {'error': f'Whois command failed: {result.stderr}'}
            
            raw_text = result.stdout
            if not raw_text.strip():
                return {'error': 'Empty WHOIS response'}
            
            # Parse the raw text
            parsed = self.parse_whois_text(raw_text)
            
            return {
                'raw_text': raw_text,
                'registrar': parsed.get('registrar'),
                'creation_date': parsed.get('creation_date'),
                'expiry_date': parsed.get('expiry_date'),
                'updated_date': parsed.get('updated_date'),
                'name_servers': parsed.get('name_servers', []),
                'status': parsed.get('status', []),
                'registrant_org': parsed.get('registrant_org'),
                'registrant_country': parsed.get('registrant_country'),
                'method': 'subprocess'
            }
        
        except subprocess.TimeoutExpired:
            return {'error': 'WHOIS lookup timed out'}
        except Exception as e:
            return {'error': f'Subprocess WHOIS failed: {str(e)}'}
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive WHOIS lookup using multiple methods.
        
        Args:
            domain: Domain to lookup
            
        Returns:
            Dictionary with WHOIS results
        """
        start_time = time.perf_counter()
        
        # Normalize and validate domain
        normalized_domain = self.normalize_domain(domain)
        
        if not self.validate_domain(normalized_domain):
            return {
                'domain': domain,
                'raw_text': '',
                'registrar': None,
                'creation_date': None,
                'expiry_date': None,
                'duration': time.perf_counter() - start_time,
                'error': 'Invalid domain format'
            }
        
        # Try library method first
        if WHOIS_AVAILABLE or PYTHON_WHOIS_AVAILABLE:
            result = self.whois_via_library(normalized_domain)
            if 'error' not in result:
                result['domain'] = domain
                result['duration'] = round(time.perf_counter() - start_time, 3)
                return result
        
        # Fallback to subprocess method
        result = self.whois_via_subprocess(normalized_domain)
        result['domain'] = domain
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result


def run_whois(domain: str) -> Dict[str, Any]:
    """
    Query and parse WHOIS information for a domain.
    
    Args:
        domain: Domain name to lookup
    
    Returns:
        Dictionary with WHOIS results:
        - "domain": original domain queried
        - "raw_text": raw WHOIS response text
        - "registrar": domain registrar name
        - "creation_date": domain creation date (ISO format)
        - "expiry_date": domain expiration date (ISO format)
        - "updated_date": last update date (ISO format)
        - "name_servers": list of name servers
        - "status": list of domain status codes
        - "duration": lookup duration in seconds
        - "error": error message or None
    """
    if not domain or not domain.strip():
        return {
            'domain': domain,
            'raw_text': '',
            'registrar': None,
            'creation_date': None,
            'expiry_date': None,
            'duration': 0,
            'error': 'Domain cannot be empty'
        }
    
    lookup_engine = WhoisLookup()
    result = lookup_engine.lookup(domain)
    
    # Ensure all required keys are present
    required_keys = ['raw_text', 'registrar', 'creation_date', 'expiry_date', 'duration', 'error']
    for key in required_keys:
        if key not in result:
            result[key] = None
    
    return result


def bulk_whois_lookup(domains: List[str], max_workers: int = 5) -> Dict[str, Any]:
    """
    Perform WHOIS lookups on multiple domains.
    
    Args:
        domains: List of domains to lookup
        max_workers: Maximum number of concurrent lookups
    
    Returns:
        Dictionary with bulk lookup results
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    start_time = time.perf_counter()
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(run_whois, domain): domain for domain in domains}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    'domain': domain,
                    'raw_text': '',
                    'registrar': None,
                    'creation_date': None,
                    'expiry_date': None,
                    'duration': 0,
                    'error': f'Lookup failed: {str(e)}'
                })
    
    # Sort results by domain name
    results.sort(key=lambda x: x.get('domain', ''))
    
    return {
        'domains': [r['domain'] for r in results],
        'results': results,
        'total_count': len(results),
        'success_count': sum(1 for r in results if not r.get('error')),
        'duration': round(time.perf_counter() - start_time, 3)
    }


def get_domain_expiry_status(domain: str) -> Dict[str, Any]:
    """
    Get domain expiration status and days until expiry.
    
    Args:
        domain: Domain to check
    
    Returns:
        Dictionary with expiry status information
    """
    result = run_whois(domain)
    
    if result.get('error') or not result.get('expiry_date'):
        return {
            'domain': domain,
            'expiry_date': None,
            'days_until_expiry': None,
            'expired': None,
            'expires_soon': None,
            'error': result.get('error', 'No expiry date found')
        }
    
    try:
        expiry_date = datetime.strptime(result['expiry_date'], '%Y-%m-%d')
        current_date = datetime.now()
        
        days_until_expiry = (expiry_date - current_date).days
        expired = days_until_expiry < 0
        expires_soon = 0 <= days_until_expiry <= 30  # Expires within 30 days
        
        return {
            'domain': domain,
            'expiry_date': result['expiry_date'],
            'days_until_expiry': days_until_expiry,
            'expired': expired,
            'expires_soon': expires_soon,
            'registrar': result.get('registrar'),
            'error': None
        }
    
    except ValueError:
        return {
            'domain': domain,
            'expiry_date': result['expiry_date'],
            'days_until_expiry': None,
            'expired': None,
            'expires_soon': None,
            'error': 'Invalid expiry date format'
        }


if __name__ == "__main__":
    # Example usage and testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Elbanna WHOIS Lookup Tool")
    parser.add_argument("domain", nargs='?', help="Domain to lookup")
    parser.add_argument("-f", "--file", help="File containing domains to lookup")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--check-expiry", action="store_true", help="Check domain expiry status")
    parser.add_argument("--bulk", action="store_true", help="Perform bulk lookup from file")
    
    args = parser.parse_args()
    
    print("Elbanna WHOIS Lookup Tool v1.0")
    print("="*40)
    
    if args.file and args.bulk:
        # Bulk lookup from file
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            print(f"Performing bulk WHOIS lookup for {len(domains)} domains...")
            result = bulk_whois_lookup(domains)
            
            print(f"\nBulk Lookup Results:")
            print(f"Total domains: {result['total_count']}")
            print(f"Successful lookups: {result['success_count']}")
            print(f"Duration: {result['duration']} seconds")
            
            for domain_result in result['results']:
                status = "✓" if not domain_result.get('error') else "✗"
                print(f"{status} {domain_result['domain']}")
                if domain_result.get('registrar'):
                    print(f"    Registrar: {domain_result['registrar']}")
                if domain_result.get('expiry_date'):
                    print(f"    Expires: {domain_result['expiry_date']}")
                if domain_result.get('error'):
                    print(f"    Error: {domain_result['error']}")
            
            # Save results if requested
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nResults saved to: {args.output}")
        
        except Exception as e:
            print(f"Error: {e}")
    
    elif args.domain:
        if args.check_expiry:
            # Check domain expiry
            result = get_domain_expiry_status(args.domain)
            
            print(f"\nDomain Expiry Status for {args.domain}:")
            print("-" * 40)
            
            if result['error']:
                print(f"Error: {result['error']}")
            else:
                print(f"Expiry Date: {result['expiry_date']}")
                print(f"Days Until Expiry: {result['days_until_expiry']}")
                print(f"Expired: {'Yes' if result['expired'] else 'No'}")
                print(f"Expires Soon: {'Yes' if result['expires_soon'] else 'No'}")
                if result['registrar']:
                    print(f"Registrar: {result['registrar']}")
        else:
            # Regular WHOIS lookup
            result = run_whois(args.domain)
            
            print(f"\nWHOIS Lookup for {args.domain}:")
            print("-" * 40)
            
            if result['error']:
                print(f"Error: {result['error']}")
            else:
                if result['registrar']:
                    print(f"Registrar: {result['registrar']}")
                if result['creation_date']:
                    print(f"Created: {result['creation_date']}")
                if result['expiry_date']:
                    print(f"Expires: {result['expiry_date']}")
                if result.get('updated_date'):
                    print(f"Updated: {result['updated_date']}")
                if result.get('name_servers'):
                    print(f"Name Servers: {', '.join(result['name_servers'])}")
                if result.get('status'):
                    print(f"Status: {', '.join(result['status'])}")
                
                print(f"\nLookup Duration: {result['duration']} seconds")
                
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(result.get('raw_text', ''))
                    print(f"Raw WHOIS data saved to: {args.output}")
    
    else:
        print("Error: Please provide a domain name or use --file for bulk lookup")
        print("Example: python whois_lookup.py example.com")
        print("         python whois_lookup.py -f domains.txt --bulk")
