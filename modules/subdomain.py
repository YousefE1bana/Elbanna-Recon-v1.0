"""
Subdomain Scanner Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

Subdomain discovery using certificate transparency logs (crt.sh) and DNS brute-forcing.
"""

import os
import sys
import time
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class SubdomainScanner:
    """
    Comprehensive subdomain discovery scanner with multiple methods.
    """
    
    def __init__(self, domain: str, threads: int = 50, max_results: int = 500):
        """
        Initialize the subdomain scanner.
        
        Args:
            domain: Target domain to scan
            threads: Number of threads for concurrent operations
            max_results: Maximum number of results to return
        """
        self.domain = domain.lower().strip()
        self.threads = threads
        self.max_results = max_results
        self.found_subdomains = set()
        self.results = []
        self.lock = threading.Lock()
        
        # Configure session for HTTP requests
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            self.session.timeout = 5
    
    def normalize_domain(self, subdomain: str) -> str:
        """
        Normalize subdomain format.
        
        Args:
            subdomain: Raw subdomain string
            
        Returns:
            Normalized subdomain
        """
        subdomain = subdomain.lower().strip()
        
        # Remove protocol if present
        if subdomain.startswith(('http://', 'https://')):
            subdomain = urlparse(subdomain).hostname or subdomain
        
        # Remove trailing dots
        subdomain = subdomain.rstrip('.')
        
        # Remove wildcards
        if subdomain.startswith('*.'):
            subdomain = subdomain[2:]
        
        return subdomain
    
    def is_valid_subdomain(self, subdomain: str) -> bool:
        """
        Validate if subdomain is valid and belongs to target domain.
        
        Args:
            subdomain: Subdomain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not subdomain or len(subdomain) > 253:
            return False
        
        # Must end with target domain
        if not subdomain.endswith(self.domain):
            return False
        
        # Basic character validation
        allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if not all(c in allowed_chars for c in subdomain):
            return False
        
        # Must not be the root domain itself
        if subdomain == self.domain:
            return False
        
        return True
    
    def query_crtsh(self) -> Set[str]:
        """
        Query crt.sh certificate transparency logs for subdomains.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        if not REQUESTS_AVAILABLE:
            return subdomains
        
        try:
            print(f"[*] Querying crt.sh for {self.domain}")
            
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            certificates = response.json()
            
            for cert in certificates:
                if isinstance(cert, dict) and 'name_value' in cert:
                    names = cert['name_value'].split('\n')
                    for name in names:
                        normalized = self.normalize_domain(name)
                        if self.is_valid_subdomain(normalized):
                            subdomains.add(normalized)
                            
                            # Stop if we have enough results
                            if len(subdomains) >= self.max_results:
                                break
                
                if len(subdomains) >= self.max_results:
                    break
            
            print(f"[+] Found {len(subdomains)} subdomains from crt.sh")
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Error querying crt.sh: {e}")
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing crt.sh response: {e}")
        except Exception as e:
            print(f"[!] Unexpected error in crt.sh query: {e}")
        
        return subdomains
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """
        Load subdomain wordlist from file.
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            List of subdomain prefixes
        """
        subdomains = []
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and not subdomain.startswith('#'):
                        # Create full subdomain
                        full_subdomain = f"{subdomain}.{self.domain}"
                        if self.is_valid_subdomain(full_subdomain):
                            subdomains.append(full_subdomain)
                            
                            # Limit wordlist size
                            if len(subdomains) >= self.max_results:
                                break
        
        except Exception as e:
            print(f"[!] Error loading wordlist {wordlist_path}: {e}")
        
        return subdomains
    
    def resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """
        Resolve subdomain to IP address using DNS.
        
        Args:
            subdomain: Subdomain to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        if not DNS_AVAILABLE:
            # Fallback to socket resolution
            try:
                return socket.gethostbyname(subdomain)
            except socket.gaierror:
                return None
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            answers = resolver.resolve(subdomain, 'A')
            return str(answers[0])
            
        except (dns.exception.DNSException, Exception):
            return None
    
    def check_subdomain_alive(self, subdomain: str, ip: str) -> Dict[str, Any]:
        """
        Check if subdomain is alive by attempting HTTP/HTTPS requests.
        
        Args:
            subdomain: Subdomain to check
            ip: IP address of subdomain
            
        Returns:
            Dictionary with alive status and details
        """
        result = {
            'subdomain': subdomain,
            'ip': ip,
            'alive': False,
            'status_code': None,
            'protocol': None,
            'redirect': None
        }
        
        if not REQUESTS_AVAILABLE:
            result['alive'] = ip is not None  # Just check if it resolves
            return result
        
        # Try HTTPS first, then HTTP
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{subdomain}"
                response = self.session.head(url, timeout=5, allow_redirects=False)
                
                result['alive'] = True
                result['status_code'] = response.status_code
                result['protocol'] = protocol
                
                # Check for redirects
                if response.status_code in [301, 302, 303, 307, 308]:
                    result['redirect'] = response.headers.get('Location')
                
                break  # Success, no need to try other protocol
                
            except requests.exceptions.RequestException:
                continue  # Try next protocol
        
        return result
    
    def scan_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Complete scan of a single subdomain (resolve + alive check).
        
        Args:
            subdomain: Subdomain to scan
            
        Returns:
            Scan result dictionary or None if invalid
        """
        # Resolve subdomain
        ip = self.resolve_subdomain(subdomain)
        if not ip:
            return None
        
        # Check if alive
        result = self.check_subdomain_alive(subdomain, ip)
        
        with self.lock:
            self.found_subdomains.add(subdomain)
        
        return result
    
    def brute_force_dns(self, wordlist_path: str) -> List[Dict[str, Any]]:
        """
        Perform DNS brute-force using wordlist.
        
        Args:
            wordlist_path: Path to subdomain wordlist
            
        Returns:
            List of found subdomains with details
        """
        results = []
        
        if not wordlist_path or not os.path.exists(wordlist_path):
            print(f"[!] Wordlist not found: {wordlist_path}")
            return results
        
        print(f"[*] Loading wordlist from {wordlist_path}")
        subdomains = self.load_wordlist(wordlist_path)
        
        if not subdomains:
            print(f"[!] No valid subdomains loaded from wordlist")
            return results
        
        print(f"[*] Starting DNS brute-force with {len(subdomains)} subdomains")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.scan_subdomain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            completed = 0
            for future in as_completed(future_to_subdomain):
                completed += 1
                
                # Progress update
                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(subdomains)} subdomains checked")
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"[+] Found: {result['subdomain']} -> {result['ip']}")
                        
                        # Stop if we have enough results
                        if len(results) >= self.max_results:
                            print(f"[*] Reached maximum results limit ({self.max_results})")
                            break
                            
                except Exception as e:
                    subdomain = future_to_subdomain[future]
                    print(f"[!] Error scanning {subdomain}: {e}")
        
        return results
    
    def get_default_wordlist(self) -> Optional[str]:
        """
        Try to find a default subdomain wordlist.
        
        Returns:
            Path to default wordlist or None
        """
        # Common wordlist locations
        possible_paths = [
            "subdomains.txt",
            "wordlists/subdomains.txt",
            "/usr/share/wordlists/subdomains.txt",
            "Tools/subdomain_wordlist.txt"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def create_default_wordlist(self, path: str) -> bool:
        """
        Create a basic subdomain wordlist.
        
        Args:
            path: Path where to create the wordlist
            
        Returns:
            True if successful, False otherwise
        """
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test', 'stage',
            'staging', 'app', 'apps', 'web', 'secure', 'vpn', 'remote', 'proxy',
            'gateway', 'portal', 'dashboard', 'panel', 'control', 'manage',
            'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
            'cdn', 'static', 'media', 'images', 'img', 'upload', 'download',
            'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'webmail',
            'beta', 'alpha', 'demo', 'sandbox', 'lab', 'research',
            'mobile', 'm', 'wap', 'old', 'new', 'v2', 'v3',
            'db', 'database', 'sql', 'mysql', 'postgres', 'oracle',
            'backup', 'bak', 'old', 'temp', 'tmp', 'cache',
            'login', 'auth', 'sso', 'ldap', 'ad', 'directory'
        ]
        
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                for subdomain in common_subdomains:
                    f.write(f"{subdomain}\n")
            return True
        except Exception as e:
            print(f"[!] Error creating default wordlist: {e}")
            return False


def run_subdomain_scanner(domain: str, wordlist: Optional[str] = None, threads: int = 50, 
                         use_crtsh: bool = True, max_results: int = 500) -> Dict[str, Any]:
    """
    Comprehensive subdomain discovery using multiple methods.
    
    Args:
        domain: Target domain to scan
        wordlist: Path to subdomain wordlist (optional)
        threads: Number of threads for concurrent operations
        use_crtsh: Whether to query crt.sh certificate transparency logs
        max_results: Maximum number of results to return
    
    Returns:
        Dictionary with scan results:
        - "domain": target domain
        - "subdomains": list of discovered subdomains with details
        - "total_found": total number of subdomains found
        - "methods_used": list of discovery methods used
        - "duration": scan duration in seconds
        - "error": error message or None
    """
    start_time = time.perf_counter()
    
    # Validate inputs
    if not domain or not domain.strip():
        return {
            'domain': domain,
            'subdomains': [],
            'total_found': 0,
            'methods_used': [],
            'duration': 0,
            'error': 'Domain cannot be empty'
        }
    
    # Check dependencies
    missing_deps = []
    if not REQUESTS_AVAILABLE:
        missing_deps.append('requests')
    if not DNS_AVAILABLE:
        missing_deps.append('dnspython')
    
    if missing_deps:
        return {
            'domain': domain,
            'subdomains': [],
            'total_found': 0,
            'methods_used': [],
            'duration': time.perf_counter() - start_time,
            'error': f'Missing dependencies: {", ".join(missing_deps)}. Install with: pip install {" ".join(missing_deps)}'
        }
    
    try:
        # Initialize scanner
        scanner = SubdomainScanner(domain, threads, max_results)
        methods_used = []
        all_results = []
        
        print(f"[*] Starting subdomain discovery for {domain}")
        print(f"[*] Max results: {max_results}, Threads: {threads}")
        
        # Method 1: Certificate Transparency (crt.sh)
        if use_crtsh:
            print(f"\n[*] Method 1: Certificate Transparency (crt.sh)")
            crtsh_subdomains = scanner.query_crtsh()
            
            if crtsh_subdomains:
                methods_used.append('crt.sh')
                
                # Scan found subdomains
                print(f"[*] Scanning {len(crtsh_subdomains)} subdomains from crt.sh")
                
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = [
                        executor.submit(scanner.scan_subdomain, subdomain)
                        for subdomain in list(crtsh_subdomains)[:max_results]
                    ]
                    
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                all_results.append(result)
                        except Exception as e:
                            print(f"[!] Error in crt.sh scan: {e}")
        
        # Method 2: DNS Brute-force
        if wordlist or scanner.get_default_wordlist():
            print(f"\n[*] Method 2: DNS Brute-force")
            
            if not wordlist:
                wordlist = scanner.get_default_wordlist()
                if not wordlist:
                    # Create default wordlist
                    default_path = "subdomains.txt"
                    if scanner.create_default_wordlist(default_path):
                        wordlist = default_path
                        print(f"[+] Created default wordlist: {default_path}")
            
            if wordlist:
                methods_used.append('dns_bruteforce')
                bruteforce_results = scanner.brute_force_dns(wordlist)
                
                # Merge results, avoiding duplicates
                existing_subdomains = {r['subdomain'] for r in all_results}
                for result in bruteforce_results:
                    if result['subdomain'] not in existing_subdomains:
                        all_results.append(result)
        
        # Remove duplicates and sort results
        unique_results = []
        seen_subdomains = set()
        
        for result in all_results:
            if result['subdomain'] not in seen_subdomains:
                seen_subdomains.add(result['subdomain'])
                unique_results.append(result)
        
        # Sort by subdomain name
        unique_results.sort(key=lambda x: x['subdomain'])
        
        # Limit results
        if len(unique_results) > max_results:
            unique_results = unique_results[:max_results]
        
        duration = time.perf_counter() - start_time
        
        print(f"\n[+] Subdomain discovery completed!")
        print(f"[+] Found {len(unique_results)} unique subdomains")
        print(f"[+] Methods used: {', '.join(methods_used)}")
        print(f"[+] Duration: {duration:.2f} seconds")
        
        # Count alive subdomains
        alive_count = sum(1 for r in unique_results if r['alive'])
        print(f"[+] Alive subdomains: {alive_count}/{len(unique_results)}")
        
        return {
            'domain': domain,
            'subdomains': unique_results,
            'total_found': len(unique_results),
            'alive_count': alive_count,
            'methods_used': methods_used,
            'duration': round(duration, 3),
            'error': None
        }
    
    except Exception as e:
        return {
            'domain': domain,
            'subdomains': [],
            'total_found': 0,
            'methods_used': [],
            'duration': time.perf_counter() - start_time,
            'error': f'Scan failed: {str(e)}'
        }


if __name__ == "__main__":
    # Example usage and testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Elbanna Subdomain Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--no-crtsh", action="store_true", help="Disable crt.sh queries")
    parser.add_argument("-m", "--max", type=int, default=500, help="Maximum results")
    parser.add_argument("-o", "--output", help="Output file for results")
    
    args = parser.parse_args()
    
    print("Elbanna Subdomain Scanner v1.0")
    print("="*40)
    
    result = run_subdomain_scanner(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        use_crtsh=not args.no_crtsh,
        max_results=args.max
    )
    
    print("\nScan Results:")
    print("="*40)
    
    if result['error']:
        print(f"Error: {result['error']}")
    else:
        print(f"Domain: {result['domain']}")
        print(f"Total Found: {result['total_found']}")
        print(f"Alive: {result.get('alive_count', 0)}")
        print(f"Methods: {', '.join(result['methods_used'])}")
        print(f"Duration: {result['duration']} seconds")
        
        if result['subdomains']:
            print(f"\nDiscovered Subdomains:")
            print("-" * 60)
            for sub in result['subdomains'][:20]:  # Show first 20
                status = "✓" if sub['alive'] else "✗"
                protocol = f" ({sub['protocol']})" if sub.get('protocol') else ""
                status_code = f" [{sub['status_code']}]" if sub.get('status_code') else ""
                print(f"{status} {sub['subdomain']} -> {sub['ip']}{protocol}{status_code}")
            
            if len(result['subdomains']) > 20:
                print(f"... and {len(result['subdomains']) - 20} more")
        
        # Save results if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nResults saved to: {args.output}")
            except Exception as e:
                print(f"Error saving results: {e}")
