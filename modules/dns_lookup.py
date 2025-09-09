"""
DNS Lookup Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

Comprehensive DNS record lookup with support for multiple record types and detailed parsing.
"""

import os
import sys
import time
from typing import Dict, List, Any, Optional, Union

try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSLookup:
    """
    DNS record lookup engine with comprehensive record type support.
    """
    
    # Common DNS record types to query
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'SRV']
    
    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None):
        """
        Initialize the DNS lookup engine.
        
        Args:
            timeout: DNS query timeout in seconds
            nameservers: Custom nameservers to use (optional)
        """
        self.timeout = timeout
        self.nameservers = nameservers
        self.resolver = None
        
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
            
            # Use reliable DNS servers by default
            if nameservers:
                self.resolver.nameservers = nameservers
            else:
                # Use Google's DNS servers for reliable resolution
                self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    
    def normalize_domain(self, domain: str) -> str:
        """
        Normalize domain format for DNS lookup.
        
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
        
        # Remove trailing dots (will be added by dnspython if needed)
        domain = domain.rstrip('.')
        
        return domain
    
    def validate_domain(self, domain: str) -> bool:
        """
        Validate domain format for DNS queries.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters
        import re
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(domain_pattern.match(domain))
    
    def format_mx_record(self, mx_record) -> str:
        """
        Format MX record data.
        
        Args:
            mx_record: MX record object from dnspython
            
        Returns:
            Formatted MX record string
        """
        try:
            priority = mx_record.preference
            exchange = str(mx_record.exchange).rstrip('.')
            return f"{priority} {exchange}"
        except Exception:
            return str(mx_record)
    
    def format_txt_record(self, txt_record) -> str:
        """
        Format TXT record data.
        
        Args:
            txt_record: TXT record object from dnspython
            
        Returns:
            Formatted TXT record string
        """
        try:
            # TXT records can have multiple strings
            strings = []
            for string in txt_record.strings:
                if isinstance(string, bytes):
                    strings.append(string.decode('utf-8', errors='ignore'))
                else:
                    strings.append(str(string))
            return ''.join(strings)
        except Exception:
            return str(txt_record)
    
    def format_soa_record(self, soa_record) -> Dict[str, Any]:
        """
        Format SOA record data.
        
        Args:
            soa_record: SOA record object from dnspython
            
        Returns:
            Dictionary with SOA record details
        """
        try:
            return {
                'mname': str(soa_record.mname).rstrip('.'),
                'rname': str(soa_record.rname).rstrip('.'),
                'serial': soa_record.serial,
                'refresh': soa_record.refresh,
                'retry': soa_record.retry,
                'expire': soa_record.expire,
                'minimum': soa_record.minimum
            }
        except Exception:
            return {'raw': str(soa_record)}
    
    def format_srv_record(self, srv_record) -> str:
        """
        Format SRV record data.
        
        Args:
            srv_record: SRV record object from dnspython
            
        Returns:
            Formatted SRV record string
        """
        try:
            priority = srv_record.priority
            weight = srv_record.weight
            port = srv_record.port
            target = str(srv_record.target).rstrip('.')
            return f"{priority} {weight} {port} {target}"
        except Exception:
            return str(srv_record)
    
    def query_record_type(self, domain: str, record_type: str) -> List[Any]:
        """
        Query a specific DNS record type for a domain.
        
        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            List of record values
        """
        if not self.resolver:
            return []
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = []
            
            for rdata in answers:
                if record_type == 'A' or record_type == 'AAAA':
                    records.append(str(rdata))
                elif record_type == 'MX':
                    records.append(self.format_mx_record(rdata))
                elif record_type == 'TXT':
                    records.append(self.format_txt_record(rdata))
                elif record_type == 'NS' or record_type == 'CNAME':
                    records.append(str(rdata).rstrip('.'))
                elif record_type == 'SOA':
                    records.append(self.format_soa_record(rdata))
                elif record_type == 'SRV':
                    records.append(self.format_srv_record(rdata))
                elif record_type == 'PTR':
                    records.append(str(rdata).rstrip('.'))
                else:
                    records.append(str(rdata))
            
            return records
            
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist
            return []
        except dns.resolver.NoAnswer:
            # Domain exists but no records of this type
            return []
        except dns.resolver.LifetimeTimeout:
            # Query timed out
            return []
        except dns.exception.DNSException:
            # Other DNS errors
            return []
        except Exception:
            # Unexpected errors
            return []
    
    def lookup_all_records(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive DNS lookup for multiple record types.
        
        Args:
            domain: Domain to lookup
            record_types: List of record types to query (default: common types)
            
        Returns:
            Dictionary with all DNS records and metadata
        """
        start_time = time.perf_counter()
        
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        # Normalize domain
        normalized_domain = self.normalize_domain(domain)
        
        # Validate domain
        if not self.validate_domain(normalized_domain):
            return {
                'domain': domain,
                'records': {},
                'total_records': 0,
                'record_types_found': [],
                'duration': time.perf_counter() - start_time,
                'error': 'Invalid domain format'
            }
        
        # Query each record type
        all_records = {}
        total_count = 0
        found_types = []
        
        for record_type in record_types:
            records = self.query_record_type(normalized_domain, record_type)
            all_records[record_type] = records
            
            if records:
                total_count += len(records)
                found_types.append(record_type)
        
        duration = time.perf_counter() - start_time
        
        return {
            'domain': domain,
            'normalized_domain': normalized_domain,
            'records': all_records,
            'total_records': total_count,
            'record_types_found': found_types,
            'nameservers_used': self.resolver.nameservers if self.resolver else [],
            'duration': round(duration, 3),
            'error': None
        }
    
    def reverse_dns_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with reverse DNS results
        """
        start_time = time.perf_counter()
        
        if not self.resolver:
            return {
                'ip_address': ip_address,
                'hostnames': [],
                'duration': time.perf_counter() - start_time,
                'error': 'DNS resolver not available'
            }
        
        try:
            # Create reverse domain name
            reversed_name = dns.reversename.from_address(ip_address)
            
            # Query PTR records
            answers = self.resolver.resolve(reversed_name, 'PTR')
            hostnames = [str(rdata).rstrip('.') for rdata in answers]
            
            return {
                'ip_address': ip_address,
                'hostnames': hostnames,
                'duration': round(time.perf_counter() - start_time, 3),
                'error': None
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'ip_address': ip_address,
                'hostnames': [],
                'duration': round(time.perf_counter() - start_time, 3),
                'error': 'No reverse DNS record found'
            }
        except Exception as e:
            return {
                'ip_address': ip_address,
                'hostnames': [],
                'duration': round(time.perf_counter() - start_time, 3),
                'error': f'Reverse DNS lookup failed: {str(e)}'
            }


def run_dns_lookup(domain: str, record_types: Optional[List[str]] = None, 
                  nameservers: Optional[List[str]] = None, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Query multiple DNS record types for a domain and return structured results.
    
    Args:
        domain: Domain name to lookup
        record_types: List of record types to query (default: A, AAAA, MX, TXT, NS, CNAME)
        nameservers: Custom nameservers to use (optional)
        timeout: Query timeout in seconds
    
    Returns:
        Dictionary with DNS lookup results:
        - "domain": original domain queried
        - "records": dict mapping record types to lists of values
            - "A": list of IPv4 addresses
            - "AAAA": list of IPv6 addresses  
            - "MX": list of mail exchange records
            - "TXT": list of text records
            - "NS": list of name servers
            - "CNAME": list of canonical names
        - "total_records": total number of records found
        - "record_types_found": list of record types that had results
        - "duration": lookup duration in seconds
        - "error": error message or None
    """
    if not DNS_AVAILABLE:
        return {
            'domain': domain,
            'records': {
                'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 'CNAME': []
            },
            'total_records': 0,
            'record_types_found': [],
            'duration': 0,
            'error': 'dnspython library not installed. Install with: pip install dnspython'
        }
    
    if not domain or not domain.strip():
        return {
            'domain': domain,
            'records': {
                'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 'CNAME': []
            },
            'total_records': 0,
            'record_types_found': [],
            'duration': 0,
            'error': 'Domain cannot be empty'
        }
    
    # Initialize DNS lookup engine
    dns_lookup = DNSLookup(timeout=timeout, nameservers=nameservers)
    
    # Perform lookup
    result = dns_lookup.lookup_all_records(domain, record_types)
    
    # Ensure all expected record types are present in results
    if 'records' in result:
        for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']:
            if record_type not in result['records']:
                result['records'][record_type] = []
    
    return result


def run_reverse_dns_lookup(ip_address: str, nameservers: Optional[List[str]] = None, 
                          timeout: float = 5.0) -> Dict[str, Any]:
    """
    Perform reverse DNS lookup for an IP address.
    
    Args:
        ip_address: IP address to lookup
        nameservers: Custom nameservers to use (optional)
        timeout: Query timeout in seconds
    
    Returns:
        Dictionary with reverse DNS results
    """
    if not DNS_AVAILABLE:
        return {
            'ip_address': ip_address,
            'hostnames': [],
            'duration': 0,
            'error': 'dnspython library not installed'
        }
    
    dns_lookup = DNSLookup(timeout=timeout, nameservers=nameservers)
    return dns_lookup.reverse_dns_lookup(ip_address)


def get_nameservers(domain: str) -> List[str]:
    """
    Get authoritative nameservers for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List of nameserver hostnames
    """
    result = run_dns_lookup(domain, record_types=['NS'])
    return result.get('records', {}).get('NS', [])


def check_dns_propagation(domain: str, nameservers: List[str], record_type: str = 'A') -> Dict[str, Any]:
    """
    Check DNS propagation across multiple nameservers.
    
    Args:
        domain: Domain to check
        nameservers: List of nameservers to query
        record_type: DNS record type to check
        
    Returns:
        Dictionary with propagation results
    """
    results = {}
    
    for ns in nameservers:
        try:
            result = run_dns_lookup(domain, record_types=[record_type], nameservers=[ns])
            records = result.get('records', {}).get(record_type, [])
            results[ns] = {
                'records': records,
                'count': len(records),
                'error': result.get('error')
            }
        except Exception as e:
            results[ns] = {
                'records': [],
                'count': 0,
                'error': str(e)
            }
    
    # Check if all nameservers return the same results
    all_records = [tuple(sorted(r['records'])) for r in results.values() if r['records']]
    propagated = len(set(all_records)) <= 1 if all_records else False
    
    return {
        'domain': domain,
        'record_type': record_type,
        'nameserver_results': results,
        'propagated': propagated,
        'total_nameservers': len(nameservers),
        'responding_nameservers': sum(1 for r in results.values() if not r['error'])
    }


if __name__ == "__main__":
    # Example usage and testing
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Elbanna DNS Lookup Tool")
    parser.add_argument("domain", nargs='?', help="Domain to lookup")
    parser.add_argument("-t", "--types", nargs='+', help="Record types to query", 
                       choices=['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR'])
    parser.add_argument("-r", "--reverse", help="Perform reverse DNS lookup for IP")
    parser.add_argument("--nameservers", nargs='+', help="Custom nameservers to use")
    parser.add_argument("--timeout", type=float, default=5.0, help="Query timeout")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--propagation", action="store_true", help="Check DNS propagation")
    
    args = parser.parse_args()
    
    print("Elbanna DNS Lookup Tool v1.0")
    print("="*40)
    
    if args.reverse:
        # Reverse DNS lookup
        print(f"Reverse DNS lookup for {args.reverse}:")
        print("-" * 40)
        
        result = run_reverse_dns_lookup(args.reverse, args.nameservers, args.timeout)
        
        if result['error']:
            print(f"Error: {result['error']}")
        else:
            print(f"IP Address: {result['ip_address']}")
            if result['hostnames']:
                print("Hostnames:")
                for hostname in result['hostnames']:
                    print(f"  - {hostname}")
            else:
                print("No reverse DNS records found")
            print(f"Duration: {result['duration']} seconds")
    
    elif args.domain:
        if args.propagation:
            # DNS propagation check
            nameservers = args.nameservers or ['8.8.8.8', '1.1.1.1', '208.67.222.222']
            record_type = args.types[0] if args.types else 'A'
            
            print(f"Checking DNS propagation for {args.domain} ({record_type} records):")
            print("-" * 60)
            
            result = check_dns_propagation(args.domain, nameservers, record_type)
            
            for ns, ns_result in result['nameserver_results'].items():
                status = "✓" if not ns_result['error'] else "✗"
                print(f"{status} {ns}: {ns_result['count']} records")
                if ns_result['records']:
                    for record in ns_result['records']:
                        print(f"    {record}")
                if ns_result['error']:
                    print(f"    Error: {ns_result['error']}")
            
            print(f"\nPropagated: {'Yes' if result['propagated'] else 'No'}")
            print(f"Responding nameservers: {result['responding_nameservers']}/{result['total_nameservers']}")
        
        else:
            # Regular DNS lookup
            print(f"DNS lookup for {args.domain}:")
            print("-" * 40)
            
            result = run_dns_lookup(
                domain=args.domain,
                record_types=args.types,
                nameservers=args.nameservers,
                timeout=args.timeout
            )
            
            if result['error']:
                print(f"Error: {result['error']}")
            else:
                print(f"Domain: {result['domain']}")
                print(f"Total records: {result['total_records']}")
                print(f"Record types found: {', '.join(result['record_types_found'])}")
                print(f"Duration: {result['duration']} seconds")
                
                for record_type, records in result['records'].items():
                    if records:
                        print(f"\n{record_type} Records:")
                        for record in records:
                            print(f"  {record}")
            
            # Save results if requested
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nResults saved to: {args.output}")
    
    else:
        print("Error: Please provide a domain name or use --reverse for reverse lookup")
        print("Example: python dns_lookup.py google.com")
        print("         python dns_lookup.py -r 8.8.8.8")
        print("         python dns_lookup.py google.com -t A MX NS")
