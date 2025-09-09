"""
Port Scanner Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

Multi-threaded TCP port scanner with service detection and progress tracking.
"""

import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any


# Common port to service mappings
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}


class PortScanner:
    """
    Multi-threaded TCP port scanner with service detection.
    """
    
    def __init__(self, target: str, timeout: float = 1.0):
        """
        Initialize the port scanner.
        
        Args:
            target: Target IP address or hostname
            timeout: Connection timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.start_time = None
        self.show_progress = False
    
    def resolve_target(self) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Returns:
            Resolved IP address or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            return None
    
    def get_service_name(self, port: int) -> Optional[str]:
        """
        Get service name for a given port.
        
        Args:
            port: Port number
            
        Returns:
            Service name or None if unknown
        """
        return COMMON_SERVICES.get(port)
    
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single port.
        
        Args:
            port: Port number to scan
            
        Returns:
            Dict with port info if open, None if closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            with self.lock:
                self.scanned_count += 1
                
                # Print progress every 100 ports if enabled
                if self.show_progress and self.scanned_count % 100 == 0:
                    print(f"[*] Scanned {self.scanned_count} ports...")
            
            if result == 0:
                service = self.get_service_name(port)
                return {
                    "port": port,
                    "service": service
                }
            
        except Exception:
            # Silently handle connection errors
            with self.lock:
                self.scanned_count += 1
            
        return None
    
    def scan_ports_threaded(self, ports: List[int], threads: int = 100) -> List[Dict[str, Any]]:
        """
        Scan multiple ports using ThreadPoolExecutor.
        
        Args:
            ports: List of port numbers to scan
            threads: Number of threads to use
            
        Returns:
            List of open port dictionaries
        """
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all port scan tasks
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])
        return open_ports


def run_port_scanner(target: str, ports: List[int], threads: int = 100, timeout: float = 1.0) -> Dict[str, Any]:
    """
    Performs a multi-threaded TCP port scan on target for the provided ports.
    
    Args:
        target: Target IP address or hostname
        ports: List of port numbers to scan
        threads: Number of threads to use (default: 100)
        timeout: Connection timeout in seconds (default: 1.0)
    
    Returns:
        Dictionary with scan results:
        - "target": target
        - "open_ports": list of {"port": int, "service": str|None}
        - "scanned": total scanned count
        - "duration": seconds float
        - "error": error message or None
    """
    start_time = time.time()
    
    try:
        # Initialize scanner
        scanner = PortScanner(target, timeout)
        scanner.start_time = start_time
        
        # Enable progress for large scans (>100 ports)
        scanner.show_progress = len(ports) > 100
        
        # Resolve target if it's a hostname
        resolved_ip = scanner.resolve_target()
        if not resolved_ip:
            return {
                "target": target,
                "open_ports": [],
                "scanned": 0,
                "duration": time.time() - start_time,
                "error": f"Could not resolve hostname: {target}"
            }
        
        # Update target to resolved IP
        scanner.target = resolved_ip
        
        # Validate port list
        if not ports:
            return {
                "target": target,
                "open_ports": [],
                "scanned": 0,
                "duration": time.time() - start_time,
                "error": "No ports provided for scanning"
            }
        
        # Filter out invalid ports
        valid_ports = [p for p in ports if 1 <= p <= 65535]
        if len(valid_ports) != len(ports):
            invalid_count = len(ports) - len(valid_ports)
            print(f"[!] Warning: Filtered out {invalid_count} invalid port(s)")
        
        if not valid_ports:
            return {
                "target": target,
                "open_ports": [],
                "scanned": 0,
                "duration": time.time() - start_time,
                "error": "No valid ports to scan (must be 1-65535)"
            }
        
        # Show scan info for large scans
        if scanner.show_progress:
            print(f"[*] Starting port scan on {target} ({resolved_ip})")
            print(f"[*] Scanning {len(valid_ports)} ports with {threads} threads")
        
        # Perform the scan
        open_ports = scanner.scan_ports_threaded(valid_ports, threads)
        
        duration = time.time() - start_time
        
        # Final progress update
        if scanner.show_progress:
            print(f"[*] Scan completed: {len(open_ports)} open ports found")
        
        return {
            "target": target,
            "resolved_ip": resolved_ip,
            "open_ports": open_ports,
            "scanned": scanner.scanned_count,
            "duration": round(duration, 2),
            "error": None
        }
    
    except Exception as e:
        return {
            "target": target,
            "open_ports": [],
            "scanned": 0,
            "duration": time.time() - start_time,
            "error": f"Scan failed: {str(e)}"
        }


def chunk_ports(ports: List[int], chunk_size: int = 1000) -> List[List[int]]:
    """
    Split a large port list into smaller chunks for processing.
    
    Args:
        ports: List of port numbers
        chunk_size: Maximum size of each chunk
        
    Returns:
        List of port lists (chunks)
    """
    chunks = []
    for i in range(0, len(ports), chunk_size):
        chunks.append(ports[i:i + chunk_size])
    return chunks


def get_common_ports() -> List[int]:
    """
    Get a list of commonly scanned ports.
    
    Returns:
        List of common port numbers
    """
    return list(COMMON_SERVICES.keys())


def get_top_ports(count: int = 1000) -> List[int]:
    """
    Get a list of the most commonly used ports.
    
    Args:
        count: Number of top ports to return
        
    Returns:
        List of port numbers
    """
    # Top 1000 ports based on nmap's frequency data
    top_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 1433, 1521, 3389, 5432, 6379,
        25565, 27017, 5984, 11211, 50000
    ]
    
    # Add sequential ports to reach desired count
    current_ports = set(top_ports)
    port = 1
    while len(current_ports) < count and port <= 65535:
        if port not in current_ports:
            top_ports.append(port)
            current_ports.add(port)
        port += 1
    
    return sorted(top_ports[:count])


if __name__ == "__main__":
    # Example usage for testing
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [ports...]")
        print("Example: python port_scanner.py google.com 80 443 22")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2:
        ports = [int(p) for p in sys.argv[2:]]
    else:
        ports = get_common_ports()
    
    print(f"Scanning {target} on ports: {ports}")
    result = run_port_scanner(target, ports, threads=50, timeout=2.0)
    
    print("\nScan Results:")
    print(f"Target: {result['target']}")
    if result['error']:
        print(f"Error: {result['error']}")
    else:
        print(f"Scanned: {result['scanned']} ports")
        print(f"Duration: {result['duration']} seconds")
        print(f"Open ports: {len(result['open_ports'])}")
        
        for port_info in result['open_ports']:
            service = port_info['service'] or 'unknown'
            print(f"  {port_info['port']}/tcp - {service}")
