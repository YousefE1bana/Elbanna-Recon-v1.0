"""
Packet Sniffer Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

Network packet capture and analysis using scapy with protocol detection and PCAP export.
"""

import os
import sys
import time
import platform
from typing import Dict, List, Optional, Any, Union

try:
    from scapy.all import sniff, wrpcap, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketSniffer:
    """
    Network packet sniffer with protocol analysis and PCAP export capabilities.
    """
    
    def __init__(self, interface: Optional[str] = None, filter_expr: str = "", save_pcap: Optional[str] = None):
        """
        Initialize the packet sniffer.
        
        Args:
            interface: Network interface to capture on (None for default)
            filter_expr: BPF filter expression
            save_pcap: Path to save PCAP file (optional)
        """
        self.interface = interface
        self.filter_expr = filter_expr
        self.save_pcap = save_pcap
        self.captured_packets = []
        self.packet_summaries = []
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'IPv6': 0,
            'Other': 0
        }
        self.start_time = None
        self.end_time = None
    
    def check_privileges(self) -> Optional[str]:
        """
        Check if the current process has sufficient privileges for packet capture.
        
        Returns:
            Error message if insufficient privileges, None if OK
        """
        system = platform.system().lower()
        
        if system in ['linux', 'darwin']:  # Unix-like systems
            try:
                if os.geteuid() != 0:
                    return "Root privileges required for packet capture on Unix systems. Run with sudo."
            except AttributeError:
                # geteuid not available, assume we're on Windows or have privileges
                pass
        elif system == 'windows':
            # On Windows, check if we can access raw sockets (requires admin or special privileges)
            try:
                # Try to get interfaces - this will fail without proper privileges
                interfaces = get_if_list()
                if not interfaces:
                    return "Administrator privileges may be required for packet capture on Windows."
            except Exception:
                return "Administrator privileges required for packet capture on Windows."
        
        return None
    
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        try:
            return get_if_list()
        except Exception:
            return []
    
    def select_default_interface(self) -> Optional[str]:
        """
        Select the default network interface.
        
        Returns:
            Default interface name or None
        """
        try:
            # Use scapy's default interface
            return conf.iface
        except Exception:
            # Fallback to first available interface
            interfaces = self.get_available_interfaces()
            return interfaces[0] if interfaces else None
    
    def parse_packet(self, packet) -> Dict[str, Any]:
        """
        Parse a packet and extract relevant information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet information
        """
        packet_info = {
            'timestamp': time.time(),
            'src': None,
            'dst': None,
            'sport': None,
            'dport': None,
            'protocol': 'Other',
            'payload_len': len(packet),
            'summary': packet.summary()
        }
        
        # Extract Layer 2 info
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        # Extract Layer 3 info (IP)
        if packet.haslayer(IP):
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            
            # Extract Layer 4 info
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                self.protocol_counts['TCP'] += 1
                
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
                self.protocol_counts['UDP'] += 1
                
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type
                packet_info['icmp_code'] = packet[ICMP].code
                self.protocol_counts['ICMP'] += 1
            else:
                self.protocol_counts['Other'] += 1
                
        elif packet.haslayer(IPv6):
            packet_info['protocol'] = 'IPv6'
            packet_info['src'] = packet[IPv6].src
            packet_info['dst'] = packet[IPv6].dst
            self.protocol_counts['IPv6'] += 1
            
        elif packet.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['src'] = packet[ARP].psrc
            packet_info['dst'] = packet[ARP].pdst
            packet_info['operation'] = packet[ARP].op
            self.protocol_counts['ARP'] += 1
        else:
            self.protocol_counts['Other'] += 1
        
        return packet_info
    
    def packet_callback(self, packet):
        """
        Callback function for processing captured packets.
        
        Args:
            packet: Scapy packet object
        """
        # Store the raw packet for potential PCAP export
        self.captured_packets.append(packet)
        
        # Parse and store packet summary
        packet_info = self.parse_packet(packet)
        self.packet_summaries.append(packet_info)
    
    def capture_packets(self, count: int = 50) -> Dict[str, Any]:
        """
        Capture network packets.
        
        Args:
            count: Number of packets to capture
            
        Returns:
            Dictionary with capture results
        """
        try:
            # Determine interface to use
            if not self.interface:
                self.interface = self.select_default_interface()
                if not self.interface:
                    return {
                        'error': 'No network interface available for packet capture'
                    }
            
            print(f"[*] Starting packet capture on interface: {self.interface}")
            if self.filter_expr:
                print(f"[*] Using filter: {self.filter_expr}")
            print(f"[*] Capturing {count} packets...")
            
            self.start_time = time.time()
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.filter_expr if self.filter_expr else None,
                prn=self.packet_callback,
                count=count,
                store=False  # Don't store packets in sniff result to save memory
            )
            
            self.end_time = time.time()
            
            # Save to PCAP if requested
            pcap_saved = None
            if self.save_pcap and self.captured_packets:
                try:
                    wrpcap(self.save_pcap, self.captured_packets)
                    pcap_saved = self.save_pcap
                    print(f"[+] Packets saved to: {self.save_pcap}")
                except Exception as e:
                    print(f"[!] Failed to save PCAP: {e}")
            
            duration = self.end_time - self.start_time
            
            return {
                'interface': self.interface,
                'packets_captured': len(self.captured_packets),
                'summary': dict(self.protocol_counts),
                'pcap_file': pcap_saved,
                'duration': round(duration, 2),
                'packet_details': self.packet_summaries[:10],  # First 10 packets for preview
                'error': None
            }
            
        except Exception as e:
            return {
                'interface': self.interface,
                'packets_captured': 0,
                'summary': {},
                'pcap_file': None,
                'duration': 0,
                'error': f"Capture failed: {str(e)}"
            }


def run_packet_sniffer(interface: Optional[str] = None, filter_expr: str = "", count: int = 50, save_pcap: Optional[str] = None) -> Dict[str, Any]:
    """
    Capture network packets using scapy sniff with protocol analysis.
    
    Args:
        interface: Network interface to capture on (None for default)
        filter_expr: BPF filter expression (e.g., 'tcp', 'udp', 'icmp')
        count: Number of packets to capture (default: 50)
        save_pcap: Path to save PCAP file (optional)
    
    Returns:
        Dictionary with capture results:
        - "interface": interface used
        - "packets_captured": int
        - "summary": dict counts by protocol
        - "pcap_file": path or None
        - "duration": seconds
        - "error": str|None
    """
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        return {
            'interface': interface,
            'packets_captured': 0,
            'summary': {},
            'pcap_file': None,
            'duration': 0,
            'error': 'Scapy library not installed. Install with: pip install scapy'
        }
    
    # Initialize sniffer
    sniffer = PacketSniffer(interface, filter_expr, save_pcap)
    
    # Check privileges
    privilege_error = sniffer.check_privileges()
    if privilege_error:
        return {
            'interface': interface,
            'packets_captured': 0,
            'summary': {},
            'pcap_file': None,
            'duration': 0,
            'error': privilege_error
        }
    
    # Validate count
    if count <= 0:
        return {
            'interface': interface,
            'packets_captured': 0,
            'summary': {},
            'pcap_file': None,
            'duration': 0,
            'error': 'Count must be greater than 0'
        }
    
    # Perform packet capture
    result = sniffer.capture_packets(count)
    
    return result


def get_available_interfaces() -> List[str]:
    """
    Get list of available network interfaces.
    
    Returns:
        List of interface names
    """
    if not SCAPY_AVAILABLE:
        return []
    
    try:
        return get_if_list()
    except Exception:
        return []


def validate_filter_expression(filter_expr: str) -> bool:
    """
    Validate BPF filter expression syntax (basic validation).
    
    Args:
        filter_expr: BPF filter expression
        
    Returns:
        True if expression appears valid, False otherwise
    """
    if not filter_expr:
        return True
    
    # Basic validation for common expressions
    valid_protocols = ['tcp', 'udp', 'icmp', 'arp', 'ip', 'ip6']
    valid_keywords = ['src', 'dst', 'host', 'net', 'port', 'portrange', 'and', 'or', 'not']
    
    # Simple check - if it contains only valid keywords and protocols, likely OK
    words = filter_expr.lower().split()
    for word in words:
        if not any(keyword in word for keyword in valid_protocols + valid_keywords) and not word.isdigit():
            # Check for IP addresses and ranges
            if not ('.' in word or ':' in word or '/' in word):
                return False
    
    return True


if __name__ == "__main__":
    # Example usage for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Elbanna Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-f", "--filter", default="", help="BPF filter expression")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture")
    parser.add_argument("-o", "--output", help="Output PCAP file")
    
    args = parser.parse_args()
    
    print("Elbanna Packet Sniffer v1.0")
    print("="*40)
    
    if args.interface:
        print(f"Interface: {args.interface}")
    else:
        print("Interface: Auto-detect")
    
    if args.filter:
        print(f"Filter: {args.filter}")
    
    print(f"Count: {args.count}")
    
    if args.output:
        print(f"Output: {args.output}")
    
    print("\nAvailable interfaces:")
    for iface in get_available_interfaces():
        print(f"  - {iface}")
    
    print("\nStarting capture...")
    result = run_packet_sniffer(
        interface=args.interface,
        filter_expr=args.filter,
        count=args.count,
        save_pcap=args.output
    )
    
    print("\nCapture Results:")
    print("="*40)
    
    if result['error']:
        print(f"Error: {result['error']}")
    else:
        print(f"Interface: {result['interface']}")
        print(f"Packets captured: {result['packets_captured']}")
        print(f"Duration: {result['duration']} seconds")
        
        if result['pcap_file']:
            print(f"PCAP saved: {result['pcap_file']}")
        
        print("\nProtocol Summary:")
        for protocol, count in result['summary'].items():
            if count > 0:
                print(f"  {protocol}: {count}")
        
        if 'packet_details' in result and result['packet_details']:
            print(f"\nFirst few packets:")
            for i, packet in enumerate(result['packet_details'][:5], 1):
                src = packet.get('src', 'N/A')
                dst = packet.get('dst', 'N/A')
                proto = packet.get('protocol', 'Unknown')
                print(f"  {i}. {proto}: {src} -> {dst}")
