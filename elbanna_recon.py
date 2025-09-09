#!/usr/bin/env python3
"""
Elbanna Recon v1.0 - Main CLI Interface
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University
"""

import sys
import signal
import json
from typing import Dict, List, Any
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False
    try:
        import art
        ART_AVAILABLE = True
    except ImportError:
        ART_AVAILABLE = False

# Global results storage
results: List[Dict[str, Any]] = []

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Fore.YELLOW}[!] Interrupt received. Exiting gracefully...")
    print(f"{Fore.CYAN}[*] Session results saved in memory: {len(results)} operations")
    sys.exit(0)

def print_banner():
    """Display the ASCII banner and subtitle"""
    print(f"{Fore.CYAN}" + "="*80)
    
    if PYFIGLET_AVAILABLE:
        banner = pyfiglet.figlet_format("Elbanna v1.0")
        print(f"{Fore.GREEN}{banner}")
    elif ART_AVAILABLE:
        banner = art.text2art("Elbanna v1.0", font="block")
        print(f"{Fore.GREEN}{banner}")
    else:
        print(f"{Fore.GREEN}")
        print("  ███████╗██╗     ██████╗  █████╗ ███╗   ██╗███╗   ██╗ █████╗     ██╗   ██╗ ██╗    ██████╗ ")
        print("  ██╔════╝██║     ██╔══██╗██╔══██╗████╗  ██║████╗  ██║██╔══██╗    ██║   ██║███║   ██╔═████╗")
        print("  █████╗  ██║     ██████╔╝███████║██╔██╗ ██║██╔██╗ ██║███████║    ██║   ██║╚██║   ██║██╔██║")
        print("  ██╔══╝  ██║     ██╔══██╗██╔══██║██║╚██╗██║██║╚██╗██║██╔══██║    ╚██╗ ██╔╝ ██║   ████╔╝██║")
        print("  ███████╗███████╗██████╔╝██║  ██║██║ ╚████║██║ ╚████║██║  ██║     ╚████╔╝  ██║██╗╚██████╔╝")
        print("  ╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═╝      ╚═══╝   ╚═╝╚═╝ ╚═════╝ ")
    
    print(f"{Fore.YELLOW}    Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University")
    print(f"{Fore.CYAN}" + "="*80)
    print()

def display_menu():
    """Display the main menu options"""
    print(f"{Fore.CYAN}┌─── {Style.BRIGHT}RECON TOOLS{Style.RESET_ALL}{Fore.CYAN} ────────────────────────────────────────┐")
    print(f"{Fore.GREEN}│ 1.  Port Scanner          │ 2.  Subdomain Scanner      │")
    print(f"{Fore.GREEN}│ 3.  Directory Bruteforce  │ 4.  DNS Lookup             │")
    print(f"{Fore.GREEN}│ 5.  IP Geolocation        │ 6.  URL Scanner            │")
    print(f"{Fore.CYAN}├─── {Style.BRIGHT}NETWORK TOOLS{Style.RESET_ALL}{Fore.CYAN} ──────────────────────────────────────┤")
    print(f"{Fore.GREEN}│ 7.  Packet Sniffer        │ 8.  Header Analysis        │")
    print(f"{Fore.GREEN}│ 9.  Ping Sweep            │ 10. Network Mapping        │")
    print(f"{Fore.CYAN}├─── {Style.BRIGHT}UTILITIES{Style.RESET_ALL}{Fore.CYAN} ─────────────────────────────────────────┤")
    print(f"{Fore.GREEN}│ 11. Password Cracker      │ 12. EXIF Metadata          │")
    print(f"{Fore.GREEN}│ 13. Steganography Tool    │ 14. WHOIS Lookup           │")
    print(f"{Fore.CYAN}├─── {Style.BRIGHT}EXTRA{Style.RESET_ALL}{Fore.CYAN} ───────────────────────────────────────────┤")
    print(f"{Fore.GREEN}│ 15. Website Age Analysis  │ 16. User-Agent Lookup      │")
    print(f"{Fore.GREEN}│ 17. Git Reconnaissance    │ 18. URL Expander           │")
    print(f"{Fore.GREEN}│ 19. YouTube Lookup        │                            │")
    print(f"{Fore.CYAN}├─── {Style.BRIGHT}SYSTEM{Style.RESET_ALL}{Fore.CYAN} ───────────────────────────────────────────┤")
    print(f"{Fore.YELLOW}│ 20. View Results          │ 21. Save Results           │")
    print(f"{Fore.RED}│ 0.  Exit                  │                            │")
    print(f"{Fore.CYAN}└────────────────────────────────────────────────────────┘")
    print()

def pretty_print_result(result: Dict[str, Any], operation: str):
    """Pretty print operation results"""
    print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}RESULT: {operation.upper()}{Style.RESET_ALL}{Fore.CYAN} {'─' * (50 - len(operation))}┐")
    
    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, (list, dict)):
                print(f"{Fore.GREEN}│ {key}: {Fore.YELLOW}{json.dumps(value, indent=2)}")
            else:
                print(f"{Fore.GREEN}│ {key}: {Fore.YELLOW}{value}")
    else:
        print(f"{Fore.GREEN}│ Result: {Fore.YELLOW}{result}")
    
    print(f"{Fore.CYAN}└{'─' * 60}┘")
    print()

def handle_choice(choice: str):
    """Handle user menu choice and call appropriate modules"""
    global results
    
    try:
        if choice == "1":
            # Port Scanner
            print(f"{Fore.YELLOW}[*] Starting Port Scanner...")
            target = input(f"{Fore.CYAN}Enter target IP/hostname: {Fore.WHITE}")
            ports_input = input(f"{Fore.CYAN}Enter ports (comma-separated, or 'common' for common ports): {Fore.WHITE}")
            
            if ports_input.lower() == 'common':
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
            else:
                ports = [int(p.strip()) for p in ports_input.split(',')]
            
            threads = int(input(f"{Fore.CYAN}Number of threads (default 50): {Fore.WHITE}") or "50")
            timeout = float(input(f"{Fore.CYAN}Timeout in seconds (default 1.0): {Fore.WHITE}") or "1.0")
            
            try:
                from modules.port_scanner import run_port_scanner
                result = run_port_scanner(target, ports, threads, timeout)
                pretty_print_result(result, "Port Scanner")
                results.append({"tool": "port_scanner", "target": target, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Port scanner module not found. Please ensure modules/port_scanner.py exists.")
            
        elif choice == "2":
            # Subdomain Scanner
            print(f"{Fore.YELLOW}[*] Starting Subdomain Scanner...")
            domain = input(f"{Fore.CYAN}Enter domain: {Fore.WHITE}")
            wordlist = input(f"{Fore.CYAN}Enter wordlist path (default: subdomains.txt): {Fore.WHITE}") or "subdomains.txt"
            threads = int(input(f"{Fore.CYAN}Number of threads (default 20): {Fore.WHITE}") or "20")
            
            try:
                from modules.subdomain import run_subdomain_scanner
                result = run_subdomain_scanner(domain, wordlist, threads)
                pretty_print_result(result, "Subdomain Scanner")
                results.append({"tool": "subdomain_scanner", "target": domain, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Subdomain scanner module not found. Will be implemented later.")
                
        elif choice == "3":
            # Directory Bruteforce
            print(f"{Fore.YELLOW}[*] Starting Directory Bruteforce...")
            target = input(f"{Fore.CYAN}Enter target URL: {Fore.WHITE}")
            wordlist = input(f"{Fore.CYAN}Enter wordlist path (default: directories.txt): {Fore.WHITE}") or "directories.txt"
            
            try:
                from modules.dirbrute import run_directory_bruteforce
                result = run_directory_bruteforce(target, wordlist)
                pretty_print_result(result, "Directory Bruteforce")
                results.append({"tool": "directory_bruteforce", "target": target, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Directory bruteforce module not found. Will be implemented later.")
                
        elif choice == "4":
            # DNS Lookup
            print(f"{Fore.YELLOW}[*] Starting DNS Lookup...")
            domain = input(f"{Fore.CYAN}Enter domain: {Fore.WHITE}")
            record_types_input = input(f"{Fore.CYAN}Enter record types (comma-separated, default: A,AAAA,MX,TXT,NS,CNAME): {Fore.WHITE}")
            timeout_input = input(f"{Fore.CYAN}Enter timeout in seconds (default: 5): {Fore.WHITE}")
            
            try:
                from modules.dns_lookup import run_dns_lookup
                
                # Parse record types
                if record_types_input.strip():
                    record_types = [t.strip().upper() for t in record_types_input.split(',')]
                else:
                    record_types = None
                
                # Parse timeout
                try:
                    timeout = float(timeout_input) if timeout_input.strip() else 5.0
                except ValueError:
                    timeout = 5.0
                
                result = run_dns_lookup(domain, record_types=record_types, timeout=timeout)
                pretty_print_result(result, "DNS Lookup")
                results.append({"tool": "dns_lookup", "target": domain, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] DNS lookup module not found. Please install dnspython: pip install dnspython")
                
        elif choice == "5":
            # IP Geolocation
            print(f"{Fore.YELLOW}[*] Starting IP Geolocation Lookup...")
            ip_address = input(f"{Fore.CYAN}Enter IP address: {Fore.WHITE}")
            timeout_input = input(f"{Fore.CYAN}Enter timeout in seconds (default: 10): {Fore.WHITE}")
            
            try:
                from modules.ip_lookup import run_ip_lookup
                
                # Parse timeout
                try:
                    timeout = float(timeout_input) if timeout_input.strip() else 10.0
                except ValueError:
                    timeout = 10.0
                
                result = run_ip_lookup(ip_address, timeout=timeout)
                pretty_print_result(result, "IP Geolocation")
                results.append({"tool": "ip_lookup", "target": ip_address, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] IP lookup module not found. Please install requests: pip install requests")
                
        elif choice == "6":
            # URL Scanner
            print(f"{Fore.YELLOW}[*] Starting URL Scanner...")
            url = input(f"{Fore.CYAN}Enter URL to scan: {Fore.WHITE}")
            vt_api_key = input(f"{Fore.CYAN}Enter VirusTotal API key (optional, press Enter to skip): {Fore.WHITE}")
            
            try:
                from modules.url_scanner import run_url_scanner
                
                # Use API key only if provided and not empty
                api_key = vt_api_key.strip() if vt_api_key and vt_api_key.strip() else None
                
                result = run_url_scanner(url, virustotal_api_key=api_key)
                pretty_print_result(result, "URL Scanner")
                results.append({"tool": "url_scanner", "target": url, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] URL scanner module not found. Please install requests: pip install requests")
                
        elif choice == "7":
            # Packet Sniffer
            print(f"{Fore.YELLOW}[*] Starting Packet Sniffer...")
            interface = input(f"{Fore.CYAN}Enter network interface (e.g., eth0, wlan0): {Fore.WHITE}")
            filter_expr = input(f"{Fore.CYAN}Enter BPF filter (default: tcp): {Fore.WHITE}") or "tcp"
            count = int(input(f"{Fore.CYAN}Number of packets to capture (default 100): {Fore.WHITE}") or "100")
            save_pcap = input(f"{Fore.CYAN}Save to PCAP file (optional, press Enter to skip): {Fore.WHITE}") or None
            
            try:
                from modules.packet_sniffer import run_packet_sniffer
                result = run_packet_sniffer(interface, filter_expr, count, save_pcap)
                pretty_print_result(result, "Packet Sniffer")
                results.append({"tool": "packet_sniffer", "interface": interface, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Packet sniffer module not found. Please ensure modules/packet_sniffer.py exists.")
                
        elif choice == "8":
            # Header Analysis
            print(f"{Fore.YELLOW}[*] Starting HTTP Header Analysis...")
            url = input(f"{Fore.CYAN}Enter URL to analyze: {Fore.WHITE}")
            
            try:
                from modules.header_info import run_header_info, format_header_summary
                
                result = run_header_info(url)
                
                # Display formatted summary
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}HEADER ANALYSIS RESULTS{Style.RESET_ALL}{Fore.CYAN} ──────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}│ Error: {result['error']}")
                else:
                    summary = format_header_summary(result)
                    for line in summary.split('\n'):
                        if line.strip():
                            print(f"{Fore.GREEN}│ {line}")
                
                print(f"{Fore.CYAN}└{'─' * 60}┘")
                print()
                
                results.append({"tool": "header_analysis", "target": url, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Header analysis module not found. Please install requests: pip install requests")
                
        elif choice == "9":
            # Ping Sweep
            print(f"{Fore.YELLOW}[*] Starting Ping Sweep...")
            network = input(f"{Fore.CYAN}Enter network range (e.g., 192.168.1.0/24): {Fore.WHITE}")
            timeout = float(input(f"{Fore.CYAN}Enter timeout per host (default 1.0): {Fore.WHITE}") or "1.0")
            
            try:
                from modules.ping_sweep import run_ping_sweep
                result = run_ping_sweep(network, timeout)
                pretty_print_result(result, "Ping Sweep")
                results.append({"tool": "ping_sweep", "network": network, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Ping sweep module not found. Will be implemented later.")
                
        elif choice == "11":
            # Password Cracker
            print(f"{Fore.YELLOW}[*] Starting Password Cracker...")
            target_hash = input(f"{Fore.CYAN}Enter target hash: {Fore.WHITE}")
            algorithm = input(f"{Fore.CYAN}Enter hash algorithm (md5, sha1, sha256, etc.): {Fore.WHITE}")
            wordlist_path = input(f"{Fore.CYAN}Enter wordlist path: {Fore.WHITE}")
            show_progress = input(f"{Fore.CYAN}Show progress? (y/n, default y): {Fore.WHITE}").lower() != 'n'
            
            try:
                from modules.password_cracker import run_password_cracker
                result = run_password_cracker(target_hash, algorithm, wordlist_path, show_progress)
                pretty_print_result(result, "Password Cracker")
                results.append({"tool": "password_cracker", "hash": target_hash, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Password cracker module not found. Please ensure modules/password_cracker.py exists.")
                
        elif choice == "12":
            # EXIF Metadata Extraction
            print(f"{Fore.YELLOW}[*] Starting EXIF Metadata Analysis...")
            image_path = input(f"{Fore.CYAN}Enter image file path: {Fore.WHITE}")
            
            try:
                from modules.exif_metadata import run_exif_metadata, format_exif_summary
                
                result = run_exif_metadata(image_path)
                
                # Display formatted summary
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}EXIF METADATA RESULTS{Style.RESET_ALL}{Fore.CYAN} ────────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}│ Error: {result['error']}")
                else:
                    summary = format_exif_summary(result)
                    for line in summary.split('\n'):
                        if line.strip():
                            print(f"{Fore.GREEN}│ {line}")
                    
                    # Show privacy warnings if high risk
                    privacy = result.get('privacy_analysis', {})
                    if privacy.get('privacy_score', 0) > 6:
                        print(f"{Fore.RED}│ ")
                        print(f"{Fore.RED}│ ⚠️  HIGH PRIVACY RISK DETECTED!")
                        print(f"{Fore.RED}│ Consider removing metadata before sharing this image.")
                
                print(f"{Fore.CYAN}└{'─' * 64}┘")
                print()
                
                results.append({"tool": "exif_metadata", "target": image_path, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] EXIF metadata module not found. Please install: pip install Pillow exifread")
                
        elif choice == "13":
            # Steganography Tool
            print(f"{Fore.YELLOW}[*] Steganography Tool Options:")
            print(f"{Fore.GREEN}1. Encode text in image")
            print(f"{Fore.GREEN}2. Decode text from image")
            stego_choice = input(f"{Fore.CYAN}Choose option (1/2): {Fore.WHITE}")
            
            try:
                from modules.stego_tool import encode_text_in_image, decode_text_from_image
                
                if stego_choice == "1":
                    input_image = input(f"{Fore.CYAN}Enter input image path: {Fore.WHITE}")
                    output_image = input(f"{Fore.CYAN}Enter output image path: {Fore.WHITE}")
                    message = input(f"{Fore.CYAN}Enter message to hide: {Fore.WHITE}")
                    result = encode_text_in_image(input_image, output_image, message)
                    pretty_print_result(result, "Steganography Encode")
                    results.append({"tool": "steganography_encode", "result": result})
                    
                elif stego_choice == "2":
                    input_image = input(f"{Fore.CYAN}Enter image path to decode: {Fore.WHITE}")
                    result = decode_text_from_image(input_image)
                    pretty_print_result(result, "Steganography Decode")
                    results.append({"tool": "steganography_decode", "result": result})
                    
            except ImportError:
                print(f"{Fore.RED}[!] Steganography module not found. Please ensure modules/stego_tool.py exists.")
                
        elif choice == "14":
            # WHOIS Lookup
            print(f"{Fore.YELLOW}[*] Starting WHOIS Lookup...")
            domain = input(f"{Fore.CYAN}Enter domain name: {Fore.WHITE}")
            
            try:
                from modules.whois_lookup import run_whois
                result = run_whois(domain)
                pretty_print_result(result, "WHOIS Lookup")
                results.append({"tool": "whois_lookup", "target": domain, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] WHOIS lookup module not found. Please ensure modules/whois_lookup.py exists.")
                
        elif choice == "15":
            # Website Age Analysis
            print(f"{Fore.YELLOW}[*] Starting Website Age Analysis...")
            domain = input(f"{Fore.CYAN}Enter domain name: {Fore.WHITE}")
            
            try:
                from modules.website_age import run_website_age
                result = run_website_age(domain)
                pretty_print_result(result, "Website Age Analysis")
                results.append({"tool": "website_age", "target": domain, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Website age module not found. Please ensure modules/website_age.py exists.")
                
        elif choice == "16":
            # User-Agent Lookup
            print(f"{Fore.YELLOW}[*] Starting User-Agent Analysis...")
            user_agent = input(f"{Fore.CYAN}Enter User-Agent string: {Fore.WHITE}")
            
            try:
                from modules.useragent_lookup import run_useragent_lookup, format_useragent_summary
                
                result = run_useragent_lookup(user_agent)
                
                # Display formatted summary
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}USER-AGENT ANALYSIS RESULTS{Style.RESET_ALL}{Fore.CYAN} ──────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}│ Error: {result['error']}")
                else:
                    summary = format_useragent_summary(result)
                    for line in summary.split('\n'):
                        if line.strip():
                            print(f"{Fore.GREEN}│ {line}")
                    
                    # Show security warnings if high risk
                    security = result.get('security_analysis', {})
                    if security.get('risk_level') == 'high':
                        print(f"{Fore.RED}│ ")
                        print(f"{Fore.RED}│ ⚠️  HIGH SECURITY RISK DETECTED!")
                        print(f"{Fore.RED}│ This appears to be a security tool or suspicious client.")
                    elif security.get('risk_level') == 'medium':
                        print(f"{Fore.YELLOW}│ ")
                        print(f"{Fore.YELLOW}│ ⚠️  MEDIUM SECURITY RISK - Non-browser client detected.")
                
                print(f"{Fore.CYAN}└{'─' * 66}┘")
                print()
                
                results.append({"tool": "useragent_lookup", "target": user_agent[:100], "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] User-Agent lookup module not found. Please install: pip install user-agents httpagentparser")
                
        elif choice == "17":
            # Git Reconnaissance
            print(f"{Fore.YELLOW}[*] Starting Git Reconnaissance...")
            username = input(f"{Fore.CYAN}Enter username to investigate: {Fore.WHITE}")
            platform = input(f"{Fore.CYAN}Enter platform (github/gitlab, default: github): {Fore.WHITE}") or "github"
            
            try:
                from modules.git_recon import run_git_recon, format_git_recon_summary
                
                result = run_git_recon(username, platform)
                
                # Display formatted summary
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}GIT RECONNAISSANCE RESULTS{Style.RESET_ALL}{Fore.CYAN} ────────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}│ Error: {result['error']}")
                else:
                    summary = format_git_recon_summary(result)
                    for line in summary.split('\n'):
                        if line.strip():
                            print(f"{Fore.GREEN}│ {line}")
                    
                    # Show security warnings if repositories flagged
                    summary_data = result.get('summary', {})
                    security_concerns = summary_data.get('security_concerns', 0)
                    if security_concerns > 0:
                        print(f"{Fore.YELLOW}│ ")
                        print(f"{Fore.YELLOW}│ ⚠️  {security_concerns} repositories flagged for security review")
                        print(f"{Fore.YELLOW}│ Consider manual inspection of sensitive repositories")
                    
                    # Show rate limit warning if low
                    rate_limit = result.get('rate_limit_info', {})
                    remaining = rate_limit.get('remaining', 0)
                    if remaining is not None and remaining < 10:
                        print(f"{Fore.YELLOW}│ ")
                        print(f"{Fore.YELLOW}│ ⚠️  API rate limit low: {remaining} requests remaining")
                        print(f"{Fore.YELLOW}│ Consider setting GITHUB_TOKEN environment variable")
                
                print(f"{Fore.CYAN}└{'─' * 68}┘")
                print()
                
                # Show top repositories
                repositories = result.get('repositories', [])
                if repositories:
                    print(f"{Fore.CYAN}[*] Top Repositories:")
                    for i, repo in enumerate(repositories[:5], 1):  # Show top 5
                        stars = repo.get('stars', 0)
                        language = repo.get('language', 'N/A')
                        print(f"{Fore.GREEN}  {i}. {repo.get('name', 'N/A')} ({stars} ⭐, {language})")
                        if repo.get('description'):
                            desc = repo['description'][:60] + '...' if len(repo['description']) > 60 else repo['description']
                            print(f"{Fore.WHITE}     {desc}")
                    print()
                
                results.append({"tool": "git_recon", "target": f"{username}@{platform}", "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] Git reconnaissance module not found. Please install: pip install requests")
                
        elif choice == "18":
            # URL Expander
            print(f"{Fore.YELLOW}[*] Starting URL Expander...")
            short_url = input(f"{Fore.CYAN}Enter URL to expand: {Fore.WHITE}")
            max_redirects_input = input(f"{Fore.CYAN}Enter maximum redirects (default: 10): {Fore.WHITE}")
            
            try:
                from modules.url_expander import run_url_expander
                
                # Parse max_redirects
                try:
                    max_redirects = int(max_redirects_input) if max_redirects_input.strip() else 10
                    if max_redirects < 0 or max_redirects > 50:
                        max_redirects = 10
                except ValueError:
                    max_redirects = 10
                
                result = run_url_expander(short_url, max_redirects)
                
                # Pretty print results
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}URL EXPANSION RESULTS{Style.RESET_ALL}{Fore.CYAN} ─────────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}[!] Error: {result['error']}")
                else:
                    print(f"{Fore.GREEN}[+] Original URL: {result.get('original_url', 'N/A')}")
                    print(f"{Fore.GREEN}[+] Final URL: {result.get('final_url', 'N/A')}")
                    print(f"{Fore.YELLOW}[+] Total Redirects: {result.get('total_redirects', 0)}")
                    print(f"{Fore.YELLOW}[+] Success: {'Yes' if result.get('success') else 'No'}")
                    
                    # Security analysis
                    security = result.get('security_analysis', {})
                    risk_level = security.get('overall_risk', 'unknown').upper()
                    risk_color = Fore.GREEN if risk_level == 'LOW' else Fore.YELLOW if risk_level == 'MEDIUM' else Fore.RED
                    print(f"{risk_color}[+] Security Risk: {risk_level}")
                    
                    # Show flags if any
                    flags = security.get('unique_flags', [])
                    if flags:
                        print(f"{Fore.CYAN}[+] Security Flags: {', '.join(flags)}")
                    
                    # Show shortener services
                    shorteners = result.get('shortener_services', [])
                    if shorteners:
                        print(f"{Fore.CYAN}[+] URL Shorteners: {', '.join(shorteners)}")
                    
                    # Performance metrics
                    performance = result.get('performance_metrics', {})
                    if performance.get('total_requests'):
                        print(f"{Fore.MAGENTA}[+] Total Requests: {performance['total_requests']}")
                        print(f"{Fore.MAGENTA}[+] Average Response Time: {performance.get('average_response_time', 0)}ms")
                    
                    # Show warnings
                    warnings = security.get('all_warnings', [])
                    if warnings:
                        print(f"{Fore.YELLOW}[!] Security Warnings:")
                        for warning in warnings[:5]:  # Show first 5 warnings
                            print(f"    - {warning}")
                    
                    print(f"{Fore.CYAN}[+] Analysis Duration: {result.get('duration', 0):.3f}s")
                
                print(f"{Fore.CYAN}└{'─' * 60}┘")
                
                results.append({"tool": "url_expander", "target": short_url, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] URL expander module not found. Please install: pip install requests")
                
        elif choice == "19":
            # YouTube Lookup
            print(f"{Fore.YELLOW}[*] Starting YouTube Lookup...")
            youtube_url = input(f"{Fore.CYAN}Enter YouTube video or channel URL: {Fore.WHITE}")
            
            try:
                from modules.youtube_lookup import run_youtube_lookup
                
                result = run_youtube_lookup(youtube_url)
                
                # Pretty print results
                print(f"\n{Fore.CYAN}┌─── {Style.BRIGHT}YOUTUBE LOOKUP RESULTS{Style.RESET_ALL}{Fore.CYAN} ──────────────────────────────┐")
                
                if result.get('error'):
                    print(f"{Fore.RED}[!] Error: {result['error']}")
                else:
                    if result.get('title'):  # Video result
                        print(f"{Fore.GREEN}[+] Title: {result.get('title', 'N/A')}")
                        print(f"{Fore.GREEN}[+] Channel: {result.get('author_name', 'N/A')}")
                        if result.get('author_url'):
                            print(f"{Fore.CYAN}[+] Channel URL: {result.get('author_url')}")
                        
                        # Additional metadata
                        additional = result.get('additional_metadata', {})
                        if additional.get('view_count'):
                            print(f"{Fore.YELLOW}[+] Views: {additional['view_count']:,}")
                        if additional.get('duration'):
                            print(f"{Fore.YELLOW}[+] Duration: {additional['duration']}")
                        if additional.get('upload_date'):
                            print(f"{Fore.YELLOW}[+] Upload Date: {additional['upload_date']}")
                        
                        # Analysis
                        analysis = result.get('analysis', {})
                        video_quality = analysis.get('video_quality', {})
                        if video_quality.get('quality_rating'):
                            print(f"{Fore.MAGENTA}[+] Quality: {video_quality['quality_rating']}")
                        
                        content_type = analysis.get('content_type')
                        if content_type:
                            print(f"{Fore.MAGENTA}[+] Content Type: {content_type}")
                        
                        # Thumbnail
                        if result.get('thumbnail_url'):
                            print(f"{Fore.CYAN}[+] Thumbnail: {result['thumbnail_url']}")
                    
                    elif result.get('channel_name'):  # Channel result
                        print(f"{Fore.GREEN}[+] Channel Name: {result.get('channel_name', 'N/A')}")
                        
                        if result.get('subscriber_count'):
                            print(f"{Fore.YELLOW}[+] Subscribers: {result['subscriber_count']}")
                        
                        if result.get('verified'):
                            print(f"{Fore.GREEN}[+] Status: Verified ✓")
                        
                        if result.get('description'):
                            desc = result['description'][:100]
                            if len(result['description']) > 100:
                                desc += "..."
                            print(f"{Fore.CYAN}[+] Description: {desc}")
                        
                        # Analysis
                        analysis = result.get('analysis', {})
                        if analysis.get('channel_size'):
                            print(f"{Fore.MAGENTA}[+] Channel Size: {analysis['channel_size']}")
                        if analysis.get('content_focus'):
                            print(f"{Fore.MAGENTA}[+] Content Focus: {analysis['content_focus']}")
                        if analysis.get('engagement_potential'):
                            print(f"{Fore.MAGENTA}[+] Engagement: {analysis['engagement_potential']}")
                        
                        # API note
                        if result.get('api_note'):
                            print(f"{Fore.YELLOW}[!] Note: {result['api_note']}")
                    
                    print(f"{Fore.CYAN}[+] Lookup Duration: {result.get('duration', 0):.3f}s")
                
                print(f"{Fore.CYAN}└{'─' * 66}┘")
                
                results.append({"tool": "youtube_lookup", "target": youtube_url, "result": result})
            except ImportError:
                print(f"{Fore.RED}[!] YouTube lookup module not found. Please install: pip install requests")
                
        elif choice == "20":
            # View Results
            if not results:
                print(f"{Fore.YELLOW}[!] No results to display.")
            else:
                print(f"{Fore.CYAN}[*] Session Results ({len(results)} operations):")
                for i, result in enumerate(results, 1):
                    print(f"{Fore.GREEN}[{i}] {result.get('tool', 'Unknown')} - Target: {result.get('target', result.get('interface', result.get('hash', 'N/A')))}")
                    
        elif choice == "21":
            # Save Results
            if not results:
                print(f"{Fore.YELLOW}[!] No results to save.")
            else:
                output_path = input(f"{Fore.CYAN}Enter output path (default: results.json): {Fore.WHITE}") or "results.json"
                output_format = input(f"{Fore.CYAN}Enter format (json/txt/html, default: json): {Fore.WHITE}") or "json"
                
                try:
                    from modules.reports import save_results
                    result = save_results(results, output_path, output_format)
                    pretty_print_result(result, "Save Results")
                except ImportError:
                    print(f"{Fore.RED}[!] Reports module not found. Will be implemented later.")
                    # Fallback: save as JSON
                    try:
                        with open(output_path, 'w') as f:
                            json.dump(results, f, indent=2)
                        print(f"{Fore.GREEN}[+] Results saved to {output_path}")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error saving results: {e}")
                        
        elif choice == "0":
            print(f"{Fore.YELLOW}[*] Exiting Elbanna Recon v1.0...")
            print(f"{Fore.CYAN}[*] Session summary: {len(results)} operations completed")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please select a valid option.")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")

def menu_loop():
    """Main menu loop"""
    while True:
        try:
            display_menu()
            choice = input(f"{Fore.CYAN}elbanna@recon:~$ {Fore.WHITE}").strip()
            
            if choice:
                handle_choice(choice)
            else:
                continue
                
        except KeyboardInterrupt:
            signal_handler(None, None)
        except EOFError:
            print(f"\n{Fore.YELLOW}[*] EOF received. Exiting...")
            break

def main():
    """Main function"""
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        print_banner()
        print(f"{Fore.YELLOW}[*] Welcome to Elbanna Recon v1.0")
        print(f"{Fore.CYAN}[*] Modular reconnaissance and penetration testing toolkit")
        print(f"{Fore.GREEN}[*] Type your choice and press Enter. Use Ctrl+C to exit gracefully.")
        print()
        
        menu_loop()
        
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
