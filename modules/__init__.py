"""
Elbanna Recon v1.0 - Modules Package
Author: Yousef Osama - Cybersecurity Engineering, Egyptian Chinese University
Last Updated: September 8, 2025

This package contains all the core cybersecurity reconnaissance modules
for the Elbanna Recon toolkit.

Modules included:
- port_scanner: Advanced TCP/UDP port scanning
- packet_sniffer: Network traffic analysis and monitoring
- password_cracker: Hash cracking using dictionary attacks
- steganography_tool: Hidden data detection in images
- whois_lookup: Domain registration information
- dns_lookup: DNS record analysis
- subdomain: Subdomain enumeration
- ip_lookup: IP geolocation and ISP information
- website_age: Website history and creation dates
- url_scanner: URL safety analysis
- header_info: HTTP header security assessment
- exif_metadata: Image metadata extraction
- user_agent_lookup: Browser fingerprinting
- git_recon: GitHub user and repository analysis
- youtube_lookup: YouTube video and channel information
- url_expander: Short URL expansion and redirect analysis
- reports: Multi-format result saving and reporting

Usage:
    from modules import port_scanner
    from modules.whois_lookup import run_whois_lookup
    
Educational Purpose:
    These modules are designed for learning cybersecurity concepts
    and authorized security testing only. Use responsibly!
"""

__version__ = "1.0"
__author__ = "Yousef Osama"
__email__ = "your.email@example.com"
__institution__ = "Egyptian Chinese University - Cybersecurity Engineering"

# Module availability tracking
AVAILABLE_MODULES = [
    'port_scanner',
    'packet_sniffer', 
    'password_cracker',
    'steganography_tool',
    'whois_lookup',
    'dns_lookup',
    'subdomain',
    'ip_lookup',
    'website_age',
    'url_scanner',
    'header_info',
    'exif_metadata',
    'user_agent_lookup',
    'git_recon',
    'youtube_lookup',
    'url_expander',
    'reports'
]

def get_available_modules():
    """
    Get list of available modules.
    
    Returns:
        list: List of available module names
    """
    return AVAILABLE_MODULES.copy()

def check_module_availability(module_name):
    """
    Check if a specific module is available.
    
    Args:
        module_name (str): Name of the module to check
        
    Returns:
        bool: True if module is available, False otherwise
    """
    try:
        __import__(f'modules.{module_name}')
        return True
    except ImportError:
        return False

def get_module_info():
    """
    Get information about all modules.
    
    Returns:
        dict: Dictionary with module information
    """
    return {
        'version': __version__,
        'author': __author__,
        'institution': __institution__,
        'total_modules': len(AVAILABLE_MODULES),
        'modules': AVAILABLE_MODULES
    }

# Educational disclaimer
EDUCATIONAL_DISCLAIMER = """
⚠️  EDUCATIONAL USE ONLY ⚠️

This toolkit is designed for:
✅ Learning cybersecurity concepts
✅ Authorized security testing
✅ Academic research and training

DO NOT USE FOR:
❌ Unauthorized system access
❌ Malicious activities
❌ Illegal purposes

Users are responsible for ensuring their activities comply with
applicable laws and regulations.
"""

def show_disclaimer():
    """Display the educational use disclaimer."""
    print(EDUCATIONAL_DISCLAIMER)
