#!/usr/bin/env python3
"""
User-Agent Lookup Module for Elbanna Recon v1.0

This module provides comprehensive User-Agent string parsing and analysis.
Features:
- Multiple parsing library support (user-agents, httpagentparser)
- Browser detection and version extraction
- Operating system identification
- Device type classification
- Security analysis of User-Agent strings
- Fallback to manual parsing when libraries unavailable

Author: Yousef Osama
"""

import re
import time
from typing import Dict, Any, Optional, Tuple
from urllib.parse import unquote

# Try to import User-Agent parsing libraries
USER_AGENTS_AVAILABLE = False
HTTPAGENTPARSER_AVAILABLE = False

try:
    from user_agents import parse as ua_parse
    USER_AGENTS_AVAILABLE = True
except ImportError:
    pass

try:
    import httpagentparser
    HTTPAGENTPARSER_AVAILABLE = True
except ImportError:
    pass


class UserAgentAnalyzer:
    """
    User-Agent string analysis and information extraction engine.
    """
    
    # Common browser patterns for manual parsing
    BROWSER_PATTERNS = {
        'chrome': r'Chrome/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'firefox': r'Firefox/([0-9]+\.[0-9]+)',
        'safari': r'Version/([0-9]+\.[0-9]+)[^0-9]*Safari',
        'edge': r'Edg/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'opera': r'OPR/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'internet_explorer': r'MSIE ([0-9]+\.[0-9]+)',
        'internet_explorer_11': r'Trident.*rv:([0-9]+\.[0-9]+)',
        'chromium': r'Chromium/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'vivaldi': r'Vivaldi/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'brave': r'Brave/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'yandex': r'YaBrowser/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'uc_browser': r'UCBrowser/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'samsung_internet': r'SamsungBrowser/([0-9]+\.[0-9]+)'
    }
    
    # Operating system patterns
    OS_PATTERNS = {
        'windows_11': r'Windows NT 10\.0.*(?:Win64|WOW64)',  # Windows 11 uses NT 10.0
        'windows_10': r'Windows NT 10\.0',
        'windows_8_1': r'Windows NT 6\.3',
        'windows_8': r'Windows NT 6\.2',
        'windows_7': r'Windows NT 6\.1',
        'windows_vista': r'Windows NT 6\.0',
        'windows_xp': r'Windows NT 5\.[12]',
        'mac_os': r'Mac OS X ([0-9]+[._][0-9]+[._]?[0-9]*)',
        'ios': r'OS ([0-9]+_[0-9]+_?[0-9]*) like Mac OS X',
        'android': r'Android ([0-9]+\.[0-9]+\.?[0-9]*)',
        'linux': r'Linux',
        'ubuntu': r'Ubuntu',
        'chromeos': r'CrOS',
        'freebsd': r'FreeBSD',
        'openbsd': r'OpenBSD',
        'netbsd': r'NetBSD'
    }
    
    # Device type patterns
    DEVICE_PATTERNS = {
        'mobile': r'Mobile|iPhone|iPod|Android.*Mobile|BlackBerry|Opera Mini',
        'tablet': r'iPad|Android(?!.*Mobile)|Tablet',
        'tv': r'TV|SmartTV|GoogleTV|AppleTV|Roku|Fire TV',
        'bot': r'bot|crawler|spider|scraper|validator|monitor|checker',
        'desktop': r'Windows|Macintosh|Linux|X11'
    }
    
    # Security-related patterns
    SECURITY_PATTERNS = {
        'automation': r'Selenium|WebDriver|PhantomJS|HeadlessChrome|automation',
        'suspicious': r'wget|curl|python-requests|libwww|urllib|httpclient',
        'crawler': r'Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot',
        'monitoring': r'Pingdom|UptimeRobot|StatusCake|Site24x7|Monitor',
        'security_scanner': r'Nmap|Nikto|Sqlmap|Burp|OWASP|ZAP|w3af'
    }
    
    def __init__(self):
        """Initialize the User-Agent analyzer."""
        self.available_libraries = []
        
        if USER_AGENTS_AVAILABLE:
            self.available_libraries.append('user-agents')
        if HTTPAGENTPARSER_AVAILABLE:
            self.available_libraries.append('httpagentparser')
    
    def clean_user_agent(self, ua: str) -> str:
        """
        Clean and normalize the User-Agent string.
        
        Args:
            ua: Raw User-Agent string
            
        Returns:
            Cleaned User-Agent string
        """
        if not ua:
            return ""
        
        # URL decode if needed
        try:
            ua = unquote(ua)
        except:
            pass
        
        # Remove excessive whitespace
        ua = ' '.join(ua.split())
        
        # Remove null bytes and control characters
        ua = ''.join(char for char in ua if ord(char) >= 32 or char in '\t\n\r')
        
        return ua.strip()
    
    def parse_with_user_agents(self, ua: str) -> Dict[str, Any]:
        """
        Parse User-Agent using the user-agents library.
        
        Args:
            ua: User-Agent string
            
        Returns:
            Parsed User-Agent information
        """
        try:
            parsed = ua_parse(ua)
            
            # Extract device type
            device_type = 'unknown'
            if parsed.is_mobile:
                device_type = 'mobile'
            elif parsed.is_tablet:
                device_type = 'tablet'
            elif parsed.is_pc:
                device_type = 'desktop'
            elif parsed.is_bot:
                device_type = 'bot'
            
            return {
                'method': 'user-agents',
                'browser_name': parsed.browser.family,
                'browser_version': parsed.browser.version_string,
                'os_name': parsed.os.family,
                'os_version': parsed.os.version_string,
                'device_type': device_type,
                'device_brand': getattr(parsed.device, 'brand', None),
                'device_model': getattr(parsed.device, 'model', None),
                'is_mobile': parsed.is_mobile,
                'is_tablet': parsed.is_tablet,
                'is_pc': parsed.is_pc,
                'is_bot': parsed.is_bot,
                'raw_info': {
                    'browser': str(parsed.browser),
                    'os': str(parsed.os),
                    'device': str(parsed.device)
                }
            }
            
        except Exception as e:
            return {
                'method': 'user-agents',
                'error': f'user-agents parsing failed: {str(e)}'
            }
    
    def parse_with_httpagentparser(self, ua: str) -> Dict[str, Any]:
        """
        Parse User-Agent using the httpagentparser library.
        
        Args:
            ua: User-Agent string
            
        Returns:
            Parsed User-Agent information
        """
        try:
            parsed = httpagentparser.detect(ua)
            
            # Extract information from httpagentparser result
            browser_info = parsed.get('browser', {})
            os_info = parsed.get('os', {})
            platform_info = parsed.get('platform', {})
            
            # Determine device type from platform
            device_type = 'unknown'
            platform_name = platform_info.get('name', '').lower()
            
            if any(mobile in platform_name for mobile in ['iphone', 'android', 'mobile']):
                device_type = 'mobile'
            elif 'ipad' in platform_name or 'tablet' in platform_name:
                device_type = 'tablet'
            elif any(desktop in platform_name for desktop in ['windows', 'mac', 'linux']):
                device_type = 'desktop'
            elif parsed.get('bot'):
                device_type = 'bot'
            
            return {
                'method': 'httpagentparser',
                'browser_name': browser_info.get('name'),
                'browser_version': browser_info.get('version'),
                'os_name': os_info.get('name'),
                'os_version': os_info.get('version'),
                'device_type': device_type,
                'platform_name': platform_info.get('name'),
                'platform_version': platform_info.get('version'),
                'is_bot': bool(parsed.get('bot')),
                'raw_info': parsed
            }
            
        except Exception as e:
            return {
                'method': 'httpagentparser',
                'error': f'httpagentparser parsing failed: {str(e)}'
            }
    
    def manual_parse(self, ua: str) -> Dict[str, Any]:
        """
        Manual User-Agent parsing using regex patterns.
        
        Args:
            ua: User-Agent string
            
        Returns:
            Manually parsed User-Agent information
        """
        result = {
            'method': 'manual',
            'browser_name': None,
            'browser_version': None,
            'os_name': None,
            'os_version': None,
            'device_type': 'unknown',
            'confidence': 'low'
        }
        
        ua_lower = ua.lower()
        
        # Browser detection
        for browser, pattern in self.BROWSER_PATTERNS.items():
            match = re.search(pattern, ua, re.IGNORECASE)
            if match:
                result['browser_name'] = browser.replace('_', ' ').title()
                result['browser_version'] = match.group(1)
                break
        
        # OS detection
        for os_name, pattern in self.OS_PATTERNS.items():
            match = re.search(pattern, ua, re.IGNORECASE)
            if match:
                result['os_name'] = os_name.replace('_', ' ').title()
                if match.groups():
                    result['os_version'] = match.group(1).replace('_', '.')
                break
        
        # Device type detection
        for device, pattern in self.DEVICE_PATTERNS.items():
            if re.search(pattern, ua, re.IGNORECASE):
                result['device_type'] = device
                break
        
        # Special cases for better accuracy
        if 'iphone' in ua_lower:
            result['device_type'] = 'mobile'
            result['os_name'] = 'iOS'
        elif 'ipad' in ua_lower:
            result['device_type'] = 'tablet'
            result['os_name'] = 'iOS'
        elif 'android' in ua_lower:
            result['os_name'] = 'Android'
            if 'mobile' not in ua_lower and 'tablet' not in ua_lower:
                # Determine mobile vs tablet for Android
                if any(tablet_hint in ua_lower for tablet_hint in ['tablet', 'pad']):
                    result['device_type'] = 'tablet'
                else:
                    result['device_type'] = 'mobile'
        
        return result
    
    def analyze_security_aspects(self, ua: str) -> Dict[str, Any]:
        """
        Analyze security-related aspects of the User-Agent.
        
        Args:
            ua: User-Agent string
            
        Returns:
            Security analysis results
        """
        security_analysis = {
            'risk_level': 'low',
            'flags': [],
            'category': 'normal',
            'suspicious_patterns': [],
            'recommendations': []
        }
        
        ua_lower = ua.lower()
        
        # Check for automation tools
        for category, pattern in self.SECURITY_PATTERNS.items():
            matches = re.findall(pattern, ua, re.IGNORECASE)
            if matches:
                security_analysis['flags'].append(category)
                security_analysis['suspicious_patterns'].extend(matches)
        
        # Determine risk level and category
        if 'security_scanner' in security_analysis['flags']:
            security_analysis['risk_level'] = 'high'
            security_analysis['category'] = 'security_tool'
            security_analysis['recommendations'].append('Potential security scanner detected')
        elif 'automation' in security_analysis['flags']:
            security_analysis['risk_level'] = 'medium'
            security_analysis['category'] = 'automation'
            security_analysis['recommendations'].append('Automated tool detected')
        elif 'suspicious' in security_analysis['flags']:
            security_analysis['risk_level'] = 'medium'
            security_analysis['category'] = 'programmatic'
            security_analysis['recommendations'].append('Non-browser client detected')
        elif 'crawler' in security_analysis['flags']:
            security_analysis['risk_level'] = 'low'
            security_analysis['category'] = 'crawler'
            security_analysis['recommendations'].append('Search engine crawler')
        elif 'monitoring' in security_analysis['flags']:
            security_analysis['risk_level'] = 'low'
            security_analysis['category'] = 'monitoring'
            security_analysis['recommendations'].append('Monitoring service detected')
        
        # Check for unusual characteristics
        if len(ua) < 20:
            security_analysis['flags'].append('short_ua')
            security_analysis['recommendations'].append('Unusually short User-Agent')
        elif len(ua) > 1000:
            security_analysis['flags'].append('long_ua')
            security_analysis['recommendations'].append('Unusually long User-Agent')
        
        # Check for missing common components
        if not re.search(r'Mozilla|Opera|webkit|gecko', ua, re.IGNORECASE):
            security_analysis['flags'].append('no_engine')
            security_analysis['recommendations'].append('Missing browser engine signature')
        
        return security_analysis
    
    def get_user_agent_info(self, ua: str) -> Dict[str, Any]:
        """
        Extract comprehensive information from User-Agent string.
        
        Args:
            ua: User-Agent string
            
        Returns:
            Complete User-Agent analysis
        """
        start_time = time.perf_counter()
        
        # Clean the User-Agent string
        cleaned_ua = self.clean_user_agent(ua)
        
        if not cleaned_ua:
            return {
                'original_ua': ua,
                'error': 'Empty or invalid User-Agent string',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        result = {
            'original_ua': ua,
            'cleaned_ua': cleaned_ua,
            'length': len(cleaned_ua),
            'available_libraries': self.available_libraries,
            'parsing_attempts': []
        }
        
        # Try parsing with available libraries
        parsed_data = None
        
        # Try user-agents library first (generally more accurate)
        if USER_AGENTS_AVAILABLE:
            parsed_data = self.parse_with_user_agents(cleaned_ua)
            result['parsing_attempts'].append('user-agents')
            
            if not parsed_data.get('error'):
                result.update(parsed_data)
            else:
                result['user_agents_error'] = parsed_data['error']
        
        # Try httpagentparser if user-agents failed or unavailable
        if (not parsed_data or parsed_data.get('error')) and HTTPAGENTPARSER_AVAILABLE:
            parsed_data = self.parse_with_httpagentparser(cleaned_ua)
            result['parsing_attempts'].append('httpagentparser')
            
            if not parsed_data.get('error'):
                result.update(parsed_data)
            else:
                result['httpagentparser_error'] = parsed_data['error']
        
        # Fall back to manual parsing
        if not parsed_data or parsed_data.get('error'):
            parsed_data = self.manual_parse(cleaned_ua)
            result['parsing_attempts'].append('manual')
            result.update(parsed_data)
        
        # Perform security analysis
        security_analysis = self.analyze_security_aspects(cleaned_ua)
        result['security_analysis'] = security_analysis
        
        # Add metadata
        result['duration'] = round(time.perf_counter() - start_time, 3)
        result['success'] = not result.get('error')
        
        return result


def run_useragent_lookup(ua: str) -> Dict[str, Any]:
    """
    Parse User-Agent string to extract browser, version, OS, and device information.
    
    Args:
        ua: User-Agent string to analyze
    
    Returns:
        Dictionary with User-Agent analysis results:
        - "original_ua": original User-Agent string
        - "cleaned_ua": cleaned and normalized UA string
        - "method": parsing method used ('user-agents', 'httpagentparser', or 'manual')
        - "browser_name": browser name (e.g., 'Chrome', 'Firefox')
        - "browser_version": browser version string
        - "os_name": operating system name
        - "os_version": OS version string
        - "device_type": device category ('mobile', 'tablet', 'desktop', 'bot', 'unknown')
        - "device_brand": device manufacturer (if available)
        - "device_model": device model (if available)
        - "is_mobile": boolean indicating mobile device
        - "is_tablet": boolean indicating tablet device
        - "is_pc": boolean indicating PC/desktop
        - "is_bot": boolean indicating bot/crawler
        - "security_analysis": security assessment and flags
        - "available_libraries": list of available parsing libraries
        - "parsing_attempts": list of attempted parsing methods
        - "duration": analysis duration in seconds
        - "error": error message if parsing failed
    """
    if not ua or not ua.strip():
        return {
            'ua': ua,
            'error': 'User-Agent string cannot be empty',
            'duration': 0
        }
    
    # Initialize User-Agent analyzer
    analyzer = UserAgentAnalyzer()
    
    # Check if any parsing library is available
    if not (USER_AGENTS_AVAILABLE or HTTPAGENTPARSER_AVAILABLE):
        # Still functional with manual parsing
        pass
    
    # Perform User-Agent analysis
    result = analyzer.get_user_agent_info(ua.strip())
    
    return result


def format_useragent_summary(result: Dict[str, Any]) -> str:
    """
    Format User-Agent analysis results for display.
    
    Args:
        result: User-Agent analysis result dictionary
        
    Returns:
        Formatted string with User-Agent information
    """
    if result.get('error'):
        return f"Error analyzing User-Agent: {result['error']}"
    
    lines = []
    lines.append(f"Original UA: {result.get('original_ua', 'Unknown')[:100]}{'...' if len(result.get('original_ua', '')) > 100 else ''}")
    lines.append(f"Length: {result.get('length', 0)} characters")
    lines.append(f"Parsing Method: {result.get('method', 'Unknown')}")
    
    # Browser information
    browser = result.get('browser_name', 'Unknown')
    version = result.get('browser_version', '')
    if version:
        lines.append(f"Browser: {browser} {version}")
    else:
        lines.append(f"Browser: {browser}")
    
    # Operating system
    os_name = result.get('os_name', 'Unknown')
    os_version = result.get('os_version', '')
    if os_version:
        lines.append(f"Operating System: {os_name} {os_version}")
    else:
        lines.append(f"Operating System: {os_name}")
    
    # Device information
    device_type = result.get('device_type', 'unknown')
    lines.append(f"Device Type: {device_type.title()}")
    
    if result.get('device_brand') and result.get('device_model'):
        lines.append(f"Device: {result['device_brand']} {result['device_model']}")
    elif result.get('device_brand'):
        lines.append(f"Device Brand: {result['device_brand']}")
    
    # Device flags
    flags = []
    if result.get('is_mobile'):
        flags.append('Mobile')
    if result.get('is_tablet'):
        flags.append('Tablet')
    if result.get('is_pc'):
        flags.append('Desktop')
    if result.get('is_bot'):
        flags.append('Bot')
    
    if flags:
        lines.append(f"Device Flags: {', '.join(flags)}")
    
    # Security analysis
    security = result.get('security_analysis', {})
    if security:
        risk_level = security.get('risk_level', 'unknown')
        category = security.get('category', 'normal')
        lines.append(f"Security: {risk_level.upper()} risk - {category.title()}")
        
        if security.get('flags'):
            lines.append(f"Security Flags: {', '.join(security['flags'])}")
        
        if security.get('recommendations'):
            lines.append("Recommendations:")
            for rec in security['recommendations'][:3]:  # Show first 3
                lines.append(f"  - {rec}")
    
    # Available libraries
    libraries = result.get('available_libraries', [])
    attempts = result.get('parsing_attempts', [])
    if libraries:
        lines.append(f"Available Libraries: {', '.join(libraries)}")
    if attempts:
        lines.append(f"Parsing Attempts: {', '.join(attempts)}")
    
    lines.append(f"Analysis Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python useragent_lookup.py <user_agent_string>")
        print("Example: python useragent_lookup.py 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'")
        
        # Show some test examples
        print("\nTest User-Agent strings:")
        test_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "curl/7.68.0"
        ]
        
        for i, ua in enumerate(test_uas, 1):
            print(f"{i}. {ua[:80]}...")
        
        sys.exit(1)
    
    user_agent = ' '.join(sys.argv[1:])  # Join all arguments as UA string might have spaces
    
    print(f"Analyzing User-Agent: {user_agent[:100]}{'...' if len(user_agent) > 100 else ''}")
    print("-" * 80)
    
    result = run_useragent_lookup(user_agent)
    formatted_output = format_useragent_summary(result)
    
    print(formatted_output)
    
    # Show detailed information if requested
    if '--details' in sys.argv and not result.get('error'):
        print("\nDetailed Information:")
        print("-" * 40)
        
        if result.get('raw_info'):
            print("Raw Parser Output:")
            raw_info = result['raw_info']
            if isinstance(raw_info, dict):
                for key, value in raw_info.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {raw_info}")
        
        if result.get('security_analysis', {}).get('suspicious_patterns'):
            print(f"Suspicious Patterns: {result['security_analysis']['suspicious_patterns']}")
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
