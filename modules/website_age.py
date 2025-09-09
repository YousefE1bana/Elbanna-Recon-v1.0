#!/usr/bin/env python3
"""
Website Age Module for Elbanna Recon v1.0

This module determines the age of a website/domain by analyzing WHOIS data.
Features:
- Domain creation date extraction from WHOIS records
- Age calculation in days and years
- Integration with existing WHOIS lookup module
- Comprehensive date parsing and error handling
- Support for multiple date formats

Author: Yousef Osama
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
import re

# Try to import date parsing libraries
try:
    from dateutil import parser as date_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False


class WebsiteAgeCalculator:
    """
    Website age calculation engine using WHOIS data.
    """
    
    # Common date formats found in WHOIS records
    DATE_FORMATS = [
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y/%m/%d',
        '%d-%m-%Y',
        '%d/%m/%Y',
        '%d.%m.%Y',
        '%m/%d/%Y',
        '%Y.%m.%d',
        '%Y%m%d',
        '%d-%b-%Y',
        '%d %b %Y',
        '%b %d, %Y',
        '%B %d, %Y'
    ]
    
    def __init__(self):
        """Initialize the website age calculator."""
        pass
    
    def normalize_date_string(self, date_str: str) -> str:
        """
        Normalize date string by cleaning common issues.
        
        Args:
            date_str: Raw date string from WHOIS
            
        Returns:
            Cleaned date string
        """
        if not date_str or not isinstance(date_str, str):
            return ""
        
        # Clean the string
        date_str = date_str.strip()
        
        # Remove common suffixes like timezone info that can cause parsing issues
        date_str = re.sub(r'\s*\(.*?\)', '', date_str)  # Remove parentheses content
        date_str = re.sub(r'\s+UTC.*$', '', date_str)   # Remove UTC and after
        date_str = re.sub(r'\s+GMT.*$', '', date_str)   # Remove GMT and after
        date_str = re.sub(r'\s+\+\d+.*$', '', date_str) # Remove timezone offsets
        
        # Clean extra whitespace
        date_str = ' '.join(date_str.split())
        
        return date_str
    
    def parse_creation_date(self, whois_result: Dict[str, Any]) -> Optional[datetime]:
        """
        Extract and parse creation date from WHOIS result.
        
        Args:
            whois_result: Result from WHOIS lookup
            
        Returns:
            Parsed datetime object or None if parsing failed
        """
        # Try to get creation date from various possible fields
        creation_date = None
        
        # Check common field names in WHOIS data
        possible_fields = [
            'creation_date', 'created', 'registered', 'registered_date',
            'created_date', 'domain_created', 'created_on', 'registration_date'
        ]
        
        for field in possible_fields:
            if field in whois_result and whois_result[field]:
                creation_date = whois_result[field]
                break
        
        if not creation_date:
            return None
        
        # Handle case where creation_date is already a datetime object
        if isinstance(creation_date, datetime):
            return creation_date
        
        # Handle case where creation_date is a list (take first element)
        if isinstance(creation_date, list) and creation_date:
            creation_date = creation_date[0]
        
        # Convert to string for parsing
        if not isinstance(creation_date, str):
            creation_date = str(creation_date)
        
        # Normalize the date string
        creation_date = self.normalize_date_string(creation_date)
        
        if not creation_date:
            return None
        
        # Try using dateutil parser first (most flexible)
        if DATEUTIL_AVAILABLE:
            try:
                parsed_date = date_parser.parse(creation_date)
                # Convert to UTC if no timezone info
                if parsed_date.tzinfo is None:
                    parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                return parsed_date
            except (ValueError, TypeError):
                pass
        
        # Fallback to manual parsing with predefined formats
        for date_format in self.DATE_FORMATS:
            try:
                parsed_date = datetime.strptime(creation_date, date_format)
                # Add UTC timezone if none specified
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                return parsed_date
            except ValueError:
                continue
        
        # Last resort: try to extract date using regex
        date_patterns = [
            r'(\d{4})-(\d{1,2})-(\d{1,2})',  # YYYY-MM-DD
            r'(\d{1,2})/(\d{1,2})/(\d{4})',   # MM/DD/YYYY or DD/MM/YYYY
            r'(\d{1,2})-(\d{1,2})-(\d{4})',   # MM-DD-YYYY or DD-MM-YYYY
            r'(\d{4})/(\d{1,2})/(\d{1,2})',   # YYYY/MM/DD
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, creation_date)
            if match:
                try:
                    groups = match.groups()
                    if len(groups) == 3:
                        # Try different interpretations
                        for date_order in [
                            (groups[0], groups[1], groups[2]),  # As is
                            (groups[2], groups[0], groups[1]),  # Year, Month, Day
                            (groups[2], groups[1], groups[0])   # Year, Day, Month
                        ]:
                            try:
                                year, month, day = map(int, date_order)
                                if 1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                                    parsed_date = datetime(year, month, day, tzinfo=timezone.utc)
                                    return parsed_date
                            except ValueError:
                                continue
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def calculate_age(self, creation_date: datetime) -> Dict[str, Any]:
        """
        Calculate domain age from creation date.
        
        Args:
            creation_date: Domain creation datetime
            
        Returns:
            Dictionary with age calculations
        """
        now = datetime.now(timezone.utc)
        
        # Ensure creation_date has timezone info
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        # Calculate time difference
        age_delta = now - creation_date
        
        # Calculate age in different units
        age_days = age_delta.days
        age_years = age_days / 365.25  # Account for leap years
        age_months = age_days / 30.44  # Average month length
        
        return {
            'creation_date_iso': creation_date.isoformat(),
            'creation_date_formatted': creation_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'current_date_iso': now.isoformat(),
            'age_days': age_days,
            'age_years': round(age_years, 2),
            'age_months': round(age_months, 1),
            'age_human': self.format_human_age(age_days)
        }
    
    def format_human_age(self, days: int) -> str:
        """
        Format age in human-readable format.
        
        Args:
            days: Age in days
            
        Returns:
            Human-readable age string
        """
        if days < 0:
            return "Invalid (future date)"
        elif days == 0:
            return "Today"
        elif days == 1:
            return "1 day"
        elif days < 30:
            return f"{days} days"
        elif days < 365:
            months = round(days / 30.44)
            if months == 1:
                return "1 month"
            else:
                return f"{months} months"
        else:
            years = days // 365
            remaining_days = days % 365
            
            if years == 1:
                year_str = "1 year"
            else:
                year_str = f"{years} years"
            
            if remaining_days == 0:
                return year_str
            elif remaining_days < 30:
                return f"{year_str}, {remaining_days} days"
            else:
                months = round(remaining_days / 30.44)
                if months == 1:
                    return f"{year_str}, 1 month"
                else:
                    return f"{year_str}, {months} months"
    
    def analyze_domain_age(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain age using WHOIS data.
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary with domain age analysis
        """
        start_time = time.perf_counter()
        
        try:
            # Import the existing WHOIS lookup module
            import sys
            import os
            
            # Add parent directory to path if running as standalone script
            if __name__ == "__main__":
                parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
            
            from modules.whois_lookup import run_whois
            
            # Get WHOIS data
            whois_result = run_whois(domain)
            
            if whois_result.get('error'):
                return {
                    'domain': domain,
                    'error': f"WHOIS lookup failed: {whois_result['error']}",
                    'duration': round(time.perf_counter() - start_time, 3)
                }
            
            # Extract creation date
            creation_date = self.parse_creation_date(whois_result)
            
            if not creation_date:
                return {
                    'domain': domain,
                    'error': 'Could not parse creation date from WHOIS data',
                    'whois_checked': True,
                    'available_fields': list(whois_result.keys()),
                    'duration': round(time.perf_counter() - start_time, 3)
                }
            
            # Calculate age
            age_info = self.calculate_age(creation_date)
            
            # Combine results
            result = {
                'domain': domain,
                'whois_checked': True,
                'creation_date': age_info['creation_date_iso'],
                'creation_date_formatted': age_info['creation_date_formatted'],
                'age_days': age_info['age_days'],
                'age_years': age_info['age_years'],
                'age_months': age_info['age_months'],
                'age_human': age_info['age_human'],
                'is_new_domain': age_info['age_days'] < 365,  # Less than 1 year
                'is_mature_domain': age_info['age_days'] > 365 * 5,  # More than 5 years
                'duration': round(time.perf_counter() - start_time, 3),
                'error': None
            }
            
            return result
            
        except ImportError:
            return {
                'domain': domain,
                'error': 'WHOIS lookup module not available. Please ensure modules/whois_lookup.py exists.',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        except Exception as e:
            return {
                'domain': domain,
                'error': f'Unexpected error: {str(e)}',
                'duration': round(time.perf_counter() - start_time, 3)
            }


def run_website_age(domain: str) -> Dict[str, Any]:
    """
    Determine website age using WHOIS lookup data.
    
    Args:
        domain: Domain name to analyze
    
    Returns:
        Dictionary with website age analysis:
        - "domain": domain name analyzed
        - "creation_date": ISO format creation date
        - "creation_date_formatted": human-readable creation date
        - "age_days": age in days
        - "age_years": age in years (decimal)
        - "age_months": age in months (decimal)
        - "age_human": human-readable age description
        - "is_new_domain": boolean, true if less than 1 year old
        - "is_mature_domain": boolean, true if more than 5 years old
        - "whois_checked": boolean indicating if WHOIS was successfully queried
        - "duration": analysis duration in seconds
        - "error": error message or None
    """
    if not domain or not domain.strip():
        return {
            'domain': domain,
            'error': 'Domain cannot be empty',
            'duration': 0
        }
    
    # Initialize website age calculator
    age_calculator = WebsiteAgeCalculator()
    
    # Perform age analysis
    result = age_calculator.analyze_domain_age(domain.strip())
    
    return result


def format_age_summary(result: Dict[str, Any]) -> str:
    """
    Format website age results for display.
    
    Args:
        result: Website age analysis result
        
    Returns:
        Formatted string with age information
    """
    if result.get('error'):
        return f"Error analyzing {result.get('domain', 'unknown')}: {result['error']}"
    
    domain = result.get('domain', 'Unknown')
    creation_date = result.get('creation_date_formatted', 'Unknown')
    age_human = result.get('age_human', 'Unknown')
    age_days = result.get('age_days', 0)
    age_years = result.get('age_years', 0)
    
    lines = []
    lines.append(f"Domain: {domain}")
    lines.append(f"Created: {creation_date}")
    lines.append(f"Age: {age_human}")
    lines.append(f"Exact: {age_days} days ({age_years} years)")
    
    if result.get('is_new_domain'):
        lines.append("Status: New domain (less than 1 year old)")
    elif result.get('is_mature_domain'):
        lines.append("Status: Mature domain (more than 5 years old)")
    else:
        lines.append("Status: Established domain")
    
    lines.append(f"Analysis duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python website_age.py <domain>")
        print("Example: python website_age.py google.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    print(f"Analyzing domain age: {domain}")
    print("-" * 50)
    
    result = run_website_age(domain)
    formatted_output = format_age_summary(result)
    
    print(formatted_output)
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2))
