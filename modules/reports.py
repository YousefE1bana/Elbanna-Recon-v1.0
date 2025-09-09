#!/usr/bin/env python3
"""
Reports Module for Elbanna Recon v1.0

This module provides comprehensive result saving and report generation capabilities.
Features:
- Multiple output formats (JSON, TXT, HTML, CSV)
- Automatic directory creation and management
- Pretty-formatted text reports with color coding
- HTML reports with interactive elements
- CSV exports for data analysis
- Comprehensive error handling and validation
- File backup and versioning support

Author: Yousef Osama
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
import traceback
from pathlib import Path


class ReportsGenerator:
    """
    Advanced report generation and file management engine.
    """
    
    # Default reports directory
    DEFAULT_REPORTS_DIR = "reports"
    
    # Supported file formats
    SUPPORTED_FORMATS = {
        'json': 'JSON format with structured data',
        'txt': 'Plain text format with readable output',
        'html': 'HTML format with interactive elements',
        'csv': 'CSV format for data analysis'
    }
    
    # HTML template for reports
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elbanna Recon v1.0 - Report</title>
    <style>
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1f6feb, #7c3aed);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }}
        .metadata {{
            background-color: #161b22;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #58a6ff;
            margin-bottom: 20px;
        }}
        .operation {{
            background-color: #21262d;
            margin-bottom: 20px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        .operation-header {{
            background-color: #2d333b;
            padding: 15px;
            border-bottom: 1px solid #30363d;
        }}
        .operation-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #58a6ff;
            margin: 0;
        }}
        .operation-target {{
            color: #7c3aed;
            font-weight: bold;
        }}
        .operation-content {{
            padding: 15px;
        }}
        .success {{ color: #238636; }}
        .error {{ color: #f85149; }}
        .warning {{ color: #d29922; }}
        .info {{ color: #58a6ff; }}
        .key {{ color: #79c0ff; font-weight: bold; }}
        .value {{ color: #f0f6fc; }}
        .json-container {{
            background-color: #0d1117;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #30363d;
            overflow-x: auto;
        }}
        pre {{
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background-color: #161b22;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #30363d;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #58a6ff;
        }}
        .stat-label {{
            color: #8b949e;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #8b949e;
            border-top: 1px solid #30363d;
            margin-top: 30px;
        }}
        .collapsible {{
            cursor: pointer;
            padding: 10px;
            background-color: #2d333b;
            border: 1px solid #30363d;
            border-radius: 4px;
            margin: 5px 0;
        }}
        .collapsible:hover {{
            background-color: #373e47;
        }}
        .content {{
            padding: 0 15px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: #161b22;
        }}
        .content.active {{
            max-height: 1000px;
            padding: 15px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Elbanna Recon v1.0 - Security Report</h1>
        <p>Reconnaissance and Security Analysis Results</p>
    </div>
    
    <div class="metadata">
        <h3>📊 Report Metadata</h3>
        <p><span class="key">Generated:</span> <span class="value">{timestamp}</span></p>
        <p><span class="key">Total Operations:</span> <span class="value">{total_operations}</span></p>
        <p><span class="key">Report Format:</span> <span class="value">HTML Interactive Report</span></p>
        <p><span class="key">Generated By:</span> <span class="value">Elbanna Recon v1.0 - Yousef Osama</span></p>
    </div>
    
    <div class="stats">
        {stats_cards}
    </div>
    
    <div class="operations-container">
        <h2>🛠️ Operations Results</h2>
        {operations_html}
    </div>
    
    <div class="footer">
        <p>Report generated by <strong>Elbanna Recon v1.0</strong> - Yousef Osama</p>
        <p>Cybersecurity Engineering - Egyptian Chinese University</p>
        <p><em>For educational and authorized security testing purposes only</em></p>
    </div>
    
    <script>
        // Make sections collapsible
        document.querySelectorAll('.collapsible').forEach(function(element) {{
            element.addEventListener('click', function() {{
                this.classList.toggle('active');
                var content = this.nextElementSibling;
                content.classList.toggle('active');
            }});
        }});
        
        // Auto-expand first operation
        if (document.querySelector('.collapsible')) {{
            document.querySelector('.collapsible').click();
        }}
    </script>
</body>
</html>
"""
    
    def __init__(self, reports_dir: str = None):
        """
        Initialize the reports generator.
        
        Args:
            reports_dir: Directory to save reports (default: "reports")
        """
        self.reports_dir = reports_dir or self.DEFAULT_REPORTS_DIR
        self.ensure_reports_directory()
    
    def ensure_reports_directory(self) -> bool:
        """
        Ensure the reports directory exists.
        
        Returns:
            True if directory exists or was created successfully
        """
        try:
            Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False
    
    def validate_format(self, fmt: str) -> bool:
        """
        Validate if the format is supported.
        
        Args:
            fmt: Format string to validate
            
        Returns:
            True if format is supported
        """
        return fmt.lower() in self.SUPPORTED_FORMATS
    
    def generate_filename(self, base_path: str, fmt: str) -> str:
        """
        Generate a proper filename with extension and directory.
        
        Args:
            base_path: Base path for the file
            fmt: File format
            
        Returns:
            Complete file path with proper extension
        """
        # Remove extension if provided
        if '.' in base_path:
            base_path = os.path.splitext(base_path)[0]
        
        # Add proper extension
        extension = fmt.lower()
        filename = f"{base_path}.{extension}"
        
        # If path doesn't start with reports dir, prepend it
        if not filename.startswith(self.reports_dir):
            filename = os.path.join(self.reports_dir, os.path.basename(filename))
        
        return filename
    
    def backup_existing_file(self, filepath: str) -> Optional[str]:
        """
        Create a backup of existing file if it exists.
        
        Args:
            filepath: Path to the file to backup
            
        Returns:
            Backup file path or None if no backup needed
        """
        if not os.path.exists(filepath):
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{filepath}.backup_{timestamp}"
            
            # Read and write to create backup
            with open(filepath, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
            
            return backup_path
        except Exception:
            return None
    
    def save_json(self, results: List[Dict[str, Any]], filepath: str) -> Dict[str, Any]:
        """
        Save results in JSON format.
        
        Args:
            results: List of operation results
            filepath: Output file path
            
        Returns:
            Save operation result
        """
        try:
            # Create a comprehensive JSON structure
            json_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "Elbanna Recon v1.0",
                    "author": "Yousef Osama",
                    "total_operations": len(results),
                    "format": "json",
                    "version": "1.0"
                },
                "summary": self._generate_summary(results),
                "operations": results
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
            
            return {
                "saved": True,
                "path": filepath,
                "error": None,
                "size": os.path.getsize(filepath),
                "format": "json"
            }
            
        except Exception as e:
            return {
                "saved": False,
                "path": filepath,
                "error": f"JSON save error: {str(e)}",
                "format": "json"
            }
    
    def save_txt(self, results: List[Dict[str, Any]], filepath: str) -> Dict[str, Any]:
        """
        Save results in readable text format.
        
        Args:
            results: List of operation results
            filepath: Output file path
            
        Returns:
            Save operation result
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Write header
                f.write("=" * 80 + "\n")
                f.write("ELBANNA RECON v1.0 - SECURITY ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Author: Yousef Osama\n")
                f.write(f"Total Operations: {len(results)}\n")
                f.write("=" * 80 + "\n\n")
                
                # Write summary
                summary = self._generate_summary(results)
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Successful Operations: {summary['successful_operations']}\n")
                f.write(f"Failed Operations: {summary['failed_operations']}\n")
                f.write(f"Total Targets: {summary['unique_targets']}\n")
                f.write(f"Tools Used: {', '.join(summary['tools_used'])}\n")
                f.write(f"Total Duration: {summary['total_duration']:.3f}s\n\n")
                
                # Write operations
                for i, result in enumerate(results, 1):
                    f.write(f"OPERATION {i}: {result.get('tool', 'Unknown').upper()}\n")
                    f.write("-" * 60 + "\n")
                    f.write(f"Target: {result.get('target', result.get('interface', result.get('hash', 'N/A')))}\n")
                    f.write(f"Tool: {result.get('tool', 'Unknown')}\n")
                    
                    operation_result = result.get('result', {})
                    
                    # Check if operation was successful
                    success = operation_result.get('success', True)
                    f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
                    
                    # Write error if present
                    if operation_result.get('error'):
                        f.write(f"Error: {operation_result['error']}\n")
                    
                    # Write duration if present
                    if operation_result.get('duration'):
                        f.write(f"Duration: {operation_result['duration']:.3f}s\n")
                    
                    # Write key results
                    f.write("\nKey Results:\n")
                    self._write_key_results(f, operation_result, result.get('tool'))
                    
                    f.write("\n" + "=" * 80 + "\n\n")
                
                # Write footer
                f.write("Report generated by Elbanna Recon v1.0 - Yousef Osama\n")
                f.write("Cybersecurity Engineering - Egyptian Chinese University\n")
                f.write("For educational and authorized security testing purposes only\n")
            
            return {
                "saved": True,
                "path": filepath,
                "error": None,
                "size": os.path.getsize(filepath),
                "format": "txt"
            }
            
        except Exception as e:
            return {
                "saved": False,
                "path": filepath,
                "error": f"Text save error: {str(e)}",
                "format": "txt"
            }
    
    def save_html(self, results: List[Dict[str, Any]], filepath: str) -> Dict[str, Any]:
        """
        Save results in HTML format with interactive elements.
        
        Args:
            results: List of operation results
            filepath: Output file path
            
        Returns:
            Save operation result
        """
        try:
            summary = self._generate_summary(results)
            
            # Generate stats cards
            stats_cards = f"""
            <div class="stat-card">
                <div class="stat-number">{len(results)}</div>
                <div class="stat-label">Total Operations</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['successful_operations']}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['failed_operations']}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary['unique_targets']}</div>
                <div class="stat-label">Unique Targets</div>
            </div>
            """
            
            # Generate operations HTML
            operations_html = ""
            for i, result in enumerate(results, 1):
                tool_name = result.get('tool', 'Unknown')
                target = result.get('target', result.get('interface', result.get('hash', 'N/A')))
                operation_result = result.get('result', {})
                success = operation_result.get('success', True)
                
                status_class = "success" if success else "error"
                status_text = "✅ SUCCESS" if success else "❌ FAILED"
                
                operations_html += f"""
                <div class="operation">
                    <div class="collapsible operation-header">
                        <div class="operation-title">
                            {i}. {tool_name.upper().replace('_', ' ')} - 
                            <span class="{status_class}">{status_text}</span>
                        </div>
                        <div class="operation-target">Target: {target}</div>
                    </div>
                    <div class="content operation-content">
                        {self._generate_html_operation_content(operation_result, tool_name)}
                    </div>
                </div>
                """
            
            # Fill template
            html_content = self.HTML_TEMPLATE.format(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total_operations=len(results),
                stats_cards=stats_cards,
                operations_html=operations_html
            )
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return {
                "saved": True,
                "path": filepath,
                "error": None,
                "size": os.path.getsize(filepath),
                "format": "html"
            }
            
        except Exception as e:
            return {
                "saved": False,
                "path": filepath,
                "error": f"HTML save error: {str(e)}",
                "format": "html"
            }
    
    def save_csv(self, results: List[Dict[str, Any]], filepath: str) -> Dict[str, Any]:
        """
        Save results in CSV format for data analysis.
        
        Args:
            results: List of operation results
            filepath: Output file path
            
        Returns:
            Save operation result
        """
        try:
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                # Write header
                f.write("Operation,Tool,Target,Status,Duration,Error,Key_Results\n")
                
                for i, result in enumerate(results, 1):
                    tool = result.get('tool', 'Unknown')
                    target = result.get('target', result.get('interface', result.get('hash', 'N/A')))
                    operation_result = result.get('result', {})
                    
                    status = 'Success' if operation_result.get('success', True) else 'Failed'
                    duration = operation_result.get('duration', 0)
                    error = operation_result.get('error', '').replace('"', '""')  # Escape quotes
                    
                    # Extract key results as summary
                    key_results = self._extract_csv_key_results(operation_result, tool)
                    key_results = key_results.replace('"', '""')  # Escape quotes
                    
                    # Write CSV row
                    f.write(f'{i},"{tool}","{target}","{status}",{duration},"{error}","{key_results}"\n')
            
            return {
                "saved": True,
                "path": filepath,
                "error": None,
                "size": os.path.getsize(filepath),
                "format": "csv"
            }
            
        except Exception as e:
            return {
                "saved": False,
                "path": filepath,
                "error": f"CSV save error: {str(e)}",
                "format": "csv"
            }
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of all operations."""
        successful = 0
        failed = 0
        tools_used = set()
        targets = set()
        total_duration = 0
        
        for result in results:
            operation_result = result.get('result', {})
            
            if operation_result.get('success', True):
                successful += 1
            else:
                failed += 1
            
            tools_used.add(result.get('tool', 'Unknown'))
            targets.add(result.get('target', result.get('interface', result.get('hash', 'N/A'))))
            
            if operation_result.get('duration'):
                total_duration += operation_result['duration']
        
        return {
            'successful_operations': successful,
            'failed_operations': failed,
            'tools_used': list(tools_used),
            'unique_targets': len(targets),
            'total_duration': total_duration
        }
    
    def _write_key_results(self, f, operation_result: Dict[str, Any], tool: str):
        """Write key results for text format."""
        if tool == 'port_scanner':
            open_ports = operation_result.get('open_ports', [])
            f.write(f"  Open Ports: {len(open_ports)}\n")
            if open_ports:
                f.write(f"  Ports: {', '.join(map(str, open_ports[:10]))}\n")
        
        elif tool == 'dns_lookup':
            records = operation_result.get('records', {})
            f.write(f"  DNS Records Found: {len(records)}\n")
            for record_type, values in records.items():
                f.write(f"  {record_type}: {len(values)} records\n")
        
        elif tool == 'whois_lookup':
            whois_data = operation_result.get('whois_data', {})
            if whois_data.get('domain_name'):
                f.write(f"  Domain: {whois_data['domain_name']}\n")
            if whois_data.get('registrar'):
                f.write(f"  Registrar: {whois_data['registrar']}\n")
        
        elif tool == 'youtube_lookup':
            if operation_result.get('title'):
                f.write(f"  Title: {operation_result['title']}\n")
                f.write(f"  Channel: {operation_result.get('author_name', 'N/A')}\n")
            elif operation_result.get('channel_name'):
                f.write(f"  Channel: {operation_result['channel_name']}\n")
        
        elif tool == 'url_expander':
            f.write(f"  Final URL: {operation_result.get('final_url', 'N/A')}\n")
            f.write(f"  Redirects: {operation_result.get('total_redirects', 0)}\n")
        
        else:
            # Generic key-value extraction
            for key, value in operation_result.items():
                if key not in ['success', 'error', 'duration'] and not key.startswith('_'):
                    if isinstance(value, (str, int, float)) and len(str(value)) < 100:
                        f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
    
    def _generate_html_operation_content(self, operation_result: Dict[str, Any], tool: str) -> str:
        """Generate HTML content for an operation."""
        html = ""
        
        # Add error if present
        if operation_result.get('error'):
            html += f'<p class="error"><strong>Error:</strong> {operation_result["error"]}</p>'
        
        # Add duration if present
        if operation_result.get('duration'):
            html += f'<p class="info"><strong>Duration:</strong> {operation_result["duration"]:.3f}s</p>'
        
        # Add tool-specific content
        html += '<div class="json-container"><pre>'
        html += json.dumps(operation_result, indent=2, default=str)
        html += '</pre></div>'
        
        return html
    
    def _extract_csv_key_results(self, operation_result: Dict[str, Any], tool: str) -> str:
        """Extract key results for CSV format."""
        key_results = []
        
        if tool == 'port_scanner':
            open_ports = operation_result.get('open_ports', [])
            key_results.append(f"Open ports: {len(open_ports)}")
        
        elif tool == 'dns_lookup':
            records = operation_result.get('records', {})
            key_results.append(f"DNS records: {len(records)}")
        
        elif tool == 'youtube_lookup':
            if operation_result.get('title'):
                key_results.append(f"Video: {operation_result['title'][:50]}")
            elif operation_result.get('channel_name'):
                key_results.append(f"Channel: {operation_result['channel_name']}")
        
        elif tool == 'url_expander':
            key_results.append(f"Redirects: {operation_result.get('total_redirects', 0)}")
        
        return '; '.join(key_results) if key_results else 'No specific results'


def save_results(results: List[Dict[str, Any]], path: str, fmt: str = "json") -> Dict[str, Any]:
    """
    Save reconnaissance results to a file in the specified format.
    
    Args:
        results: List of operation result dictionaries from reconnaissance tools
        path: Output file path (extension will be added automatically)
        fmt: Output format - one of: 'json', 'txt', 'html', 'csv' (default: 'json')
    
    Returns:
        Dictionary with save operation results:
        - "saved": boolean indicating if save was successful
        - "path": actual path where file was saved
        - "error": error message if save failed, None if successful
        - "size": file size in bytes (if successful)
        - "format": format used for saving
        - "backup_path": path to backup file if original was overwritten
        - "operations_count": number of operations saved
        
        For JSON format: saves with indent=2 and comprehensive metadata
        For TXT format: creates pretty-printed readable report
        For HTML format: generates interactive web report with styling
        For CSV format: exports data in spreadsheet-compatible format
    """
    if not results:
        return {
            "saved": False,
            "path": path,
            "error": "No results to save - results list is empty",
            "format": fmt
        }
    
    if not isinstance(results, list):
        return {
            "saved": False,
            "path": path,
            "error": "Results must be a list of dictionaries",
            "format": fmt
        }
    
    # Validate format
    fmt = fmt.lower().strip()
    if fmt not in ReportsGenerator.SUPPORTED_FORMATS:
        return {
            "saved": False,
            "path": path,
            "error": f"Unsupported format '{fmt}'. Supported formats: {', '.join(ReportsGenerator.SUPPORTED_FORMATS.keys())}",
            "format": fmt
        }
    
    try:
        # Initialize reports generator
        generator = ReportsGenerator()
        
        # Generate proper filename
        filepath = generator.generate_filename(path, fmt)
        
        # Create backup if file exists
        backup_path = generator.backup_existing_file(filepath)
        
        # Save based on format
        if fmt == 'json':
            result = generator.save_json(results, filepath)
        elif fmt == 'txt':
            result = generator.save_txt(results, filepath)
        elif fmt == 'html':
            result = generator.save_html(results, filepath)
        elif fmt == 'csv':
            result = generator.save_csv(results, filepath)
        else:
            return {
                "saved": False,
                "path": path,
                "error": f"Format '{fmt}' not implemented",
                "format": fmt
            }
        
        # Add additional metadata to result
        if result.get('saved'):
            result['backup_path'] = backup_path
            result['operations_count'] = len(results)
            result['reports_directory'] = generator.reports_dir
        
        return result
        
    except Exception as e:
        return {
            "saved": False,
            "path": path,
            "error": f"Unexpected error during save: {str(e)}",
            "format": fmt,
            "traceback": traceback.format_exc()
        }


def format_save_summary(result: Dict[str, Any]) -> str:
    """
    Format save result for display.
    
    Args:
        result: Save result dictionary
        
    Returns:
        Formatted string with save information
    """
    if result.get('saved'):
        lines = [
            f"✅ Results saved successfully!",
            f"📁 File: {result.get('path', 'Unknown')}",
            f"📊 Format: {result.get('format', 'Unknown').upper()}",
            f"📈 Operations: {result.get('operations_count', 0)}",
            f"💾 Size: {result.get('size', 0):,} bytes"
        ]
        
        if result.get('backup_path'):
            lines.append(f"🔄 Backup: {result['backup_path']}")
        
        return '\n'.join(lines)
    else:
        return f"❌ Save failed: {result.get('error', 'Unknown error')}"


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    # Test data
    test_results = [
        {
            "tool": "port_scanner",
            "target": "example.com",
            "result": {
                "success": True,
                "open_ports": [80, 443, 22],
                "closed_ports": [21, 25],
                "duration": 2.5
            }
        },
        {
            "tool": "dns_lookup", 
            "target": "example.com",
            "result": {
                "success": True,
                "records": {
                    "A": ["93.184.216.34"],
                    "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]
                },
                "duration": 1.2
            }
        },
        {
            "tool": "whois_lookup",
            "target": "example.com", 
            "result": {
                "success": False,
                "error": "Domain not found",
                "duration": 0.8
            }
        }
    ]
    
    if len(sys.argv) < 2:
        print("Usage: python reports.py <format> [output_path]")
        print("Formats: json, txt, html, csv")
        print("Example: python reports.py json test_report")
        print("Example: python reports.py html analysis_report")
        sys.exit(1)
    
    fmt = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else f"test_report_{fmt}"
    
    print(f"Testing reports generation...")
    print(f"Format: {fmt}")
    print(f"Output: {output_path}")
    print("-" * 50)
    
    result = save_results(test_results, output_path, fmt)
    summary = format_save_summary(result)
    
    print(summary)
    
    if result.get('saved'):
        print(f"\n📂 Report saved to: {result['path']}")
        print("You can now open the file to view the results!")
    
    # Show raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
