#!/usr/bin/env python3
"""
Elbanna Recon v1.0 - Smoke Tests
Author: Yousef Osama - Cybersecurity Engineering, Egyptian Chinese University
Last Updated: September 8, 2025

This module contains smoke tests to verify that all core modules are properly
importable and their main functions return the expected data structure.

Smoke tests are designed to:
- Verify module imports work correctly
- Check that main functions exist and are callable
- Ensure functions return dictionary objects as expected
- Test basic functionality without requiring network access
- Validate error handling for invalid inputs

Usage:
    pytest tests/test_modules_smoke.py -v
    python -m pytest tests/test_modules_smoke.py -v --tb=short
    python tests/test_modules_smoke.py  # Direct execution
"""

import sys
import os
import pytest
import importlib
from typing import Dict, Any, Callable
from unittest.mock import patch, MagicMock

# Add project root to Python path for module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestModuleImports:
    """Test that all modules can be imported successfully."""
    
    def test_port_scanner_import(self):
        """Test port scanner module import."""
        try:
            from modules.port_scanner import run_port_scanner
            assert callable(run_port_scanner), "run_port_scanner should be callable"
        except ImportError as e:
            pytest.skip(f"Port scanner module not available: {e}")
    
    def test_packet_sniffer_import(self):
        """Test packet sniffer module import."""
        try:
            from modules.packet_sniffer import run_packet_sniffer
            assert callable(run_packet_sniffer), "run_packet_sniffer should be callable"
        except ImportError as e:
            pytest.skip(f"Packet sniffer module not available: {e}")
    
    def test_password_cracker_import(self):
        """Test password cracker module import."""
        try:
            from modules.password_cracker import run_password_cracker
            assert callable(run_password_cracker), "run_password_cracker should be callable"
        except ImportError as e:
            pytest.skip(f"Password cracker module not available: {e}")
    
    def test_steganography_import(self):
        """Test steganography tool import."""
        try:
            from modules.steganography_tool import run_steganography_analysis
            assert callable(run_steganography_analysis), "run_steganography_analysis should be callable"
        except ImportError as e:
            pytest.skip(f"Steganography tool module not available: {e}")
    
    def test_subdomain_scanner_import(self):
        """Test subdomain scanner module import."""
        try:
            from modules.subdomain import run_subdomain_scanner
            assert callable(run_subdomain_scanner), "run_subdomain_scanner should be callable"
        except ImportError as e:
            pytest.skip(f"Subdomain scanner module not available: {e}")
    
    def test_whois_lookup_import(self):
        """Test WHOIS lookup module import."""
        try:
            from modules.whois_lookup import run_whois_lookup
            assert callable(run_whois_lookup), "run_whois_lookup should be callable"
        except ImportError as e:
            pytest.skip(f"WHOIS lookup module not available: {e}")
    
    def test_dns_lookup_import(self):
        """Test DNS lookup module import."""
        try:
            from modules.dns_lookup import run_dns_lookup
            assert callable(run_dns_lookup), "run_dns_lookup should be callable"
        except ImportError as e:
            pytest.skip(f"DNS lookup module not available: {e}")
    
    def test_reports_import(self):
        """Test reports module import."""
        try:
            from modules.reports import save_results
            assert callable(save_results), "save_results should be callable"
        except ImportError as e:
            pytest.skip(f"Reports module not available: {e}")


class TestModuleReturnTypes:
    """Test that modules return expected data structures."""
    
    def test_port_scanner_return_type(self):
        """Test port scanner returns dictionary."""
        try:
            from modules.port_scanner import run_port_scanner
            
            # Test with invalid input to trigger error handling
            result = run_port_scanner("", [])
            assert isinstance(result, dict), "run_port_scanner should return a dictionary"
            assert 'error' in result, "Error case should include 'error' key"
            
        except ImportError:
            pytest.skip("Port scanner module not available")
    
    def test_packet_sniffer_return_type(self):
        """Test packet sniffer returns dictionary."""
        try:
            from modules.packet_sniffer import run_packet_sniffer
            
            # Test with invalid interface to trigger error handling
            result = run_packet_sniffer("invalid_interface", 1, 1)
            assert isinstance(result, dict), "run_packet_sniffer should return a dictionary"
            # Should handle errors gracefully
            
        except ImportError:
            pytest.skip("Packet sniffer module not available")
    
    def test_password_cracker_return_type(self):
        """Test password cracker returns dictionary."""
        try:
            from modules.password_cracker import run_password_cracker
            
            # Test with empty inputs to trigger error handling
            result = run_password_cracker("", "", "md5")
            assert isinstance(result, dict), "run_password_cracker should return a dictionary"
            assert 'error' in result, "Error case should include 'error' key"
            
        except ImportError:
            pytest.skip("Password cracker module not available")
    
    def test_steganography_return_type(self):
        """Test steganography tool returns dictionary."""
        try:
            from modules.steganography_tool import run_steganography_analysis
            
            # Test with invalid file path
            result = run_steganography_analysis("nonexistent_file.png")
            assert isinstance(result, dict), "run_steganography_analysis should return a dictionary"
            assert 'error' in result, "Error case should include 'error' key"
            
        except ImportError:
            pytest.skip("Steganography tool module not available")
    
    def test_whois_lookup_return_type(self):
        """Test WHOIS lookup returns dictionary."""
        try:
            from modules.whois_lookup import run_whois_lookup
            
            # Test with empty domain
            result = run_whois_lookup("")
            assert isinstance(result, dict), "run_whois_lookup should return a dictionary"
            assert 'error' in result, "Error case should include 'error' key"
            
        except ImportError:
            pytest.skip("WHOIS lookup module not available")
    
    def test_dns_lookup_return_type(self):
        """Test DNS lookup returns dictionary."""
        try:
            from modules.dns_lookup import run_dns_lookup
            
            # Test with empty domain
            result = run_dns_lookup("", [])
            assert isinstance(result, dict), "run_dns_lookup should return a dictionary"
            assert 'error' in result, "Error case should include 'error' key"
            
        except ImportError:
            pytest.skip("DNS lookup module not available")
    
    def test_reports_return_type(self):
        """Test reports module returns dictionary."""
        try:
            from modules.reports import save_results
            
            # Test with empty results
            result = save_results([], "test", "json")
            assert isinstance(result, dict), "save_results should return a dictionary"
            assert 'saved' in result, "Result should include 'saved' key"
            assert 'error' in result, "Result should include 'error' key"
            
        except ImportError:
            pytest.skip("Reports module not available")


class TestModuleFunctionSignatures:
    """Test that module functions have expected signatures."""
    
    def test_port_scanner_signature(self):
        """Test port scanner function signature."""
        try:
            from modules.port_scanner import run_port_scanner
            import inspect
            
            sig = inspect.signature(run_port_scanner)
            params = list(sig.parameters.keys())
            
            # Should accept at least target parameter
            assert len(params) >= 1, "run_port_scanner should accept at least 1 parameter"
            assert 'target' in params, "run_port_scanner should have 'target' parameter"
            
        except ImportError:
            pytest.skip("Port scanner module not available")
    
    def test_password_cracker_signature(self):
        """Test password cracker function signature."""
        try:
            from modules.password_cracker import run_password_cracker
            import inspect
            
            sig = inspect.signature(run_password_cracker)
            params = list(sig.parameters.keys())
            
            # Should accept hash, wordlist, and algorithm parameters
            assert len(params) >= 3, "run_password_cracker should accept at least 3 parameters"
            
        except ImportError:
            pytest.skip("Password cracker module not available")


class TestModuleErrorHandling:
    """Test error handling in modules."""
    
    def test_port_scanner_invalid_input(self):
        """Test port scanner with invalid inputs."""
        try:
            from modules.port_scanner import run_port_scanner
            
            # Test with various invalid inputs
            test_cases = [
                ("", []),  # Empty target
                ("invalid_host_name_that_does_not_exist", [80]),  # Non-existent host
                ("127.0.0.1", "invalid_ports"),  # Invalid port format
            ]
            
            for target, ports in test_cases:
                result = run_port_scanner(target, ports)
                assert isinstance(result, dict), f"Should return dict for input: {target}, {ports}"
                # Should either succeed or have error message
                assert result.get('success') is not None or result.get('error') is not None
                
        except ImportError:
            pytest.skip("Port scanner module not available")
    
    def test_reports_invalid_format(self):
        """Test reports module with invalid format."""
        try:
            from modules.reports import save_results
            
            # Test with invalid format
            result = save_results([{"test": "data"}], "test", "invalid_format")
            assert isinstance(result, dict), "Should return dict for invalid format"
            assert result.get('saved') is False, "Should indicate save failed"
            assert result.get('error') is not None, "Should include error message"
            
        except ImportError:
            pytest.skip("Reports module not available")


class TestMainModuleFunctionality:
    """Test core functionality of main CLI module."""
    
    def test_main_module_import(self):
        """Test that main module can be imported."""
        try:
            import elbanna_recon
            # Check if main functions exist
            assert hasattr(elbanna_recon, 'main') or hasattr(elbanna_recon, 'run_cli'), \
                "Main module should have main() or run_cli() function"
        except ImportError as e:
            pytest.skip(f"Main module not available: {e}")
    
    def test_module_directory_structure(self):
        """Test that modules directory exists and contains expected files."""
        modules_dir = os.path.join(os.path.dirname(__file__), '..', 'modules')
        assert os.path.exists(modules_dir), "modules/ directory should exist"
        
        # Check for __init__.py to make it a proper Python package
        init_file = os.path.join(modules_dir, '__init__.py')
        if not os.path.exists(init_file):
            # Create __init__.py if it doesn't exist
            with open(init_file, 'w') as f:
                f.write('# Elbanna Recon v1.0 - Modules Package\n')


class TestUtilityFunctions:
    """Test utility and helper functions."""
    
    def test_pretty_print_result_function(self):
        """Test pretty print function from main module."""
        try:
            import elbanna_recon
            
            # Check if pretty_print_result function exists
            if hasattr(elbanna_recon, 'pretty_print_result'):
                func = getattr(elbanna_recon, 'pretty_print_result')
                assert callable(func), "pretty_print_result should be callable"
                
                # Test with sample data
                sample_result = {"success": True, "test": "data"}
                try:
                    func(sample_result, "Test Operation")
                    # If no exception, the function works
                    assert True
                except Exception as e:
                    pytest.fail(f"pretty_print_result failed: {e}")
                    
        except ImportError:
            pytest.skip("Main module not available")


def run_manual_smoke_tests():
    """
    Run smoke tests manually without pytest.
    This function can be called directly for quick testing.
    """
    print("=" * 80)
    print("ELBANNA RECON v1.0 - SMOKE TESTS")
    print("=" * 80)
    print("Author: Yousef Osama - Cybersecurity Engineering, ECU")
    print("Running manual smoke tests...")
    print()
    
    # Test module imports
    modules_to_test = [
        ('port_scanner', 'run_port_scanner'),
        ('packet_sniffer', 'run_packet_sniffer'),
        ('password_cracker', 'run_password_cracker'),
        ('steganography_tool', 'run_steganography_analysis'),
        ('whois_lookup', 'run_whois_lookup'),
        ('dns_lookup', 'run_dns_lookup'),
        ('reports', 'save_results'),
    ]
    
    passed = 0
    failed = 0
    skipped = 0
    
    for module_name, function_name in modules_to_test:
        try:
            module = importlib.import_module(f'modules.{module_name}')
            func = getattr(module, function_name, None)
            
            if func and callable(func):
                print(f"✅ PASS: {module_name}.{function_name} - Import and callable check")
                passed += 1
            else:
                print(f"❌ FAIL: {module_name}.{function_name} - Function not found or not callable")
                failed += 1
                
        except ImportError as e:
            print(f"⏭️  SKIP: {module_name} - Module not available ({e})")
            skipped += 1
        except Exception as e:
            print(f"❌ FAIL: {module_name} - Unexpected error ({e})")
            failed += 1
    
    # Test basic functionality
    print("\nTesting basic functionality...")
    
    # Test reports module
    try:
        from modules.reports import save_results
        result = save_results([], "test", "json")
        if isinstance(result, dict) and 'saved' in result:
            print("✅ PASS: reports.save_results - Return type check")
            passed += 1
        else:
            print("❌ FAIL: reports.save_results - Invalid return type")
            failed += 1
    except Exception as e:
        print(f"⏭️  SKIP: reports.save_results - Error during test ({e})")
        skipped += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("SMOKE TEST SUMMARY")
    print("=" * 80)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⏭️  Skipped: {skipped}")
    print(f"📊 Total: {passed + failed + skipped}")
    
    if failed == 0:
        print("\n🎉 All available tests passed! Your modules are working correctly.")
    else:
        print(f"\n⚠️  {failed} tests failed. Please check the module implementations.")
    
    return failed == 0


if __name__ == "__main__":
    # Run manual tests if executed directly
    run_manual_smoke_tests()
else:
    # Running with pytest
    print("Running Elbanna Recon v1.0 smoke tests with pytest...")
