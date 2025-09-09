"""
Password Cracker Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

Dictionary attack module with support for multiple hash algorithms and progress tracking.
Integrates with existing Elbanna password cracker functionality.
"""

import os
import sys
import time
import hashlib
from pathlib import Path
from typing import Dict, Optional, Any

# Add the Tools directory to the Python path to import existing tools
tools_dir = Path(__file__).parent.parent / "Tools" / "Password_Cracker"
sys.path.insert(0, str(tools_dir))

try:
    # Try to import the existing password cracker class
    from password_cracker import PasswordCrackerCLI
    EXISTING_CRACKER_AVAILABLE = True
except ImportError:
    EXISTING_CRACKER_AVAILABLE = False


class PasswordCracker:
    """
    Password cracker with dictionary attacks and multiple hash algorithm support.
    """
    
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    def __init__(self):
        """Initialize the password cracker."""
        self.tested_passwords = 0
        self.start_time = None
        self.show_progress = True
        self.progress_interval = 1000  # Show progress every N passwords
    
    def normalize_hash(self, hash_value: str) -> str:
        """
        Normalize hash value by removing whitespace and converting to lowercase.
        
        Args:
            hash_value: Input hash string
            
        Returns:
            Normalized hash string
        """
        return hash_value.strip().lower()
    
    def hash_password(self, password: str, algorithm: str) -> str:
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: Password to hash
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
            
        Returns:
            Hexadecimal hash digest
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()
        hasher.update(password.encode('utf-8', errors='ignore'))
        return hasher.hexdigest()
    
    def generate_password_variations(self, password: str) -> list[str]:
        """
        Generate common password variations.
        
        Args:
            password: Base password
            
        Returns:
            List of password variations
        """
        variations = [password]  # Original password
        
        # Common variations
        variations.extend([
            password.lower(),
            password.upper(),
            password.capitalize(),
            password + "123",
            password + "!",
            password + "1",
            "123" + password,
            "!" + password,
            "1" + password,
            password + "321",
            password + "@",
            password + "#",
            password + "$"
        ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var not in seen:
                seen.add(var)
                unique_variations.append(var)
        
        return unique_variations
    
    def count_wordlist_lines(self, wordlist_path: str) -> int:
        """
        Count the number of lines in a wordlist file.
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            Number of lines in the file
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def crack_hash_from_wordlist(self, target_hash: str, algorithm: str, wordlist_path: str, 
                                stop_on_first: bool = True) -> Optional[str]:
        """
        Attempt to crack a hash using a wordlist.
        
        Args:
            target_hash: Target hash to crack
            algorithm: Hash algorithm
            wordlist_path: Path to wordlist file
            stop_on_first: Stop on first match found
            
        Returns:
            Cracked password or None if not found
        """
        target_hash = self.normalize_hash(target_hash)
        self.tested_passwords = 0
        
        try:
            # Count total lines for progress tracking
            total_lines = self.count_wordlist_lines(wordlist_path)
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if not password:
                        continue
                    
                    # Generate and test password variations
                    variations = self.generate_password_variations(password)
                    
                    for variation in variations:
                        self.tested_passwords += 1
                        
                        # Hash the candidate password
                        candidate_hash = self.hash_password(variation, algorithm)
                        
                        # Check if it matches
                        if candidate_hash == target_hash:
                            return variation
                        
                        # Show progress
                        if self.show_progress and self.tested_passwords % self.progress_interval == 0:
                            progress = (line_num / total_lines) * 100 if total_lines > 0 else 0
                            print(f"[*] Progress: {progress:.1f}% - Tested {self.tested_passwords} passwords")
                    
                    # Stop early if requested (though we test variations of each word)
                    if stop_on_first and self.tested_passwords > len(variations):
                        # This allows us to test all variations of current word
                        pass
        
        except Exception as e:
            if self.show_progress:
                print(f"[!] Error reading wordlist: {e}")
        
        return None


def run_password_cracker(target_hash: str, algorithm: str = "md5", wordlist_path: Optional[str] = None, 
                        show_progress: bool = True, stop_on_first: bool = True) -> Dict[str, Any]:
    """
    Dictionary attack against target_hash using specified algorithm.
    
    Args:
        target_hash: Target hash to crack (hex string)
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')
        wordlist_path: Path to wordlist file
        show_progress: Show progress during cracking
        stop_on_first: Stop on first match found
    
    Returns:
        Dictionary with crack results:
        - "target_hash": str - Original target hash
        - "algorithm": str - Hash algorithm used
        - "found": bool - Whether password was found
        - "password": str|None - Cracked password or None
        - "tested": int - Number of passwords tested
        - "duration": float - Time taken in seconds
        - "error": str|None - Error message or None
    """
    start_time = time.perf_counter()
    
    # Validate algorithm
    algorithm = algorithm.lower()
    if algorithm not in PasswordCracker.SUPPORTED_ALGORITHMS:
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": False,
            "password": None,
            "tested": 0,
            "duration": time.perf_counter() - start_time,
            "error": f"Unsupported algorithm: {algorithm}. Supported: {list(PasswordCracker.SUPPORTED_ALGORITHMS.keys())}"
        }
    
    # Validate target hash
    if not target_hash or not target_hash.strip():
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": False,
            "password": None,
            "tested": 0,
            "duration": time.perf_counter() - start_time,
            "error": "Target hash cannot be empty"
        }
    
    # Use default wordlist if none provided
    if not wordlist_path:
        # Try to find the sample wordlist in the Tools directory
        default_wordlist = tools_dir / "sample_wordlist.txt"
        if default_wordlist.exists():
            wordlist_path = str(default_wordlist)
        else:
            return {
                "target_hash": target_hash,
                "algorithm": algorithm,
                "found": False,
                "password": None,
                "tested": 0,
                "duration": time.perf_counter() - start_time,
                "error": "No wordlist provided and default wordlist not found"
            }
    
    # Check if wordlist exists
    if not os.path.exists(wordlist_path):
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": False,
            "password": None,
            "tested": 0,
            "duration": time.perf_counter() - start_time,
            "error": f"Wordlist file not found: {wordlist_path}"
        }
    
    # Check if wordlist is readable
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.readline()  # Try to read first line
    except Exception as e:
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": False,
            "password": None,
            "tested": 0,
            "duration": time.perf_counter() - start_time,
            "error": f"Cannot read wordlist file: {e}"
        }
    
    try:
        # Initialize cracker
        cracker = PasswordCracker()
        cracker.show_progress = show_progress
        
        if show_progress:
            print(f"[*] Starting dictionary attack on {algorithm.upper()} hash")
            print(f"[*] Target hash: {target_hash}")
            print(f"[*] Using wordlist: {wordlist_path}")
        
        # Attempt to crack the hash
        found_password = cracker.crack_hash_from_wordlist(
            target_hash, algorithm, wordlist_path, stop_on_first
        )
        
        duration = time.perf_counter() - start_time
        
        if show_progress:
            if found_password:
                print(f"[+] Password found: {found_password}")
            else:
                print(f"[!] Password not found in wordlist")
            print(f"[*] Tested {cracker.tested_passwords} passwords in {duration:.2f} seconds")
        
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": found_password is not None,
            "password": found_password,
            "tested": cracker.tested_passwords,
            "duration": round(duration, 3),
            "error": None
        }
    
    except Exception as e:
        return {
            "target_hash": target_hash,
            "algorithm": algorithm,
            "found": False,
            "password": None,
            "tested": 0,
            "duration": time.perf_counter() - start_time,
            "error": f"Cracking failed: {str(e)}"
        }


def get_supported_algorithms() -> list[str]:
    """
    Get list of supported hash algorithms.
    
    Returns:
        List of supported algorithm names
    """
    return list(PasswordCracker.SUPPORTED_ALGORITHMS.keys())


def validate_hash_format(hash_value: str, algorithm: str) -> bool:
    """
    Validate hash format for given algorithm.
    
    Args:
        hash_value: Hash value to validate
        algorithm: Hash algorithm
        
    Returns:
        True if format appears valid, False otherwise
    """
    algorithm = algorithm.lower()
    if algorithm not in PasswordCracker.SUPPORTED_ALGORITHMS:
        return False
    
    # Remove whitespace and check if it's hexadecimal
    clean_hash = hash_value.strip()
    
    try:
        int(clean_hash, 16)  # Check if it's valid hex
    except ValueError:
        return False
    
    # Check expected length for each algorithm
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }
    
    return len(clean_hash) == expected_lengths.get(algorithm, 0)


def create_sample_hashes(passwords: list[str], algorithm: str = 'md5') -> Dict[str, str]:
    """
    Create sample hashes for testing purposes.
    
    Args:
        passwords: List of passwords to hash
        algorithm: Hash algorithm to use
        
    Returns:
        Dictionary mapping passwords to their hashes
    """
    if algorithm not in PasswordCracker.SUPPORTED_ALGORITHMS:
        return {}
    
    cracker = PasswordCracker()
    result = {}
    
    for password in passwords:
        try:
            hash_value = cracker.hash_password(password, algorithm)
            result[password] = hash_value
        except Exception:
            continue
    
    return result


if __name__ == "__main__":
    # Example usage and testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Elbanna Password Cracker")
    parser.add_argument("hash", help="Target hash to crack")
    parser.add_argument("-a", "--algorithm", default="md5", choices=get_supported_algorithms(),
                       help="Hash algorithm")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable progress output")
    parser.add_argument("--test", action="store_true", help="Run test with sample hashes")
    
    args = parser.parse_args()
    
    if args.test:
        # Create test hashes
        test_passwords = ["password", "123456", "admin", "test", "hello"]
        print("Creating test hashes...")
        
        for algo in ['md5', 'sha1', 'sha256']:
            print(f"\n{algo.upper()} Test Hashes:")
            hashes = create_sample_hashes(test_passwords, algo)
            for pwd, hash_val in hashes.items():
                print(f"  {pwd} -> {hash_val}")
    else:
        # Run the cracker
        print("Elbanna Password Cracker v1.0")
        print("="*40)
        
        result = run_password_cracker(
            target_hash=args.hash,
            algorithm=args.algorithm,
            wordlist_path=args.wordlist,
            show_progress=not args.quiet
        )
        
        print("\nCracking Results:")
        print("="*40)
        
        if result['error']:
            print(f"Error: {result['error']}")
        else:
            print(f"Target Hash: {result['target_hash']}")
            print(f"Algorithm: {result['algorithm'].upper()}")
            print(f"Password Found: {result['found']}")
            if result['found']:
                print(f"Password: {result['password']}")
            print(f"Passwords Tested: {result['tested']}")
            print(f"Duration: {result['duration']} seconds")
