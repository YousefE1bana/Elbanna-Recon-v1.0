"""
Steganography Tool Module for Elbanna Recon v1.0
Yousef Osama - Studying Cybersecurity Engineering in Egyptian Chinese University

LSB steganography module for hiding and extracting text in images using Pillow.
Integrates with existing Elbanna steganography functionality.
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# Add the Tools directory to the Python path to import existing tools
tools_dir = Path(__file__).parent.parent / "Tools" / "Steganography_Tool"
sys.path.insert(0, str(tools_dir))

try:
    # Try to import the existing steganography engine
    from pyqt5_steganography_tool import SteganographyEngine
    EXISTING_STEGO_AVAILABLE = True
except ImportError:
    EXISTING_STEGO_AVAILABLE = False


class LSBSteganography:
    """
    LSB (Least Significant Bit) steganography implementation using Pillow.
    """
    
    # End-of-message delimiter: 16 bits pattern (0xFF 0x00 repeated)
    DELIMITER = "1111111100000000" * 2  # 32 bits total for reliability
    
    def __init__(self):
        """Initialize the steganography engine."""
        pass
    
    def text_to_binary(self, text: str) -> str:
        """
        Convert text to binary representation.
        
        Args:
            text: Text to convert
            
        Returns:
            Binary string representation
        """
        return ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
    
    def binary_to_text(self, binary: str) -> str:
        """
        Convert binary representation back to text.
        
        Args:
            binary: Binary string
            
        Returns:
            Decoded text
        """
        try:
            text_bytes = bytearray()
            for i in range(0, len(binary), 8):
                byte = binary[i:i+8]
                if len(byte) == 8:
                    text_bytes.append(int(byte, 2))
            return text_bytes.decode('utf-8')
        except (UnicodeDecodeError, ValueError):
            return text_bytes.decode('utf-8', errors='ignore')
    
    def calculate_capacity(self, image_path: str) -> int:
        """
        Calculate maximum payload capacity of image in characters.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Maximum number of characters that can be hidden
        """
        try:
            with Image.open(image_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                width, height = img.size
                # 3 bits per pixel (RGB), 8 bits per character
                total_bits = width * height * 3
                # Reserve space for delimiter
                available_bits = total_bits - len(self.DELIMITER)
                return available_bits // 8
        except Exception:
            return 0
    
    def validate_image(self, image_path: str) -> Optional[str]:
        """
        Validate image file for steganography operations.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Error message if invalid, None if valid
        """
        if not os.path.exists(image_path):
            return f"Image file not found: {image_path}"
        
        try:
            with Image.open(image_path) as img:
                # Check if image can be loaded
                img.verify()
            
            # Re-open for mode checking (verify() closes the image)
            with Image.open(image_path) as img:
                if img.mode not in ['RGB', 'RGBA', 'L', 'P']:
                    return f"Unsupported image mode: {img.mode}"
                
                # Check minimum size
                if img.size[0] < 10 or img.size[1] < 10:
                    return "Image too small for steganography (minimum 10x10 pixels)"
                
        except Exception as e:
            return f"Invalid image file: {str(e)}"
        
        return None
    
    def encode_message(self, image_path: str, output_path: str, message: str) -> Dict[str, Any]:
        """
        Hide message in image using LSB steganography.
        
        Args:
            image_path: Path to input image
            output_path: Path for output image
            message: Text message to hide
            
        Returns:
            Dictionary with operation results
        """
        start_time = time.perf_counter()
        
        try:
            # Validate input image
            error = self.validate_image(image_path)
            if error:
                return {
                    'success': False,
                    'saved_path': None,
                    'capacity_used': 0,
                    'capacity_total': 0,
                    'duration': time.perf_counter() - start_time,
                    'error': error
                }
            
            # Check if message is empty
            if not message:
                return {
                    'success': False,
                    'saved_path': None,
                    'capacity_used': 0,
                    'capacity_total': 0,
                    'duration': time.perf_counter() - start_time,
                    'error': "Message cannot be empty"
                }
            
            # Open and prepare image
            with Image.open(image_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                
                # Calculate capacity
                capacity = self.calculate_capacity(image_path)
                message_length = len(message)
                
                if message_length > capacity:
                    return {
                        'success': False,
                        'saved_path': None,
                        'capacity_used': message_length,
                        'capacity_total': capacity,
                        'duration': time.perf_counter() - start_time,
                        'error': f"Message too large! Required: {message_length} chars, Available: {capacity} chars"
                    }
                
                # Convert message to binary with delimiter
                binary_message = self.text_to_binary(message) + self.DELIMITER
                
                # Get pixel data
                pixels = list(img.getdata())
                new_pixels = []
                bit_index = 0
                
                for pixel in pixels:
                    r, g, b = pixel[:3]
                    
                    # Modify LSB of red channel
                    if bit_index < len(binary_message):
                        r = (r & 0xFE) | int(binary_message[bit_index])
                        bit_index += 1
                    
                    # Modify LSB of green channel
                    if bit_index < len(binary_message):
                        g = (g & 0xFE) | int(binary_message[bit_index])
                        bit_index += 1
                    
                    # Modify LSB of blue channel
                    if bit_index < len(binary_message):
                        b = (b & 0xFE) | int(binary_message[bit_index])
                        bit_index += 1
                    
                    # Preserve alpha channel if present
                    if len(pixel) == 4:
                        new_pixels.append((r, g, b, pixel[3]))
                    else:
                        new_pixels.append((r, g, b))
                    
                    # Break if all bits encoded
                    if bit_index >= len(binary_message):
                        new_pixels.extend(pixels[len(new_pixels):])
                        break
                
                # Create and save new image
                new_img = Image.new(img.mode, img.size)
                new_img.putdata(new_pixels)
                
                # Ensure output directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Save as PNG to preserve quality
                if not output_path.lower().endswith('.png'):
                    output_path = os.path.splitext(output_path)[0] + '.png'
                
                new_img.save(output_path, "PNG")
                
                duration = time.perf_counter() - start_time
                
                return {
                    'success': True,
                    'saved_path': output_path,
                    'capacity_used': message_length,
                    'capacity_total': capacity,
                    'message_bits': len(binary_message) - len(self.DELIMITER),
                    'duration': round(duration, 3),
                    'error': None
                }
                
        except Exception as e:
            return {
                'success': False,
                'saved_path': None,
                'capacity_used': 0,
                'capacity_total': 0,
                'duration': time.perf_counter() - start_time,
                'error': f"Encoding failed: {str(e)}"
            }
    
    def decode_message(self, image_path: str) -> Dict[str, Any]:
        """
        Extract hidden message from image.
        
        Args:
            image_path: Path to image containing hidden message
            
        Returns:
            Dictionary with extraction results
        """
        start_time = time.perf_counter()
        
        try:
            # Validate input image
            error = self.validate_image(image_path)
            if error:
                return {
                    'success': False,
                    'message': None,
                    'message_length': 0,
                    'bits_extracted': 0,
                    'duration': time.perf_counter() - start_time,
                    'error': error
                }
            
            with Image.open(image_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                
                pixels = list(img.getdata())
                binary_data = ""
                
                # Extract bits from LSB of each channel
                for pixel in pixels:
                    r, g, b = pixel[:3]
                    binary_data += str(r & 1)
                    binary_data += str(g & 1)
                    binary_data += str(b & 1)
                    
                    # Check for delimiter periodically to save time
                    if len(binary_data) % 96 == 0:  # Check every 32 pixels
                        if self.DELIMITER in binary_data:
                            break
                
                # Find delimiter
                delimiter_pos = binary_data.find(self.DELIMITER)
                if delimiter_pos == -1:
                    return {
                        'success': False,
                        'message': None,
                        'message_length': 0,
                        'bits_extracted': len(binary_data),
                        'duration': time.perf_counter() - start_time,
                        'error': "No hidden message found in this image"
                    }
                
                # Extract and decode message
                message_binary = binary_data[:delimiter_pos]
                
                # Ensure we have complete bytes
                if len(message_binary) % 8 != 0:
                    message_binary += '0' * (8 - len(message_binary) % 8)
                
                decoded_text = self.binary_to_text(message_binary)
                duration = time.perf_counter() - start_time
                
                return {
                    'success': True,
                    'message': decoded_text,
                    'message_length': len(decoded_text),
                    'bits_extracted': len(message_binary),
                    'delimiter_position': delimiter_pos,
                    'duration': round(duration, 3),
                    'error': None
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': None,
                'message_length': 0,
                'bits_extracted': 0,
                'duration': time.perf_counter() - start_time,
                'error': f"Decoding failed: {str(e)}"
            }


def encode_text_in_image(input_image: str, output_image: str, message: str) -> Dict[str, Any]:
    """
    Hide message in image using LSB steganography.
    
    Args:
        input_image: Path to input image file
        output_image: Path for output image file
        message: Text message to hide
    
    Returns:
        Dictionary with operation results:
        - "success": bool - Whether operation succeeded
        - "saved_path": str|None - Path to saved image or None
        - "capacity_used": int - Characters used
        - "capacity_total": int - Total capacity available
        - "duration": float - Operation duration in seconds
        - "error": str|None - Error message or None
    """
    if not PILLOW_AVAILABLE:
        return {
            'success': False,
            'saved_path': None,
            'capacity_used': 0,
            'capacity_total': 0,
            'duration': 0,
            'error': 'Pillow library not installed. Install with: pip install Pillow'
        }
    
    stego = LSBSteganography()
    return stego.encode_message(input_image, output_image, message)


def decode_text_from_image(input_image: str) -> Dict[str, Any]:
    """
    Extract hidden message from image.
    
    Args:
        input_image: Path to image file containing hidden message
    
    Returns:
        Dictionary with extraction results:
        - "success": bool - Whether operation succeeded
        - "message": str|None - Extracted message or None
        - "message_length": int - Length of extracted message
        - "duration": float - Operation duration in seconds
        - "error": str|None - Error message or None
    """
    if not PILLOW_AVAILABLE:
        return {
            'success': False,
            'message': None,
            'message_length': 0,
            'duration': 0,
            'error': 'Pillow library not installed. Install with: pip install Pillow'
        }
    
    stego = LSBSteganography()
    return stego.decode_message(input_image)


def get_image_capacity(image_path: str) -> Dict[str, Any]:
    """
    Calculate steganography capacity of an image.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary with capacity information
    """
    if not PILLOW_AVAILABLE:
        return {
            'success': False,
            'capacity': 0,
            'width': 0,
            'height': 0,
            'error': 'Pillow library not installed'
        }
    
    try:
        stego = LSBSteganography()
        capacity = stego.calculate_capacity(image_path)
        
        with Image.open(image_path) as img:
            width, height = img.size
            mode = img.mode
            
        return {
            'success': True,
            'capacity': capacity,
            'width': width,
            'height': height,
            'mode': mode,
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'capacity': 0,
            'width': 0,
            'height': 0,
            'error': f"Failed to analyze image: {str(e)}"
        }


def validate_image_for_steganography(image_path: str) -> Dict[str, Any]:
    """
    Validate if an image is suitable for steganography operations.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary with validation results
    """
    if not PILLOW_AVAILABLE:
        return {
            'valid': False,
            'error': 'Pillow library not installed'
        }
    
    stego = LSBSteganography()
    error = stego.validate_image(image_path)
    
    return {
        'valid': error is None,
        'error': error
    }


if __name__ == "__main__":
    # Example usage and testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Elbanna Steganography Tool")
    parser.add_argument("command", choices=['encode', 'decode', 'capacity'], help="Operation to perform")
    parser.add_argument("-i", "--input", required=True, help="Input image path")
    parser.add_argument("-o", "--output", help="Output image path (for encode)")
    parser.add_argument("-m", "--message", help="Message to hide (for encode)")
    parser.add_argument("--test", action="store_true", help="Run test operations")
    
    args = parser.parse_args()
    
    print("Elbanna Steganography Tool v1.0")
    print("="*40)
    
    if args.test:
        # Create a test image and message
        test_image = "test_input.png"
        test_output = "test_output.png"
        test_message = "Hello, this is a secret message hidden in the image!"
        
        print("Creating test image...")
        # Create a simple test image
        if PILLOW_AVAILABLE:
            test_img = Image.new('RGB', (200, 200), color='red')
            test_img.save(test_image)
            
            print(f"Encoding message: '{test_message}'")
            result = encode_text_in_image(test_image, test_output, test_message)
            print(f"Encode result: {result}")
            
            if result['success']:
                print("\nDecoding message...")
                decode_result = decode_text_from_image(test_output)
                print(f"Decode result: {decode_result}")
                
                if decode_result['success']:
                    print(f"\nOriginal: '{test_message}'")
                    print(f"Decoded:  '{decode_result['message']}'")
                    print(f"Match: {test_message == decode_result['message']}")
        
    elif args.command == "capacity":
        result = get_image_capacity(args.input)
        print(f"Image capacity analysis:")
        if result['success']:
            print(f"  File: {args.input}")
            print(f"  Dimensions: {result['width']}x{result['height']}")
            print(f"  Mode: {result['mode']}")
            print(f"  Capacity: {result['capacity']} characters")
        else:
            print(f"  Error: {result['error']}")
    
    elif args.command == "encode":
        if not args.output or not args.message:
            print("Error: --output and --message required for encode operation")
        else:
            print(f"Encoding message into {args.input}...")
            result = encode_text_in_image(args.input, args.output, args.message)
            
            if result['success']:
                print(f"Success! Message hidden in: {result['saved_path']}")
                print(f"Capacity used: {result['capacity_used']}/{result['capacity_total']} characters")
                print(f"Duration: {result['duration']} seconds")
            else:
                print(f"Error: {result['error']}")
    
    elif args.command == "decode":
        print(f"Decoding message from {args.input}...")
        result = decode_text_from_image(args.input)
        
        if result['success']:
            print(f"Hidden message found:")
            print(f"  Message: '{result['message']}'")
            print(f"  Length: {result['message_length']} characters")
            print(f"  Duration: {result['duration']} seconds")
        else:
            print(f"Error: {result['error']}")
