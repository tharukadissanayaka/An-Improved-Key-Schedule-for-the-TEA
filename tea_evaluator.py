"""
TEA Evaluation Suite
===================

Comprehensive testing and vulnerability analysis for:
1. Equivalent Keys Detection
2. Avalanche Effect Analysis
3. Key Sensitivity Testing
4. Performance Benchmarking

References:
[14, 15] Cryptographic testing methodologies
[20] Avalanche and key sensitivity criteria
"""

import os
import time
from typing import Dict, List, Tuple
from tea_core import TEACore, MTEACore, XTEACore


class TEAEvaluator:
    """Comprehensive evaluation suite for TEA implementations."""

    @staticmethod
    def count_bit_differences(data1: bytes, data2: bytes) -> int:
        """
        Count the number of differing bits between two byte sequences.
        
        Args:
            data1, data2: Byte sequences to compare
            
        Returns:
            Number of positions where bits differ
        """
        diff_count = 0
        for b1, b2 in zip(data1, data2):
            xor_result = b1 ^ b2
            # Count set bits using Brian Kernighan's algorithm
            while xor_result:
                xor_result &= xor_result - 1
                diff_count += 1
        return diff_count

    @staticmethod
    def bytes_to_int(data: bytes) -> int:
        """Convert bytes to integer."""
        return int.from_bytes(data, byteorder='big')

    @staticmethod
    def int_to_bytes(value: int, length: int = 8) -> bytes:
        """Convert integer to bytes."""
        return value.to_bytes(length, byteorder='big')

    @classmethod
    def test_equivalent_keys(cls, tea_class, key_base: bytes) -> Dict[str, any]:
        """
        Test for the Equivalent Keys Vulnerability.
        
        VULNERABILITY DESCRIPTION:
        Standard TEA can have up to 4 equivalent keys per encryption due to
        toggling high-order bits of K0, K1, K2, K3. This reduces the effective
        key space from 2^128 to 2^126.
        
        TEST METHOD:
        1. Generate plaintext
        2. Encrypt with original key
        3. Toggle high bits of all 4 key subwords
        4. Encrypt with modified key
        5. Compare ciphertexts: if identical → vulnerability present
        
        Args:
            tea_class: TEACore, MTEACore, or XTEACore
            key_base: Base 128-bit key
            
        Returns:
            Dict with test results and vulnerability assessment
        """
        # Test plaintext
        plaintext = b"Hello TEA!!!!!!!"  # 16 bytes
        
        # Encrypt with original key
        ciphertext_original = tea_class.encrypt(plaintext, key_base)
        
        # Create equivalent key by toggling high-order bits
        # This exploits the additive structure of TEA's key schedule
        key_modified = bytearray(key_base)
        
        # Toggle bit 31 (high bit) of each 32-bit key word
        # K0 (bytes 0-3), K1 (bytes 4-7), K2 (bytes 8-11), K3 (bytes 12-15)
        for offset in [0, 4, 8, 12]:
            key_modified[offset] ^= 0x80  # Toggle MSB
        
        key_modified = bytes(key_modified)
        
        # Encrypt with modified key
        ciphertext_modified = tea_class.encrypt(plaintext, key_modified)
        
        # Check if ciphertexts are identical (vulnerability indicator)
        is_vulnerable = (ciphertext_original == ciphertext_modified)
        
        return {
            "algorithm": tea_class.__name__,
            "vulnerable": is_vulnerable,
            "original_ciphertext": ciphertext_original.hex()[:16] + "...",
            "modified_ciphertext": ciphertext_modified.hex()[:16] + "...",
            "plaintext": plaintext.hex(),
            "key_base": key_base.hex(),
            "key_modified": key_modified.hex(),
            "description": (
                "VULNERABLE: Equivalent keys detected!" if is_vulnerable
                else "SECURE: Equivalent keys not detected."
            )
        }

    @classmethod
    def test_avalanche_effect(cls, tea_class, plaintext: bytes, key: bytes, 
                              num_iterations: int = 100) -> Dict[str, any]:
        """
        Test the Avalanche Effect / Strict Avalanche Criterion (SAC).
        
        DEFINITION:
        The avalanche effect measures how a small change in input
        (single bit flip) causes a significant change in output.
        
        IDEAL SAC CRITERION:
        - Flipping any single bit in plaintext should flip ~50% of ciphertext bits
        - Flipping any single bit in key should flip ~50% of ciphertext bits
        
        TEST METHOD:
        1. Encrypt original plaintext
        2. For each bit position in plaintext:
           - Flip the bit
           - Encrypt modified plaintext
           - Count differing bits in ciphertext
           - Calculate percentage of flipped bits
        3. Report average and standard deviation
        
        Args:
            tea_class: TEACore, MTEACore, or XTEACore
            plaintext: Test plaintext (8-64 bytes)
            key: Test key (16 bytes)
            num_iterations: Bits to test (default: all bits in plaintext)
            
        Returns:
            Dict with avalanche statistics
        """
        # Pad plaintext to 8 bytes if needed
        if len(plaintext) < 8:
            plaintext = plaintext + b'\x00' * (8 - len(plaintext))
        
        num_iterations = min(num_iterations, len(plaintext) * 8)
        
        original_ciphertext = tea_class.encrypt(plaintext, key)
        
        plaintext_avalanche = []
        key_avalanche = []
        
        # Test plaintext bit flips
        for bit_pos in range(num_iterations):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            
            plaintext_modified = bytearray(plaintext)
            plaintext_modified[byte_idx] ^= (1 << bit_idx)
            plaintext_modified = bytes(plaintext_modified)
            
            modified_ciphertext = tea_class.encrypt(plaintext_modified, key)
            
            bit_diff = cls.count_bit_differences(original_ciphertext, modified_ciphertext)
            # Calculate percentage of bits flipped in output
            total_bits = len(original_ciphertext) * 8
            percentage = (bit_diff / total_bits) * 100
            plaintext_avalanche.append(percentage)
        
        # Test key bit flips
        for bit_pos in range(min(num_iterations, 16 * 8)):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            
            key_modified = bytearray(key)
            key_modified[byte_idx] ^= (1 << bit_idx)
            key_modified = bytes(key_modified)
            
            modified_ciphertext = tea_class.encrypt(plaintext, key_modified)
            
            bit_diff = cls.count_bit_differences(original_ciphertext, modified_ciphertext)
            total_bits = len(original_ciphertext) * 8
            percentage = (bit_diff / total_bits) * 100
            key_avalanche.append(percentage)
        
        # Calculate statistics
        def calc_stats(data):
            avg = sum(data) / len(data)
            variance = sum((x - avg) ** 2 for x in data) / len(data)
            std_dev = variance ** 0.5
            return avg, std_dev, min(data), max(data)
        
        p_avg, p_std, p_min, p_max = calc_stats(plaintext_avalanche)
        k_avg, k_std, k_min, k_max = calc_stats(key_avalanche)
        
        return {
            "algorithm": tea_class.__name__,
            "plaintext_avalanche": {
                "avg_percentage": round(p_avg, 2),
                "std_deviation": round(p_std, 2),
                "min_percentage": round(p_min, 2),
                "max_percentage": round(p_max, 2),
                "sac_score": round(abs(50 - p_avg), 2),  # Distance from ideal 50%
                "samples": len(plaintext_avalanche)
            },
            "key_avalanche": {
                "avg_percentage": round(k_avg, 2),
                "std_deviation": round(k_std, 2),
                "min_percentage": round(k_min, 2),
                "max_percentage": round(k_max, 2),
                "sac_score": round(abs(50 - k_avg), 2),
                "samples": len(key_avalanche)
            }
        }

    @classmethod
    def test_key_sensitivity(cls, tea_class, plaintext: bytes, 
                            key_base: bytes, num_flips: int = 50) -> Dict[str, any]:
        """
        Test Key Sensitivity: How sensitive is the ciphertext to key changes?
        
        DEFINITION:
        Measures the minimum changes in ciphertext when any single bit
        of the key is flipped while keeping plaintext constant.
        
        IDEAL PROPERTY:
        - Each key bit flip should affect ~50% of ciphertext bits
        - Indicates strong key diffusion
        
        Args:
            tea_class: Cipher class to test
            plaintext: Test plaintext
            key_base: Base key
            num_flips: Number of key bits to flip
            
        Returns:
            Key sensitivity metrics
        """
        original_ciphertext = tea_class.encrypt(plaintext, key_base)
        
        sensitivity_results = []
        
        for bit_pos in range(min(num_flips, 128)):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            
            key_modified = bytearray(key_base)
            key_modified[byte_idx] ^= (1 << bit_idx)
            key_modified = bytes(key_modified)
            
            modified_ciphertext = tea_class.encrypt(plaintext, key_modified)
            
            bit_diff = cls.count_bit_differences(original_ciphertext, modified_ciphertext)
            total_bits = len(original_ciphertext) * 8
            percentage = (bit_diff / total_bits) * 100
            
            sensitivity_results.append({
                "key_bit_position": bit_pos,
                "bits_affected_in_ciphertext": bit_diff,
                "percentage_affected": round(percentage, 2)
            })
        
        # Calculate aggregate statistics
        percentages = [r["percentage_affected"] for r in sensitivity_results]
        avg_percentage = sum(percentages) / len(percentages)
        
        return {
            "algorithm": tea_class.__name__,
            "avg_key_sensitivity": round(avg_percentage, 2),
            "min_sensitivity": round(min(percentages), 2),
            "max_sensitivity": round(max(percentages), 2),
            "uniformity_score": round(abs(50 - avg_percentage), 2),
            "detailed_results": sensitivity_results[:10]  # Return first 10 for brevity
        }

    @classmethod
    def benchmark_performance(cls, tea_class, plaintext: bytes, 
                             key: bytes, iterations: int = 1000) -> Dict[str, float]:
        """
        Benchmark encryption and decryption performance.
        
        Args:
            tea_class: Cipher class to benchmark
            plaintext: Test plaintext
            key: Test key (16 bytes)
            iterations: Number of iterations for timing
            
        Returns:
            Performance metrics in microseconds and operations/second
        """
        # Warmup
        for _ in range(10):
            tea_class.encrypt(plaintext, key)
        
        # Benchmark encryption
        start = time.perf_counter()
        for _ in range(iterations):
            tea_class.encrypt(plaintext, key)
        encrypt_time = (time.perf_counter() - start) / iterations * 1_000_000  # microseconds
        
        # Benchmark decryption
        ciphertext = tea_class.encrypt(plaintext, key)
        start = time.perf_counter()
        for _ in range(iterations):
            tea_class.decrypt(ciphertext, key)
        decrypt_time = (time.perf_counter() - start) / iterations * 1_000_000
        
        return {
            "algorithm": tea_class.__name__,
            "encryption_time_us": round(encrypt_time, 3),
            "decryption_time_us": round(decrypt_time, 3),
            "operations_per_second": round(1_000_000 / encrypt_time),
            "encryption_throughput_mbps": round((len(plaintext) / encrypt_time) * 1000, 2)
        }

    @classmethod
    def run_full_evaluation(cls, plaintext: bytes = b"Test Vector!!!!!", 
                          key: bytes = None,
                          num_iterations: int = 50) -> Dict:
        """
        Run comprehensive evaluation on all three cipher variants.
        
        Returns a complete evaluation report comparing TEA, MTEA, and XTEA.
        """
        if key is None:
            key = os.urandom(16)
        
        results = {
            "plaintext": plaintext.hex(),
            "key": key.hex(),
            "timestamp": time.time(),
            "algorithms": {}
        }
        
        for tea_class in [TEACore, MTEACore, XTEACore]:
            algo_name = tea_class.__name__
            results["algorithms"][algo_name] = {
                "equivalent_keys_test": cls.test_equivalent_keys(tea_class, key),
                "avalanche_effect": cls.test_avalanche_effect(tea_class, plaintext, key, num_iterations),
                "key_sensitivity": cls.test_key_sensitivity(tea_class, plaintext, key),
                "performance": cls.benchmark_performance(tea_class, plaintext, key)
            }
        
        return results


# Example usage and testing
if __name__ == "__main__":
    evaluator = TEAEvaluator()
    
    # Test with random plaintext and key
    plaintext = b"Test Vector!!!!!"
    key = os.urandom(16)
    
    print("=" * 80)
    print("TEA EQUIVALENT KEYS TEST")
    print("=" * 80)
    
    for tea_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.test_equivalent_keys(tea_class, key)
        print(f"\n{result['algorithm']}:")
        print(f"  Status: {result['description']}")
        print(f"  Vulnerable: {result['vulnerable']}")
    
    print("\n" + "=" * 80)
    print("TEA AVALANCHE EFFECT TEST")
    print("=" * 80)
    
    for tea_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.test_avalanche_effect(tea_class, plaintext, key, 32)
        print(f"\n{result['algorithm']}:")
        print(f"  Plaintext Avalanche: {result['plaintext_avalanche']['avg_percentage']:.2f}% (SAC: {result['plaintext_avalanche']['sac_score']:.2f})")
        print(f"  Key Avalanche: {result['key_avalanche']['avg_percentage']:.2f}% (SAC: {result['key_avalanche']['sac_score']:.2f})")
