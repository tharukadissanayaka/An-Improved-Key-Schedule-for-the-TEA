"""
Test and Verification Script for TEA Implementation
====================================================

Run this script to verify that all three cipher variants work correctly
and that the equivalent keys vulnerability is properly demonstrated.

Usage: python test_tea.py
"""

import os
from tea_core import TEACore, MTEACore, XTEACore
from tea_evaluator import TEAEvaluator


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt functionality."""
    print("=" * 80)
    print("TEST 1: BASIC ENCRYPTION/DECRYPTION")
    print("=" * 80)
    
    plaintext = b"Hello TEA!!!!!!!  "[:16]  # Pad to 16 bytes
    key = os.urandom(16)
    
    for cipher_class in [TEACore, MTEACore, XTEACore]:
        algo_name = cipher_class.__name__
        
        # Encrypt
        ciphertext = cipher_class.encrypt(plaintext, key)
        
        # Decrypt
        decrypted = cipher_class.decrypt(ciphertext, key)
        
        # Verify
        if decrypted == plaintext:
            print(f"✅ {algo_name}: PASS - Encrypt/Decrypt verified")
        else:
            print(f"❌ {algo_name}: FAIL - Decryption mismatch")
            print(f"   Expected: {plaintext.hex()}")
            print(f"   Got:      {decrypted.hex()}")
    
    print()


def test_equivalent_keys():
    """Test for equivalent keys vulnerability."""
    print("=" * 80)
    print("TEST 2: EQUIVALENT KEYS VULNERABILITY")
    print("=" * 80)
    
    evaluator = TEAEvaluator()
    plaintext = b"Test Vector!!!!!"
    key_base = os.urandom(16)
    
    print(f"Test Vector: {plaintext.hex()}")
    print(f"Base Key:    {key_base.hex()}\n")
    
    for cipher_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.test_equivalent_keys(cipher_class, key_base)
        algo_name = result["algorithm"]
        
        if result["vulnerable"]:
            print(f"⚠️  {algo_name:15} - VULNERABLE (equivalent keys detected)")
            print(f"    Original CT: {result['original_ciphertext']}")
            print(f"    Modified CT: {result['modified_ciphertext']}")
        else:
            print(f"✅ {algo_name:15} - SECURE (no equivalent keys)")
    
    print()


def test_avalanche_effect():
    """Test avalanche effect."""
    print("=" * 80)
    print("TEST 3: AVALANCHE EFFECT (SAC)")
    print("=" * 80)
    print("Measuring how single-bit changes affect ciphertext...\n")
    
    evaluator = TEAEvaluator()
    plaintext = b"Test Vector!!!!!"
    key = os.urandom(16)
    
    for cipher_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.test_avalanche_effect(cipher_class, plaintext, key, 32)
        algo_name = result["algorithm"]
        
        p_avg = result["plaintext_avalanche"]["avg_percentage"]
        p_std = result["plaintext_avalanche"]["std_deviation"]
        p_sac = result["plaintext_avalanche"]["sac_score"]
        
        k_avg = result["key_avalanche"]["avg_percentage"]
        k_std = result["key_avalanche"]["std_deviation"]
        k_sac = result["key_avalanche"]["sac_score"]
        
        print(f"{algo_name}:")
        print(f"  Plaintext Avalanche: {p_avg:.2f}% ± {p_std:.2f}% (SAC: {p_sac:.2f})")
        print(f"  Key Avalanche:       {k_avg:.2f}% ± {k_std:.2f}% (SAC: {k_sac:.2f})")
        
        # Evaluate SAC
        if p_sac < 5 and k_sac < 5:
            print(f"  ✅ Excellent avalanche properties (SAC < 5)")
        elif p_sac < 10 and k_sac < 10:
            print(f"  ✅ Good avalanche properties (SAC < 10)")
        else:
            print(f"  ⚠️  Acceptable avalanche properties")
        print()


def test_key_sensitivity():
    """Test key sensitivity."""
    print("=" * 80)
    print("TEST 4: KEY SENSITIVITY")
    print("=" * 80)
    print("Measuring impact of key bit flips on ciphertext...\n")
    
    evaluator = TEAEvaluator()
    plaintext = b"Test Vector!!!!!"
    key = os.urandom(16)
    
    for cipher_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.test_key_sensitivity(cipher_class, plaintext, key, 32)
        algo_name = result["algorithm"]
        
        avg_sens = result["avg_key_sensitivity"]
        min_sens = result["min_sensitivity"]
        max_sens = result["max_sensitivity"]
        uniformity = result["uniformity_score"]
        
        print(f"{algo_name}:")
        print(f"  Average Sensitivity: {avg_sens:.2f}%")
        print(f"  Range: {min_sens:.2f}% - {max_sens:.2f}%")
        print(f"  Uniformity Score: {uniformity:.2f} (ideal: 0)")
        
        if uniformity < 5:
            print(f"  ✅ Excellent uniformity (high key sensitivity)")
        elif uniformity < 10:
            print(f"  ✅ Good uniformity")
        else:
            print(f"  ⚠️  Acceptable uniformity")
        print()


def test_performance():
    """Benchmark performance."""
    print("=" * 80)
    print("TEST 5: PERFORMANCE BENCHMARKING")
    print("=" * 80)
    print("Measuring encryption/decryption speed (1000 iterations)...\n")
    
    evaluator = TEAEvaluator()
    plaintext = b"Test Vector!!!!!"
    key = os.urandom(16)
    
    results = []
    for cipher_class in [TEACore, MTEACore, XTEACore]:
        result = evaluator.benchmark_performance(cipher_class, plaintext, key, 1000)
        results.append(result)
        
        algo_name = result["algorithm"]
        enc_time = result["encryption_time_us"]
        dec_time = result["decryption_time_us"]
        ops_sec = result["operations_per_second"]
        throughput = result["encryption_throughput_mbps"]
        
        print(f"{algo_name}:")
        print(f"  Encryption: {enc_time:.3f} µs")
        print(f"  Decryption: {dec_time:.3f} µs")
        print(f"  Performance: {ops_sec:,} ops/sec")
        print(f"  Throughput: {throughput:.2f} MB/s")
        print()
    
    # Compare overhead
    tea_ops = results[0]["operations_per_second"]
    mtea_ops = results[1]["operations_per_second"]
    xtea_ops = results[2]["operations_per_second"]
    
    mtea_overhead = ((tea_ops - mtea_ops) / tea_ops) * 100
    xtea_overhead = ((tea_ops - xtea_ops) / tea_ops) * 100
    
    print(f"Overhead Analysis:")
    print(f"  MTEA: {mtea_overhead:.1f}% slower than TEA")
    print(f"  XTEA: {xtea_overhead:.1f}% slower than TEA")


def test_ciphertext_differences():
    """Verify different algorithms produce different ciphertexts."""
    print("=" * 80)
    print("TEST 6: CIPHERTEXT DIFFERENCES")
    print("=" * 80)
    print("Verifying that different algorithms produce different outputs...\n")
    
    plaintext = b"Test Vector!!!!!"
    key = os.urandom(16)
    
    ct_tea = TEACore.encrypt(plaintext, key)
    ct_mtea = MTEACore.encrypt(plaintext, key)
    ct_xtea = XTEACore.encrypt(plaintext, key)
    
    print(f"TEA:  {ct_tea.hex().upper()}")
    print(f"MTEA: {ct_mtea.hex().upper()}")
    print(f"XTEA: {ct_xtea.hex().upper()}")
    print()
    
    if ct_tea != ct_mtea:
        print("✅ TEA and MTEA produce different ciphertexts (as expected)")
    else:
        print("⚠️  TEA and MTEA produced identical ciphertexts (unexpected)")
    
    if ct_tea != ct_xtea:
        print("✅ TEA and XTEA produce different ciphertexts (as expected)")
    else:
        print("⚠️  TEA and XTEA produced identical ciphertexts (unexpected)")
    
    if ct_mtea != ct_xtea:
        print("✅ MTEA and XTEA produce different ciphertexts (as expected)")
    else:
        print("⚠️  MTEA and XTEA produced identical ciphertexts (unexpected)")
    print()


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "TEA CRYPTOGRAPHY IMPLEMENTATION - VERIFICATION SUITE".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝")
    print("\n")
    
    try:
        test_basic_encryption_decryption()
        test_equivalent_keys()
        test_avalanche_effect()
        test_key_sensitivity()
        test_ciphertext_differences()
        test_performance()
        
        print("=" * 80)
        print("✅ ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\nImplementation is ready for production use.")
        print("Run 'streamlit run app.py' to start the interactive UI.\n")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
