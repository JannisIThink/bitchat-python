#!/usr/bin/env python3
"""
Unit tests for Noise handshake Android compatibility.
Tests the new reordered decrypt strategy for handshake blocks.
"""

import os
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from encryption import NoiseCipherState, NoiseCipherState as CipherState
import hashlib

def test_handshake_48byte_static_block():
    """
    Simulate Android-style 48-byte encrypted static block (no 4-byte nonce prefix).
    This is typical for Noise handshake (32-byte plaintext + 16-byte Poly1305 tag).
    
    Android's southernstorm doesn't include nonce prefix in handshake messages.
    Python should now recognize this pattern and decrypt successfully.
    """
    print("\n" + "="*70)
    print("TEST: Android-style 48-byte encrypted static block (handshake)")
    print("="*70)
    
    # Setup: create a test key and cipher
    test_key = os.urandom(32)
    static_plaintext = os.urandom(32)  # Curve25519 static key
    test_hash_ad = hashlib.sha256(b"test_handshake_hash").digest()
    
    # Encrypt as Android would (no prefix, nonce=0, with hash AD)
    nonce_bytes = b'\x00\x00\x00\x00' + (0).to_bytes(8, byteorder='little')
    cipher_enc = ChaCha20Poly1305(test_key)
    encrypted_with_tag = cipher_enc.encrypt(nonce_bytes, static_plaintext, test_hash_ad)
    
    print(f"Plaintext (32 bytes):         {static_plaintext.hex()[:32]}...")
    print(f"Hash AD:                       {test_hash_ad.hex()[:32]}...")
    print(f"Encrypted + Tag (48 bytes):   {encrypted_with_tag.hex()[:32]}...")
    print(f"Encrypted block length:        {len(encrypted_with_tag)} bytes")
    assert len(encrypted_with_tag) == 48, f"Expected 48 bytes, got {len(encrypted_with_tag)}"
    
    # Now decrypt using Python's new strategy
    print("\nAttempting decryption with new reordered strategy...")
    cipher_dec = CipherState()
    cipher_dec.initialize_key(test_key)
    
    try:
        decrypted = cipher_dec.decrypt(encrypted_with_tag, test_hash_ad)
        print(f"\n✓ DECRYPTION SUCCESSFUL")
        print(f"Decrypted plaintext:          {decrypted.hex()[:32]}...")
        
        # Verify correctness
        if decrypted == static_plaintext:
            print("✓ PLAINTEXT MATCHES - TEST PASSED")
            return True
        else:
            print("✗ Plaintext mismatch - TEST FAILED")
            return False
    except Exception as e:
        print(f"\n✗ DECRYPTION FAILED: {e} - TEST FAILED")
        return False


def test_handshake_empty_ad_variant():
    """
    Test that decryption works with empty AD (some implementations omit it).
    """
    print("\n" + "="*70)
    print("TEST: Handshake with empty AD (compatibility variant)")
    print("="*70)
    
    test_key = os.urandom(32)
    static_plaintext = os.urandom(32)
    
    # Encrypt with EMPTY AD (some peers might not use hash AD for handshake)
    nonce_bytes = b'\x00\x00\x00\x00' + (0).to_bytes(8, byteorder='little')
    cipher_enc = ChaCha20Poly1305(test_key)
    encrypted_with_tag = cipher_enc.encrypt(nonce_bytes, static_plaintext, b'')
    
    print(f"Encrypted with:    empty AD (no hash)")
    print(f"Block size:        {len(encrypted_with_tag)} bytes")
    
    # Decrypt specifying hash AD (wrong), but strategy should fallback to empty
    cipher_dec = CipherState()
    cipher_dec.initialize_key(test_key)
    test_hash_ad = hashlib.sha256(b"some_hash").digest()
    
    print("\nAttempting decryption...")
    try:
        # Pass hash AD, but cipher should try it and then fallback to empty
        decrypted = cipher_dec.decrypt(encrypted_with_tag, test_hash_ad)
        print(f"✓ Decryption succeeded (fallback to empty AD)")
        if decrypted == static_plaintext:
            print("✓ PLAINTEXT MATCHES - TEST PASSED")
            return True
        else:
            print("✗ Plaintext mismatch - TEST FAILED")
            return False
    except Exception as e:
        print(f"✗ Decryption failed: {e} - TEST FAILED")
        return False


def test_52byte_transport_prefix_format():
    """
    Test that 52-byte blocks (4-byte prefix + 48 encrypted) still work.
    These are typical for transport layer (post-handshake).
    """
    print("\n" + "="*70)
    print("TEST: 52-byte transport format with 4-byte nonce prefix")
    print("="*70)
    
    test_key = os.urandom(32)
    static_plaintext = os.urandom(32)
    
    # Encrypt with extracted nonce (transport style)
    nonce_u32 = 42
    nonce_bytes_12 = b'\x00\x00\x00\x00' + nonce_u32.to_bytes(8, byteorder='little')
    cipher_enc = ChaCha20Poly1305(test_key)
    encrypted_with_tag = cipher_enc.encrypt(nonce_bytes_12, static_plaintext, b'')
    
    # Add 4-byte nonce prefix (big-endian)
    nonce_prefix = nonce_u32.to_bytes(4, byteorder='big')
    full_message = nonce_prefix + encrypted_with_tag
    
    print(f"Nonce prefix (4 bytes):        {nonce_prefix.hex()}")
    print(f"Encrypted + tag (48 bytes):   {encrypted_with_tag.hex()[:32]}...")
    print(f"Full message (52 bytes):       {full_message.hex()[:32]}...")
    assert len(full_message) == 52, f"Expected 52 bytes, got {len(full_message)}"
    
    # Decrypt using Python's strategy
    cipher_dec = CipherState()
    cipher_dec.initialize_key(test_key)
    
    try:
        decrypted = cipher_dec.decrypt(full_message, b'')
        print(f"\n✓ DECRYPTION SUCCESSFUL")
        print(f"Decrypted plaintext:          {decrypted.hex()[:32]}...")
        
        if decrypted == static_plaintext:
            print("✓ PLAINTEXT MATCHES - TEST PASSED")
            return True
        else:
            print("✗ Plaintext mismatch - TEST FAILED")
            return False
    except Exception as e:
        print(f"\n✗ DECRYPTION FAILED: {e} - TEST FAILED")
        return False


def run_all_tests():
    """Run all compatibility tests"""
    print("\n" + "="*70)
    print("ANDROID HANDSHAKE COMPATIBILITY TESTS")
    print("="*70)
    
    results = []
    results.append(("48-byte no-prefix handshake (hash AD)", test_handshake_48byte_static_block()))
    results.append(("Handshake with empty AD fallback", test_handshake_empty_ad_variant()))
    results.append(("52-byte prefix transport (nonce=42)", test_52byte_transport_prefix_format()))
    
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} {test_name}")
    
    total_passed = sum(1 for _, r in results if r)
    total_tests = len(results)
    print(f"\nTotal: {total_passed}/{total_tests} tests passed")
    
    return all(r for _, r in results)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
