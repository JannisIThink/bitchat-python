#!/usr/bin/env python3
"""
Exhaustive brute-force debug for Android Noise handshake incompatibility.
Tests all possible HMAC/HKDF variants and nonce configurations.
"""

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
import hashlib

# Values from actual failed handshake
ee_shared = bytes.fromhex("b4841b9307403e61cb7ba71cf176476746f3fabcbcf903e7c5a47d88e341c305")
ck_initial = bytes.fromhex("4e6f6973655f58585f32353531395f436861436861506f6c795f534841323536")
hash_state = bytes.fromhex("ae9644c7926331f0acc1c3c339c39226")
ciphertext = bytes.fromhex("1ddc9099275bb576eed329c405e4ccae53842aeec11af16af7eb4c50cce2530342c9dc8edec754bce3868b49c810f72c")

# Known "correct" derive from Python logs (unlikely to be correct since decrypt fails)
python_key = bytes.fromhex("44fec481d5ab808f6e6454035a88fe6f")

print("=" * 80)
print("EXHAUSTIVE NOISE XX HKDF/HMAC VARIANT SEARCH")
print("=" * 80)
print(f"EE Shared Secret:    {ee_shared.hex()[:32]}...")
print(f"Initial CK:          {ck_initial.hex()[:32]}...")
print(f"Hash State (AD):     {hash_state.hex()[:32]}...")
print(f"Ciphertext (48):     {ciphertext.hex()[:32]}...")
print()

candidates = []

# Variant 1: Standard Noise HKDF (what Python does)
print("[Variant 1] Standard Noise HKDF")
hmac1 = HMAC(ck_initial, hashes.SHA256())
hmac1.update(ee_shared)
prk1 = hmac1.finalize()

hmac2 = HMAC(prk1, hashes.SHA256())
hmac2.update(b'\x01')
o1_1 = hmac2.finalize()

hmac3 = HMAC(prk1, hashes.SHA256())
hmac3.update(o1_1 + b'\x02')
o2_1 = hmac3.finalize()

print(f"  PRK:      {prk1.hex()[:32]}...")
print(f"  output1:  {o1_1.hex()[:32]}...")
print(f"  output2:  {o2_1.hex()[:32]}...")
candidates.append(("Standard HKDF", o2_1))

# Variant 2: Reverse HMAC domain (swap key/data)
print("\n[Variant 2] Reverse HMAC (key=shared, data=ck)")
hmac1 = HMAC(ee_shared, hashes.SHA256())
hmac1.update(ck_initial)
prk2 = hmac1.finalize()

hmac2 = HMAC(prk2, hashes.SHA256())
hmac2.update(b'\x01')
o1_2 = hmac2.finalize()

hmac3 = HMAC(prk2, hashes.SHA256())
hmac3.update(o1_2 + b'\x02')
o2_2 = hmac3.finalize()

print(f"  PRK:      {prk2.hex()[:32]}...")
print(f"  output2:  {o2_2.hex()[:32]}...")
candidates.append(("Reverse HMAC", o2_2))

# Variant 3: PRK + info byte directly
print("\n[Variant 3] PRK as key directly (no 0x01/0x02)")
candidates.append(("PRK direct", prk1))

# Variant 4: Output of first HMAC expand
print("\n[Variant 4] First expand output (0x01)")
candidates.append(("First expand", o1_1))

# Variant 5: Shared secret direct
print("\n[Variant 5] Shared secret direct")
candidates.append(("Shared direct", ee_shared))

# Variant 6: Initial CK direct
print("\n[Variant 6] Initial CK direct")
candidates.append(("CK direct", ck_initial))

# Variant 7: Hash state as key material (edge case)
print("\n[Variant 7] Hash state as IKM")
hmac1 = HMAC(ck_initial, hashes.SHA256())
hmac1.update(hash_state)
prk7 = hmac1.finalize()

hmac2 = HMAC(prk7, hashes.SHA256())
hmac2.update(b'\x01')
o1_7 = hmac2.finalize()

hmac3 = HMAC(prk7, hashes.SHA256())
hmac3.update(o1_7 + b'\x02')
o2_7 = hmac3.finalize()

print(f"  output2:  {o2_7.hex()[:32]}...")
candidates.append(("Hash as IKM", o2_7))

# Variant 8: Try HMAC with expanded info
print("\n[Variant 8] HMAC with longer info")
hmac2 = HMAC(prk1, hashes.SHA256())
hmac2.update(b'\x01' * 16)
o1_8 = hmac2.finalize()

hmac3 = HMAC(prk1, hashes.SHA256())
hmac3.update(o1_8 + b'\x02')
o2_8 = hmac3.finalize()

print(f"  output2:  {o2_8.hex()[:32]}...")
candidates.append(("Long info", o2_8))

# Now try decrypting with each candidate key
print("\n" + "=" * 80)
print("DECRYPTION ATTEMPTS WITH VARIANTS")
print("=" * 80)

success_found = False

for variant_name, cipher_key in candidates:
    print(f"\n[{variant_name}]")
    print(f"  Key: {cipher_key.hex()[:32]}...")
    
    # Try multiple nonce values and AD variants
    for nonce_val in [0, 1, 2]:
        for ad_val in [hash_state, b'', ee_shared]:
            ad_name = "hash" if ad_val == hash_state else ("empty" if ad_val == b'' else "shared")
            try:
                nonce = b'\x00\x00\x00\x00' + nonce_val.to_bytes(8, byteorder='little')
                cipher = ChaCha20Poly1305(cipher_key)
                plaintext = cipher.decrypt(nonce, ciphertext, ad_val)
                print(f"  ✓ DECRYPTION SUCCEEDED: nonce={nonce_val}, AD={ad_name}")
                print(f"    Plaintext: {plaintext.hex()}")
                success_found = True
                break
            except Exception:
                pass
        if success_found:
            break
    if success_found:
        break

if not success_found:
    print("\n✗ No variant succeeded. Problem is likely:")
    print("  1. Different protocol name or initialization")
    print("  2. Different DH computation")
    print("  3. Different role assignment (initiator vs responder)")
    print("  4. Android using non-standard Noise variant")
