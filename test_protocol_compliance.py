#!/usr/bin/env python3
"""
Test script to verify BitChat protocol compliance.
Tests that encoding/decoding, encryption/decryption work correctly.
"""

import sys
sys.path.insert(0, '.')

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import os
import time

from binary_protocol import BinaryProtocol, BitchatPacket, MessageType
from encryption import EncryptionService

def test_binary_protocol():
    """Test binary protocol encoding/decoding"""
    print("[TEST] Binary Protocol...")
    
    # Create a simple packet
    packet = BitchatPacket(
        version=2,
        msg_type=MessageType.MESSAGE,
        ttl=7,
        timestamp=int(time.time() * 1000),
        sender_id=os.urandom(8),
        payload=b"Hello, BitChat!",
        recipient_id=None
    )
    
    # Encode
    encoded = BinaryProtocol.encode(packet)
    print(f"  Encoded: {len(encoded)} bytes")
    print(f"  Header: {encoded[:16].hex()}")
    
    # Decode
    decoded = BinaryProtocol.decode(encoded)
    if decoded is None:
        print("  [FAIL] Decoding failed!")
        return False
    
    print(f"  Decoded: type={decoded.msg_type.name}, payload_len={len(decoded.payload)}")
    
    # Verify
    if decoded.payload != packet.payload:
        print("  [FAIL] Payload mismatch!")
        return False
    
    if decoded.msg_type != packet.msg_type:
        print("  [FAIL] Message type mismatch!")
        return False
    
    print("  [PASS]")
    return True


def test_nonce_extraction():
    """Test Noise Protocol nonce extraction"""
    print("[TEST] Noise Nonce Extraction...")
    
    from encryption import NoiseCipherState
    
    # Create cipher state with key
    cipher = NoiseCipherState()
    key = os.urandom(32)
    cipher.initialize_key(key)
    
    # Encrypt some data
    plaintext = b"Test message for nonce extraction"
    ciphertext_with_nonce = cipher.encrypt(plaintext)
    
    print(f"  Input plain text: {len(plaintext)} bytes")
    print(f"  Output with nonce: {len(ciphertext_with_nonce)} bytes")
    print(f"  Format: 4-byte nonce + encrypted + 16-byte tag")
    
    # Verify format: must be at least 4 (nonce) + 16 (tag)
    if len(ciphertext_with_nonce) < 4 + 16:
        print(f"  [FAIL] Ciphertext too short! Expected >= 20, got {len(ciphertext_with_nonce)}")
        return False
    
    # Extract nonce
    nonce_bytes = ciphertext_with_nonce[:4]
    nonce_val = int.from_bytes(nonce_bytes, byteorder='big')
    print(f"  Nonce: {nonce_bytes.hex()} = {nonce_val}")
    
    # Create new cipher for decryption
    cipher2 = NoiseCipherState()
    cipher2.initialize_key(key)
    
    # Decrypt
    decrypted = cipher2.decrypt(ciphertext_with_nonce)
    
    if decrypted != plaintext:
        print(f"  [FAIL] Decryption mismatch!")
        print(f"    Expected: {plaintext}")
        print(f"    Got: {decrypted}")
        return False
    
    print("  [PASS]")
    return True


def test_handshake():
    """Test Noise XX handshake"""
    print("[TEST] Noise XX Handshake...")
    
    from encryption import NoiseHandshakeState, NoiseRole
    
    # Create initiator and responder
    initiator_key = X25519PrivateKey.generate()
    responder_key = X25519PrivateKey.generate()
    
    responder_public = responder_key.public_key()
    
    initiator = NoiseHandshakeState(NoiseRole.INITIATOR, initiator_key, responder_public)
    responder = NoiseHandshakeState(NoiseRole.RESPONDER, responder_key)
    
    try:
        # Message 1: initiator -> responder (e)
        msg1 = initiator.write_message(b'')
        print(f"  Msg1: {len(msg1)} bytes")
        
        try:
            payload1 = responder.read_message(msg1)
            print(f"  Responder received msg1")
        except Exception as e:
            print(f"  [FAIL] Responder read msg1 failed: {e}")
            return False
        
        # Message 2: responder -> initiator (e, ee, s, es)
        try:
            msg2 = responder.write_message(b'')
            print(f"  Msg2: {len(msg2)} bytes")
        except Exception as e:
            print(f"  [FAIL] Responder write msg2 failed: {e}")
            return False
        
        try:
            payload2 = initiator.read_message(msg2)
            print(f"  Initiator received msg2")
        except Exception as e:
            print(f"  [FAIL] Initiator read msg2 failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Message 3: initiator -> responder (s, se)
        try:
            msg3 = initiator.write_message(b'')
            print(f"  Msg3: {len(msg3)} bytes")
        except Exception as e:
            print(f"  [FAIL] Initiator write msg3 failed: {e}")
            return False
        
        try:
            payload3 = responder.read_message(msg3)
            print(f"  Responder received msg3")
        except Exception as e:
            print(f"  [FAIL] Responder read msg3 failed: {e}")
            return False
        
        # Check handshake complete
        if not initiator.is_handshake_complete():
            print("  [FAIL] Initiator handshake not complete!")
            return False
        
        if not responder.is_handshake_complete():
            print("  [FAIL] Responder handshake not complete!")
            return False
        
        print("  [PASS] Handshake successful")
        return True
        
    except Exception as e:
        print(f"  [FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("=" * 60)
    print("BitChat Protocol Compliance Tests")
    print("=" * 60)
    
    tests = [
        test_binary_protocol,
        test_nonce_extraction,
        test_handshake,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
        print()
    
    print("=" * 60)
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    
    if all(results):
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed")
        return 1


if __name__ == "__main__":
    exit(main())
