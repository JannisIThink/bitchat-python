#!/usr/bin/env python3
"""
Diagnostic test to verify Python's Noise XX handshake interpretation.
"""

import sys
sys.path.insert(0, '.')

from encryption import NoiseRole, NoiseHandshakeState
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def test_initiator_message_2_pattern():
    """Test what pattern the initiator sees in message 2"""
    print("[DIAGNOSTIC] Checking Initiator's Message 2 Pattern")
    print("=" * 70)
    
    # Initiator setup
    initiator_static = X25519PrivateKey.generate()
    responder_static = X25519PrivateKey.generate()
    responder_public = responder_static.public_key()
    
    initiator = NoiseHandshakeState(NoiseRole.INITIATOR, initiator_static, responder_public)
    responder = NoiseHandshakeState(NoiseRole.RESPONDER, responder_static)
    
    print(f"\nInitiator role: {initiator.role}")
    print(f"Responder role: {responder.role}")
    print(f"\nMessage patterns defined:")
    for i, pattern_list in enumerate(initiator.message_patterns, 1):
        print(f"  Message {i}: {' -> '.join(pattern_list)}")
    
    print("\n" + "=" * 70)
    print("[STEP 1] Initiator sends Message 1")
    msg1 = initiator.write_message(b'')
    print(f"  Sent {len(msg1)} bytes (should be 32 for ephemeral)")
    print(f"  Current pattern index after write: {initiator.current_pattern}")
    
    print("\n[STEP 2] Responder receives Message 1")
    payload1 = responder.read_message(msg1)
    print(f"  Current pattern index after read: {responder.current_pattern}")
    
    print("\n[STEP 3] Responder sends Message 2")
    msg2 = responder.write_message(b'')
    print(f"  Sent {len(msg2)} bytes (should be ~80: 32 ephemeral + 48 encrypted)")
    print(f"  Breakdown: ephemeral_pub(32) + encrypted_static(32+16) = 80")
    print(f"  Current pattern index after write: {responder.current_pattern}")
    print(f"  Responder is_handshake_complete(): {responder.is_handshake_complete()}")
    
    print("\n[STEP 4] Initiator processes Message 2 patterns")
    print(f"  Before read - Pattern index: {initiator.current_pattern}")
    print(f"  Patterns to process: {initiator.message_patterns[initiator.current_pattern]}")
    
    try:
        payload2 = initiator.read_message(msg2)
        print(f"  ✓ Message 2 processed successfully")
        print(f"  After read - Pattern index: {initiator.current_pattern}")
        print(f"  Initiator is_handshake_complete(): {initiator.is_handshake_complete()}")
        
        print("\n[STEP 5] Initiator sends Message 3")
        msg3 = initiator.write_message(b'')
        print(f"  Sent {len(msg3)} bytes")
        print(f"  After write - Pattern index: {initiator.current_pattern}")
        print(f"  Initiator is_handshake_complete(): {initiator.is_handshake_complete()}")
        
        print("\n[STEP 6] Responder receives Message 3")
        payload3 = responder.read_message(msg3)
        print(f"  After read - Pattern index: {responder.current_pattern}")
        print(f"  Responder is_handshake_complete(): {responder.is_handshake_complete()}")
        
        print("\n" + "=" * 70)
        print("✓ FULL HANDSHAKE SUCCEEDED LOCALLY")
        print("Conclusion: Python's XX pattern interpretation is correct for same-version handshakes")
        return True
        
    except Exception as e:
        print(f"  ✗ Message 2 processing FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_initiator_message_2_pattern()
    sys.exit(0 if success else 1)
