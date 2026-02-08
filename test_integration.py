#!/usr/bin/env python3
"""
Integration test to verify BitChat protocol works end-to-end with padding.
Tests that packets can be created, padded, sent, and parsed correctly.
"""

import sys
sys.path.insert(0, '.')

import os
import time
from binary_protocol import BinaryProtocol, BitchatPacket, MessageType, NoisePayloadType
from encryption import EncryptionService

def apply_pkcs7_padding(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def remove_pkcs7_padding(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    if len(data) == 0:
        return data
    padding_length = data[-1]
    if padding_length > len(data) or padding_length == 0:
        return data
    # Validate all padding bytes are correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            return data
    return data[:-padding_length]

def test_packet_with_padding():
    """Test creating and parsing packet with padding"""
    print("[TEST] Packet with PKCS#7 Padding...")
    
    # Create packet
    payload = b"Hello, BitChat!"
    packet = BitchatPacket(
        version=2,
        msg_type=MessageType.MESSAGE,
        ttl=7,
        timestamp=int(time.time() * 1000),
        sender_id=os.urandom(8),
        payload=payload,
        recipient_id=os.urandom(8),
    )
    
    # Encode without padding
    encoded = BinaryProtocol.encode(packet)
    print(f"  Encoded (no padding): {len(encoded)} bytes")
    
    # Apply PKCS#7 padding to 256 bytes
    padded = apply_pkcs7_padding(encoded, 256)
    print(f"  After PKCS#7 padding (256-byte block): {len(padded)} bytes")
    
    # Simulate transmission and remove padding
    received = remove_pkcs7_padding(padded)
    print(f"  After unpadding: {len(received)} bytes")
    
    # Decode
    decoded = BinaryProtocol.decode(received)
    if decoded is None:
        print("  [FAIL] Decoding failed after padding!")
        return False
    
    # Verify
    if decoded.payload != payload:
        print(f"  [FAIL] Payload mismatch!")
        print(f"    Expected: {payload}")
        print(f"    Got: {decoded.payload}")
        return False
    
    if decoded.msg_type != MessageType.MESSAGE:
        print("  [FAIL] Message type mismatch!")
        return False
    
    print("  [PASS] Packet with padding works correctly")
    return True

def test_multiple_message_types():
    """Test different message types"""
    print("[TEST] Multiple Message Types...")
    
    test_cases = [
        (MessageType.ANNOUNCE, b"announce_data"),
        (MessageType.MESSAGE, b"message_data"),
        (MessageType.LEAVE, b"leave_data"),
        (MessageType.NOISE_HANDSHAKE, b"handshake_msg1"),
        (MessageType.NOISE_ENCRYPTED, b"encrypted_payload"),
        (MessageType.FRAGMENT, b"fragment_data"),
        (MessageType.REQUEST_SYNC, b"sync_request"),
        (MessageType.FILE_TRANSFER, b"file_chunk"),
    ]
    
    for msg_type, payload in test_cases:
        packet = BitchatPacket(
            version=2,
            msg_type=msg_type,
            ttl=7,
            timestamp=int(time.time() * 1000),
            sender_id=os.urandom(8),
            payload=payload,
        )
        
        encoded = BinaryProtocol.encode(packet)
        decoded = BinaryProtocol.decode(encoded)
        
        if decoded is None:
            print(f"  [FAIL] {msg_type.name} encoding/decoding failed")
            return False
        
        if decoded.payload != payload or decoded.msg_type != msg_type:
            print(f"  [FAIL] {msg_type.name} mismatch")
            return False
    
    print(f"  [PASS] All {len(test_cases)} message types work correctly")
    return True

def test_sender_recipient_handling():
    """Test sender/recipient ID handling"""
    print("[TEST] Sender/Recipient ID Handling...")
    
    sender_id = os.urandom(8)
    recipient_id = os.urandom(8)
    
    # With recipient
    packet1 = BitchatPacket(
        version=2,
        msg_type=MessageType.MESSAGE,
        ttl=7,
        timestamp=int(time.time() * 1000),
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=b"Test",
    )
    
    encoded1 = BinaryProtocol.encode(packet1)
    decoded1 = BinaryProtocol.decode(encoded1)
    
    if decoded1 is None or decoded1.recipient_id != recipient_id:
        print("  [FAIL] Recipient ID not preserved")
        return False
    
    # Without recipient (broadcast)
    packet2 = BitchatPacket(
        version=2,
        msg_type=MessageType.ANNOUNCE,
        ttl=7,
        timestamp=int(time.time() * 1000),
        sender_id=sender_id,
        payload=b"Announce",
    )
    
    encoded2 = BinaryProtocol.encode(packet2)
    decoded2 = BinaryProtocol.decode(encoded2)
    
    if decoded2 is None or decoded2.recipient_id is not None:
        print("  [FAIL] Broadcast packet should not have recipient")
        return False
    
    print("  [PASS] Sender/recipient handling works correctly")
    return True

def test_large_payload():
    """Test large payload handling"""
    print("[TEST] Large Payload (> 500 bytes)...")
    
    # Create payload larger than typical fragment size
    large_payload = os.urandom(2000)
    
    packet = BitchatPacket(
        version=2,
        msg_type=MessageType.FILE_TRANSFER,
        ttl=7,
        timestamp=int(time.time() * 1000),
        sender_id=os.urandom(8),
        payload=large_payload,
    )
    
    encoded = BinaryProtocol.encode(packet)
    decoded = BinaryProtocol.decode(encoded)
    
    if decoded is None:
        print("  [FAIL] Large payload decoding failed")
        return False
    
    if decoded.payload != large_payload:
        print(f"  [FAIL] Large payload mismatch: {len(decoded.payload)} != {len(large_payload)}")
        return False
    
    print(f"  [PASS] Large payload ({len(large_payload)} bytes) handled correctly")
    return True

def main():
    print("=" * 60)
    print("BitChat Integration Tests")
    print("=" * 60)
    
    tests = [
        test_packet_with_padding,
        test_multiple_message_types,
        test_sender_recipient_handling,
        test_large_payload,
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
    
    passed = sum(results)
    total = len(results)
    
    print("=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    if all(results):
        print("✓ All integration tests passed!")
    else:
        print(f"✗ {total - passed} tests failed")
    print("=" * 60)

if __name__ == "__main__":
    main()
