"""
Binary Protocol implementation for BitChat
Implements the wire format serialization/deserialization per specification.

Packet structure (Variable length):
- Fixed header: version(1) + type(1) + ttl(1) + timestamp(8) + flags(1) + payloadLength(2-4)
- Sender ID: 8 bytes (always)
- Recipient ID: 8 bytes (if HAS_RECIPIENT flag set)
- Route: 1 + N*8 bytes (if HAS_ROUTE flag set, v2+ only)
- Original Size: 2 or 4 bytes (if IS_COMPRESSED flag set)
- Payload: variable
- Signature: 64 bytes (if HAS_SIGNATURE flag set)
"""

import struct
import time
import os
from enum import IntEnum
from typing import Optional, List, Tuple
from dataclasses import dataclass

# Protocol constants
PROTOCOL_VERSION = 2
V1_HEADER_SIZE = 14
V2_HEADER_SIZE = 16
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64
BROADCAST_RECIPIENT = b'\xFF' * 8

# Flags
FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02
FLAG_IS_COMPRESSED = 0x04
FLAG_HAS_ROUTE = 0x08
FLAG_IS_RSR = 0x10

# Field offsets in header
OFFSET_VERSION = 0
OFFSET_TYPE = 1
OFFSET_TTL = 2
OFFSET_TIMESTAMP = 3
OFFSET_FLAGS = 11
OFFSET_PAYLOAD_LENGTH = 12


class MessageType(IntEnum):
    ANNOUNCE = 0x01
    MESSAGE = 0x02
    LEAVE = 0x03
    NOISE_HANDSHAKE = 0x10
    NOISE_ENCRYPTED = 0x11
    FRAGMENT = 0x20
    REQUEST_SYNC = 0x21
    FILE_TRANSFER = 0x22


class NoisePayloadType(IntEnum):
    PRIVATE_MESSAGE = 0x01
    READ_RECEIPT = 0x02
    DELIVERED = 0x03
    VERIFY_CHALLENGE = 0x10
    VERIFY_RESPONSE = 0x11


@dataclass
class BitchatPacket:
    """Wire format packet"""
    version: int
    msg_type: MessageType
    ttl: int
    timestamp: int  # UInt64 milliseconds
    sender_id: bytes  # 8 bytes
    payload: bytes
    flags: int = 0
    recipient_id: Optional[bytes] = None
    route: Optional[List[bytes]] = None
    signature: Optional[bytes] = None
    original_size: Optional[int] = None
    
    @property
    def sender_id_str(self) -> str:
        """Return sender_id as hex string"""
        return self.sender_id.hex()
    
    @property
    def recipient_id_str(self) -> Optional[str]:
        """Return recipient_id as hex string"""
        return self.recipient_id.hex() if self.recipient_id else None
        return self.recipient_id.hex() if self.recipient_id else None


class BinaryProtocol:
    """BitChat binary protocol encoder/decoder"""

    @staticmethod
    def encode(packet: BitchatPacket) -> bytes:
        """Encode packet to binary format"""
        data = bytearray()

        # Determine version based on features
        version = PROTOCOL_VERSION
        has_route = packet.route is not None and len(packet.route) > 0

        # Determine header size
        header_size = V2_HEADER_SIZE if version >= 2 else V1_HEADER_SIZE

        # Build flags
        flags = 0
        if packet.recipient_id is not None:
            flags |= FLAG_HAS_RECIPIENT
        if packet.signature is not None:
            flags |= FLAG_HAS_SIGNATURE
        is_compressed = False  # TODO: Implement compression
        if is_compressed:
            flags |= FLAG_IS_COMPRESSED
        if has_route and version >= 2:
            flags |= FLAG_HAS_ROUTE

        # Calculate payload (including optional compression header)
        payload_to_send = packet.payload
        original_size = None

        # Build variable sections to determine final payload length
        variable_data = bytearray()

        # Sender ID (always present)
        variable_data.extend(packet.sender_id if len(packet.sender_id) == 8 else (packet.sender_id + b'\x00' * (8 - len(packet.sender_id)))[:8])

        # Recipient ID (if HASerialVersionUID_RECIPIENT flag)
        if flags & FLAG_HAS_RECIPIENT:
            if packet.recipient_id:
                variable_data.extend(packet.recipient_id if len(packet.recipient_id) == 8 else (packet.recipient_id + b'\x00' * (8 - len(packet.recipient_id)))[:8])
            else:
                variable_data.extend(BROADCAST_RECIPIENT)

        # Route (if HAS_ROUTE flag, v2+ only)
        if (flags & FLAG_HAS_ROUTE) and version >= 2 and packet.route:
            variable_data.append(len(packet.route))  # Hop count
            for hop in packet.route:
                hop_bytes = hop if len(hop) == 8 else (hop + b'\x00' * (8 - len(hop)))[:8]
                variable_data.extend(hop_bytes)

        # Original size (if IS_COMPRESSED flag)
        if flags & FLAG_IS_COMPRESSED:
            original_size = len(packet.payload)
            if version >= 2:
                variable_data.extend(struct.pack('>I', original_size))
            else:
                variable_data.extend(struct.pack('>H', original_size))

        # Payload
        variable_data.extend(payload_to_send)

        # Calculate payload length (all variable data except header)
        payload_length = len(variable_data)

        # Build header
        header = bytearray(header_size)

        # Version
        header[OFFSET_VERSION] = version

        # Type
        header[OFFSET_TYPE] = packet.msg_type.value

        # TTL
        header[OFFSET_TTL] = packet.ttl

        # Timestamp (big-endian 8 bytes)
        timestamp_bytes = struct.pack('>Q', packet.timestamp)
        header[OFFSET_TIMESTAMP:OFFSET_TIMESTAMP+8] = timestamp_bytes

        # Flags
        header[OFFSET_FLAGS] = flags

        # Payload length
        if version >= 2:
            payload_length_bytes = struct.pack('>I', payload_length)
            header[OFFSET_PAYLOAD_LENGTH:OFFSET_PAYLOAD_LENGTH+4] = payload_length_bytes
        else:
            payload_length_bytes = struct.pack('>H', payload_length)
            header[OFFSET_PAYLOAD_LENGTH:OFFSET_PAYLOAD_LENGTH+2] = payload_length_bytes

        # Assemble final packet
        data.extend(header)
        data.extend(variable_data)

        # Signature (if HAS_SIGNATURE flag)
        if flags & FLAG_HAS_SIGNATURE and packet.signature:
            data.extend(packet.signature[:SIGNATURE_SIZE])

        return bytes(data)

    @staticmethod
    def decode(data: bytes) -> Optional[BitchatPacket]:
        """Decode packet from binary format"""
        if len(data) < V1_HEADER_SIZE + SENDER_ID_SIZE:
            return None

        offset = 0

        # Version
        version = data[offset]
        offset += 1

        if version not in [1, 2]:
            return None

        header_size = V2_HEADER_SIZE if version >= 2 else V1_HEADER_SIZE

        if len(data) < header_size + SENDER_ID_SIZE:
            return None

        # Type
        msg_type_val = data[offset]
        offset += 1

        try:
            msg_type = MessageType(msg_type_val)
        except ValueError:
            return None

        # TTL
        ttl = data[offset]
        offset += 1

        # Timestamp (8 bytes, big-endian)
        timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8

        # Flags
        flags = data[offset]
        offset += 1

        # Payload length
        if version >= 2:
            if offset + 4 > len(data):
                return None
            payload_length = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
        else:
            if offset + 2 > len(data):
                return None
            payload_length = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

        # Sender ID (8 bytes)
        if offset + SENDER_ID_SIZE > len(data):
            return None
        sender_id = data[offset:offset+SENDER_ID_SIZE]
        offset += SENDER_ID_SIZE

        # Recipient ID (if HAS_RECIPIENT flag)
        recipient_id = None
        if flags & FLAG_HAS_RECIPIENT:
            if offset + RECIPIENT_ID_SIZE > len(data):
                return None
            recipient_id = data[offset:offset+RECIPIENT_ID_SIZE]
            offset += RECIPIENT_ID_SIZE

        # Route (if HAS_ROUTE flag, v2+ only)
        route = None
        if (flags & FLAG_HAS_ROUTE) and version >= 2:
            if offset + 1 > len(data):
                return None
            hop_count = data[offset]
            offset += 1

            route = []
            for _ in range(hop_count):
                if offset + 8 > len(data):
                    return None
                hop = data[offset:offset+8]
                route.append(hop)
                offset += 8

        # Original size (if IS_COMPRESSED flag)
        original_size = None
        if flags & FLAG_IS_COMPRESSED:
            if version >= 2:
                if offset + 4 > len(data):
                    return None
                original_size = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4
            else:
                if offset + 2 > len(data):
                    return None
                original_size = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2

        # Payload length calculation differs by version:
        # v2 (Python): payload_length includes ALL variable data (sender, recipient, etc.)
        # v1 (Android/iOS): payload_length is the actual payload size only
        if version >= 2:
            header_size = V2_HEADER_SIZE
            bytes_used_for_optional_fields = offset - header_size
            remaining_payload_length = payload_length - bytes_used_for_optional_fields
        else:
            remaining_payload_length = payload_length
        
        if remaining_payload_length < 0:
            return None
        
        payload_end = offset + remaining_payload_length
        if payload_end > len(data):
            return None
        
        payload = data[offset:payload_end]
        offset = payload_end

        # Signature (if HAS_SIGNATURE flag)
        signature = None
        if flags & FLAG_HAS_SIGNATURE:
            if offset + SIGNATURE_SIZE > len(data):
                return None
            signature = data[offset:offset+SIGNATURE_SIZE]
            offset += SIGNATURE_SIZE

        return BitchatPacket(
            version=version,
            msg_type=msg_type,
            ttl=ttl,
            timestamp=timestamp,
            sender_id=sender_id,
            payload=payload,
            flags=flags,
            recipient_id=recipient_id,
            route=route,
            signature=signature,
            original_size=original_size
        )
