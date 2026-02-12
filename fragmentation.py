"""
Fragmentation module for BitChat
Matches Android FragmentPayload format:
  - 8 bytes: Fragment ID (random)
  - 2 bytes: Index (big-endian UInt16)
  - 2 bytes: Total count (big-endian UInt16)
  - 1 byte: Original message type
  - Variable: Fragment data
  Total header size: 13 bytes
"""

import os
import struct
from dataclasses import dataclass
from typing import List, Optional

# Android defaults: MAX_FRAGMENT_SIZE = 469, FRAGMENT_SIZE_THRESHOLD = 512
MAX_FRAGMENT_SIZE = 469
FRAGMENT_SIZE_THRESHOLD = 512
FRAGMENT_HEADER_SIZE = 13
FRAGMENT_TIMEOUT = 30  # seconds


@dataclass
class FragmentPayload:
    """Matches Android FragmentPayload.kt"""
    fragment_id: bytes   # 8 bytes
    index: int           # UInt16
    total: int           # UInt16
    original_type: int   # UInt8
    data: bytes          # variable

    def encode(self) -> bytes:
        """Encode to wire format (matching Android FragmentPayload.encode)"""
        payload = bytearray()
        payload.extend(self.fragment_id[:8])
        payload.extend(struct.pack('>H', self.index))
        payload.extend(struct.pack('>H', self.total))
        payload.append(self.original_type & 0xFF)
        payload.extend(self.data)
        return bytes(payload)

    @staticmethod
    def decode(payload_data: bytes) -> Optional['FragmentPayload']:
        """Decode from wire format (matching Android FragmentPayload.decode)"""
        if len(payload_data) < FRAGMENT_HEADER_SIZE:
            return None
        fragment_id = payload_data[0:8]
        index = struct.unpack('>H', payload_data[8:10])[0]
        total = struct.unpack('>H', payload_data[10:12])[0]
        original_type = payload_data[12]
        data = payload_data[13:]
        if index >= total or total == 0:
            return None
        return FragmentPayload(fragment_id, index, total, original_type, data)

    @staticmethod
    def generate_fragment_id() -> bytes:
        """Generate a random 8-byte fragment ID"""
        return os.urandom(8)


def create_fragments(packet_data: bytes, original_type: int,
                     max_fragment_size: int = MAX_FRAGMENT_SIZE) -> List[FragmentPayload]:
    """Fragment packet data into FragmentPayload list (matching Android FragmentManager.createFragments)"""
    if len(packet_data) <= max_fragment_size:
        return []

    fragment_id = FragmentPayload.generate_fragment_id()
    chunks = [packet_data[i:i+max_fragment_size] for i in range(0, len(packet_data), max_fragment_size)]
    total = len(chunks)

    return [
        FragmentPayload(
            fragment_id=fragment_id,
            index=i,
            total=total,
            original_type=original_type,
            data=chunk
        )
        for i, chunk in enumerate(chunks)
    ]


# Export classes and functions
__all__ = ['FragmentPayload', 'create_fragments', 'MAX_FRAGMENT_SIZE',
           'FRAGMENT_SIZE_THRESHOLD', 'FRAGMENT_HEADER_SIZE', 'FRAGMENT_TIMEOUT']