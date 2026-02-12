"""Compression utilities - matching Android/iOS raw deflate format.
Android uses java.util.zip.Deflater(true) = raw deflate (no zlib/gzip headers).
"""

import zlib
from typing import Tuple

COMPRESSION_THRESHOLD = 100

def compress_if_beneficial(data: bytes) -> Tuple[bytes, bool]:
    """Compress data using raw deflate if it reduces size (matching Android CompressionUtil)"""
    if len(data) < COMPRESSION_THRESHOLD:
        return (data, False)
    
    try:
        # Raw deflate (no headers) — matches Android Deflater(DEFAULT_COMPRESSION, true)
        compress_obj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        compressed = compress_obj.compress(data) + compress_obj.flush()
        if 0 < len(compressed) < len(data):
            return (compressed, True)
        return (data, False)
    except zlib.error:
        return (data, False)

def decompress(data: bytes, original_size: int = 0) -> bytes:
    """Decompress raw deflate data (matching Android CompressionUtil.decompress)"""
    try:
        # Raw deflate first (Android default: Inflater(true))
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error:
        try:
            # Fallback: zlib headers (Android fallback: Inflater(false))
            return zlib.decompress(data)
        except zlib.error as e:
            raise ValueError(f"Decompression failed: {e}")

# Export functions
__all__ = ['compress_if_beneficial', 'decompress', 'COMPRESSION_THRESHOLD']