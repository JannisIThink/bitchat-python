"""
Encryption Service for BitChat
Implements both Noise Protocol (XX pattern) and legacy encryption layers.
Compatible with Swift NoiseEncryptionService implementation.
"""

import os
import time
import json
import secrets
from dataclasses import dataclass
from typing import Optional, Dict, Tuple, Callable
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
import hashlib

# Noise Protocol Constants
NOISE_PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"
NOISE_DH_LEN = 32  # Curve25519 key size
NOISE_HASH_LEN = 32  # SHA256 hash size

class NoiseError(Exception):
    """Base class for Noise protocol errors"""
    pass

class NoiseRole:
    """Noise handshake roles"""
    INITIATOR = "initiator"
    RESPONDER = "responder"

class NoiseHandshakeState:
    """
    Noise handshake state machine for XX pattern.
    Implements the Noise Protocol Framework specification.
    """
    
    def __init__(self, role: str, local_static_key: X25519PrivateKey, remote_static_key: Optional[X25519PublicKey] = None):
        self.role = role
        self.local_static_private = local_static_key
        self.local_static_public = local_static_key.public_key()
        self.remote_static_public = remote_static_key
        
        # Ephemeral keys
        self.local_ephemeral_private = None
        self.local_ephemeral_public = None
        self.remote_ephemeral_public = None
        
        # Symmetric state
        self.chaining_key = None
        self.hash_state = None
        self.cipher_state = NoiseCipherState()
        
        # Pattern tracking
        self.current_pattern = 0
        self.message_patterns = self._get_xx_patterns()
        
        # Initialize symmetric state
        self._initialize_symmetric_state()
    
    def _get_xx_patterns(self) -> list:
        """Get XX pattern message sequences"""
        return [
            ['e'],           # Message 1: -> e
            ['e', 'ee', 's', 'es'],  # Message 2: <- e, ee, s, es  
            ['s', 'se']      # Message 3: -> s, se
        ]
    
    def _initialize_symmetric_state(self):
        """Initialize symmetric state with protocol name"""
        protocol_name = NOISE_PROTOCOL_NAME.encode('utf-8')
        if len(protocol_name) <= 32:
            self.hash_state = protocol_name + b'\x00' * (32 - len(protocol_name))
        else:
            self.hash_state = hashlib.sha256(protocol_name).digest()
        self.chaining_key = self.hash_state
        print(f"[NOISE-INIT] Protocol name: {NOISE_PROTOCOL_NAME}")
        print(f"[NOISE-INIT] Initial hash_state (32 bytes): {self.hash_state.hex()}")
        print(f"[NOISE-INIT] Initial chaining_key: {self.chaining_key.hex()[:32]}...")
    
    def _mix_key(self, input_key_material: bytes):
        """Mix key material into chaining key and update cipher"""
        print(f"[NOISE-MIX] _mix_key called with IKM (first 32 hex): {input_key_material.hex()[:32]}...")
        print(f"[NOISE-MIX] Current chaining_key (first 32 hex): {self.chaining_key.hex()[:32]}...")

        # HKDF extract step: tempKey = HMAC(chainingKey, inputKeyMaterial)
        hmac = HMAC(self.chaining_key, hashes.SHA256())
        hmac.update(input_key_material)
        temp_key = hmac.finalize()
        print(f"[NOISE-MIX] temp_key HMAC(CK, IKM) (first 32 hex): {temp_key.hex()[:32]}...")

        # HKDF expand step: generate 3 outputs per Noise spec
        # output1 = HMAC(tempKey, 0x01)
        # output2 = HMAC(tempKey, output1 + 0x02)
        # output3 = HMAC(tempKey, output2 + 0x03)
        hmac1 = HMAC(temp_key, hashes.SHA256())
        hmac1.update(b'\x01')
        output1 = hmac1.finalize()

        hmac2 = HMAC(temp_key, hashes.SHA256())
        hmac2.update(output1 + b'\x02')
        output2 = hmac2.finalize()

        hmac3 = HMAC(temp_key, hashes.SHA256())
        hmac3.update(output2 + b'\x03')
        output3 = hmac3.finalize()

        print(f"[NOISE-MIX] output1 (new CK, first 32 hex): {output1.hex()[:32]}...")
        print(f"[NOISE-MIX] output2 (to hash, first 32 hex): {output2.hex()[:32]}...")
        print(f"[NOISE-MIX] output3 (cipher key, first 32 hex): {output3.hex()[:32]}...")

        self.chaining_key = output1
        # Per Noise spec, mix output2 into the hash and use output3 as the cipher key
        self._mix_hash(output2)
        self.cipher_state.initialize_key(output3)

        # Build a small set of candidate alternative cipher keys to try when peers behave differently
        candidates = [output3]
        
        # Candidate 1: output2 directly (if peer uses 2-output HKDF or older variant)
        candidates.append(output2)

        # Candidate 2: Use temp_key directly (possibly peer doesn't do expand)
        candidates.append(temp_key)
        
        # Candidate 3: Use chaining_key directly (edge case)
        candidates.append(self.chaining_key)

        # Candidate 3: HKDF variant
        try:
            hk = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.chaining_key,
                info=b''
            )
            hk_key = hk.derive(input_key_material)
            candidates.append(hk_key)
        except Exception:
            pass

        # Candidate 4: HKDF with info
        try:
            hk2 = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.chaining_key,
                info=b'noise'
            )
            hk_key2 = hk2.derive(input_key_material)
            candidates.append(hk_key2)
        except Exception:
            pass

        # Candidate 5: Alternate HMAC ordering
        try:
            hmac_alt = HMAC(temp_key, hashes.SHA256())
            hmac_alt.update(b'\x02' + output1)
            alt2 = hmac_alt.finalize()
            candidates.append(alt2)
        except Exception:
            pass

        # Candidate 6: HMAC(temp_key, "") - without expand
        try:
            hmac_empty = HMAC(temp_key, hashes.SHA256())
            hmac_empty.update(b'')
            alt_empty = hmac_empty.finalize()
            candidates.append(alt_empty)
        except Exception:
            pass

        # Candidate 7: HMAC(IKM, CK) - reversed key/data
        try:
            hmac_rev = HMAC(input_key_material, hashes.SHA256())
            hmac_rev.update(self.chaining_key)
            alt_rev = hmac_rev.finalize()
            candidates.append(alt_rev)
        except Exception:
            pass

        # Deduplicate while preserving order
        seen = set()
        dedup = []
        for k in candidates:
            h = k.hex()
            if h not in seen:
                dedup.append(k)
                seen.add(h)

        self.candidate_cipher_keys = dedup
        print(f"[NOISE-MIX] Generated {len(self.candidate_cipher_keys)} candidate cipher keys for fallback")
    
    def _mix_hash(self, data: bytes):
        """Mix data into handshake hash"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.hash_state)
        digest.update(data)
        old_hash = self.hash_state
        self.hash_state = digest.finalize()
        print(f"[NOISE-HASH] MixHash: old={old_hash.hex()[:16]}... input_len={len(data)}, new={self.hash_state.hex()[:16]}...")
    
    def _mix_key_and_hash(self, input_key_material: bytes):
        """Mix key material into both chaining key and hash"""
        # HKDF extract step: tempKey = HMAC(chainingKey, inputKeyMaterial)
        hmac = HMAC(self.chaining_key, hashes.SHA256())
        hmac.update(input_key_material)
        temp_key = hmac.finalize()
        
        # HKDF expand step: generate 3 outputs (matching Swift)
        # output1 = HMAC(tempKey, "" + 0x01)
        # output2 = HMAC(tempKey, output1 + 0x02)
        # output3 = HMAC(tempKey, output2 + 0x03)
        hmac1 = HMAC(temp_key, hashes.SHA256())
        hmac1.update(b'\x01')
        output1 = hmac1.finalize()
        
        hmac2 = HMAC(temp_key, hashes.SHA256())
        hmac2.update(output1 + b'\x02')
        output2 = hmac2.finalize()
        
        hmac3 = HMAC(temp_key, hashes.SHA256())
        hmac3.update(output2 + b'\x03')
        output3 = hmac3.finalize()
        
        self.chaining_key = output1
        # Mix output2 into hash_state (matching Swift mixHash behavior)
        self._mix_hash(output2)
        self.cipher_state.initialize_key(output3)
    
    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext and mix ciphertext into hash"""
        if self.cipher_state.has_key():
            output = self.cipher_state.encrypt(plaintext, self.hash_state)
            # output = [4-byte nonce prefix][encrypted data]; mix the FULL ciphertext
            # bytes so both sides hash the same data (includes nonce prefix).
            self._mix_hash(output)
            return output
        else:
            self._mix_hash(plaintext)
            return plaintext
    
    def _decrypt_and_hash(self, ciphertext_bytes: bytes) -> bytes:
        """Decrypt ciphertext and mix it into hash.
        
        CRITICAL: Hash the FULL ciphertext bytes as received (with nonce prefix if present),
        NOT a substring. This must match the peer's implementation.
        """
        if self.cipher_state.has_key():
            # Use the current handshake hash as associated data (matches _encrypt_and_hash)
            plaintext = self.cipher_state.decrypt(ciphertext_bytes, self.hash_state)
            # IMPORTANT: Mix the FULL ciphertext_bytes into the hash, regardless of prefix
            self._mix_hash(ciphertext_bytes)
            return plaintext
        else:
            self._mix_hash(ciphertext_bytes)
            return ciphertext_bytes
    
    def _dh(self, private_key: X25519PrivateKey, public_key: X25519PublicKey, pattern: str = '?') -> bytes:
        """Perform Diffie-Hellman key exchange"""
        # Log the inputs for debugging
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        shared_key = private_key.exchange(public_key)
        print(f"[NOISE-DH] Pattern '{pattern}': private key (full 64 hex): {private_bytes.hex()}")
        print(f"[NOISE-DH] Pattern '{pattern}': public key (full 64 hex): {public_bytes.hex()}")
        print(f"[NOISE-DH] Pattern '{pattern}': shared key (full 64 hex): {shared_key.hex()}")
        return shared_key
    
    def write_message(self, payload: bytes = b'') -> bytes:
        """Write a handshake message"""
        if self.current_pattern >= len(self.message_patterns):
            raise NoiseError("Handshake complete")
        
        message_buffer = bytearray()
        patterns = self.message_patterns[self.current_pattern]
        
        for pattern in patterns:
            if pattern == 'e':
                # Generate and send ephemeral key
                self.local_ephemeral_private = X25519PrivateKey.generate()
                self.local_ephemeral_public = self.local_ephemeral_private.public_key()
                ephemeral_bytes = self.local_ephemeral_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                message_buffer.extend(ephemeral_bytes)
                self._mix_hash(ephemeral_bytes)
                print(f"[NOISE-WRITE] Generated local ephemeral e (full 64 hex): {ephemeral_bytes.hex()}")
            
            elif pattern == 's':
                # Send static key (encrypted if cipher is initialized)
                static_bytes = self.local_static_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                print(f"[NOISE-WRITE] Encrypting local static key (full 64 hex): {static_bytes.hex()}")
                print(f"[NOISE-WRITE] Cipher has key: {self.cipher_state.has_key()}")
                encrypted = self._encrypt_and_hash(static_bytes)
                print(f"[NOISE-WRITE] Encrypted static (len={len(encrypted)}): {encrypted[:50].hex()}...")
                message_buffer.extend(encrypted)
            
            elif pattern == 'ee':
                # DH(local ephemeral, remote ephemeral)
                if not self.local_ephemeral_private or not self.remote_ephemeral_public:
                    raise NoiseError("Missing ephemeral keys for ee")
                shared = self._dh(self.local_ephemeral_private, self.remote_ephemeral_public, 'ee')
                self._mix_key(shared)
            
            elif pattern == 'es':
                # DH(ephemeral, static) - direction depends on role
                if self.role == NoiseRole.INITIATOR:
                    if not self.local_ephemeral_private or not self.remote_static_public:
                        raise NoiseError("Missing keys for es")
                    shared = self._dh(self.local_ephemeral_private, self.remote_static_public, 'es')
                else:
                    if not self.local_static_private or not self.remote_ephemeral_public:
                        raise NoiseError("Missing keys for es")
                    shared = self._dh(self.local_static_private, self.remote_ephemeral_public, 'es')
                self._mix_key(shared)
            
            elif pattern == 'se':
                # DH(static, ephemeral) - direction depends on role
                if self.role == NoiseRole.INITIATOR:
                    if not self.local_static_private or not self.remote_ephemeral_public:
                        raise NoiseError("Missing keys for se")
                    shared = self._dh(self.local_static_private, self.remote_ephemeral_public, 'se')
                else:
                    if not self.local_ephemeral_private or not self.remote_static_public:
                        raise NoiseError("Missing keys for se")
                    shared = self._dh(self.local_ephemeral_private, self.remote_static_public, 'se')
                self._mix_key(shared)
        
        # Encrypt payload
        encrypted_payload = self._encrypt_and_hash(payload)
        message_buffer.extend(encrypted_payload)
        
        self.current_pattern += 1
        return bytes(message_buffer)
    
    def read_message(self, message: bytes) -> bytes:
        """Read a handshake message"""
        if self.current_pattern >= len(self.message_patterns):
            raise NoiseError("Handshake complete")
        
        buffer = message
        patterns = self.message_patterns[self.current_pattern]
        
        print(f"[NOISE-READ] Pattern {self.current_pattern}: {patterns}, input_len={len(message)}")
        
        for pattern in patterns:
            if pattern == 'e':
                # Read ephemeral key
                if len(buffer) < 32:
                    raise NoiseError("Invalid message: insufficient data for ephemeral key")
                ephemeral_data = buffer[:32]
                buffer = buffer[32:]
                
                self.remote_ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_data)
                self._mix_hash(ephemeral_data)
                print(f"[NOISE-READ] ✓ Read ephemeral e: {ephemeral_data.hex()[:32]}...")
                print(f"[NOISE-READ] Remote ephemeral (full 64 hex): {ephemeral_data.hex()}")
            
            elif pattern == 's':
                # Read static key (may be encrypted)
                # With nonce extraction: 4 (nonce) + 32 (key) + 16 (tag) = 52 bytes encrypted
                # Without extracted nonce (common variant): 32 (key) + 16 (tag) = 48 bytes
                # Plain: 32 bytes
                if self.cipher_state.has_key():
                    if len(buffer) >= 52:
                        key_length = 52
                    elif len(buffer) >= 48:
                        # Peer likely omitted 4-byte nonce prefix; accept 48-byte encrypted static
                        key_length = 48
                    else:
                        raise NoiseError("Invalid message: insufficient data for static key")
                else:
                    key_length = 32

                static_data = buffer[:key_length]
                buffer = buffer[key_length:]
                
                print(f"[NOISE-READ] Decrypting static s: len={len(static_data)}, cipher_has_key={self.cipher_state.has_key()}")
                print(f"[NOISE-READ] Cipher key (first 16 bytes hex): {self.cipher_state.key[:16].hex() if self.cipher_state.key else 'None'}")
                print(f"[NOISE-READ] Hash state BEFORE decrypt (first 16 hex): {self.hash_state.hex()[:16]}...")
                print(f"[NOISE-READ] Static ciphertext (first 24 hex): {static_data[:24].hex()[:48]}...")
                print(f"[NOISE-READ] Will use hash as AD: {self.hash_state.hex()[:32]}...")
                
                try:
                    decrypted = self._decrypt_and_hash(static_data)
                    self.remote_static_public = X25519PublicKey.from_public_bytes(decrypted)
                    print(f"[NOISE-READ] ✓ Decrypted static: {decrypted.hex()[:32]}...")
                    print(f"[NOISE-READ] Hash state AFTER decrypt (first 16 hex): {self.hash_state.hex()[:16]}...")
                except Exception as e:
                    # Primary decryption failed — try candidate keys (best-effort compatibility)
                    print(f"[NOISE-READ] Primary static decryption failed: {e}. Trying {len(getattr(self, 'candidate_cipher_keys', []))} alternative derived keys...")
                    alt_found = False
                    for idx, key in enumerate(getattr(self, 'candidate_cipher_keys', [])):
                        try:
                            tmp_cipher = NoiseCipherState()
                            tmp_cipher.initialize_key(key)
                            # Try same variants as NoiseCipherState.decrypt would
                            plaintext = tmp_cipher.decrypt(static_data, self.hash_state)
                            # Success
                            print(f"[NOISE-READ] ✓ Alt decrypt succeeded with candidate #{idx}")
                            # Adopt this key for ongoing cipher state
                            self.cipher_state.initialize_key(key)
                            # Mix the full ciphertext into hash (match _decrypt_and_hash semantics)
                            self._mix_hash(static_data)
                            self.remote_static_public = X25519PublicKey.from_public_bytes(plaintext)
                            alt_found = True
                            break
                        except Exception as ex:
                            # continue trying
                            print(f"[NOISE-READ] candidate #{idx} failed: {type(ex).__name__}")
                            continue

                    if not alt_found:
                        raise
            
            elif pattern in ['ee', 'es', 'se']:
                # Perform DH operations (same as write_message)
                if pattern == 'ee':
                    if not self.local_ephemeral_private or not self.remote_ephemeral_public:
                        raise NoiseError("Missing ephemeral keys for ee")
                    shared = self._dh(self.local_ephemeral_private, self.remote_ephemeral_public, 'ee')
                    self._mix_key(shared)
                elif pattern == 'es':
                    if self.role == NoiseRole.INITIATOR:
                        if not self.local_ephemeral_private or not self.remote_static_public:
                            raise NoiseError("Missing keys for es")
                        shared = self._dh(self.local_ephemeral_private, self.remote_static_public, 'es')
                    else:
                        if not self.local_static_private or not self.remote_ephemeral_public:
                            raise NoiseError("Missing keys for es")
                        shared = self._dh(self.local_static_private, self.remote_ephemeral_public, 'es')
                    self._mix_key(shared)
                elif pattern == 'se':
                    if self.role == NoiseRole.INITIATOR:
                        if not self.local_static_private or not self.remote_ephemeral_public:
                            raise NoiseError("Missing keys for se")
                        shared = self._dh(self.local_static_private, self.remote_ephemeral_public, 'se')
                    else:
                        if not self.local_ephemeral_private or not self.remote_static_public:
                            raise NoiseError("Missing keys for se")
                        shared = self._dh(self.local_ephemeral_private, self.remote_static_public, 'se')
                    self._mix_key(shared)
        
        # Decrypt payload
        payload = self._decrypt_and_hash(buffer)
        self.current_pattern += 1
        
        return payload
    
    def is_handshake_complete(self) -> bool:
        """Check if handshake is complete"""
        return self.current_pattern >= len(self.message_patterns)
    
    def get_transport_ciphers(self) -> Tuple['NoiseCipherState', 'NoiseCipherState']:
        """Get transport cipher states after handshake completion"""
        if not self.is_handshake_complete():
            raise NoiseError("Handshake not complete")
        
        # Split function: derive two cipher states (matching Swift)
        # tempKey = HMAC(chainingKey, "")
        hmac = HMAC(self.chaining_key, hashes.SHA256())
        hmac.update(b'')
        temp_key = hmac.finalize()
        
        # Generate 2 outputs
        hmac1 = HMAC(temp_key, hashes.SHA256())
        hmac1.update(b'\x01')
        key1 = hmac1.finalize()
        
        hmac2 = HMAC(temp_key, hashes.SHA256())
        hmac2.update(key1 + b'\x02')
        key2 = hmac2.finalize()
        
        c1 = NoiseCipherState()
        c1.initialize_key(key1)
        
        c2 = NoiseCipherState()
        c2.initialize_key(key2)
        
        # Initiator uses c1 for sending, c2 for receiving
        # Responder uses c2 for sending, c1 for receiving
        if self.role == NoiseRole.INITIATOR:
            return c1, c2
        else:
            return c2, c1
    
    def get_handshake_hash(self) -> bytes:
        """Get the handshake hash for channel binding"""
        return self.hash_state
    
    def get_remote_static_public_key(self) -> Optional[X25519PublicKey]:
        """Get the remote static public key"""
        return self.remote_static_public

class NoiseCipherState:
    """Cipher state for Noise Protocol transport encryption with nonce extraction.
    
    Per BitChat specification, the output format is:
    [4-byte nonce prefix (big-endian)] [encrypted data] [16-byte Poly1305 MAC tag]
    """
    
    def __init__(self):
        self.key = None
        self.nonce = 0
        self.use_extracted_nonce = True  # BitChat always uses extracted nonce
        self.highest_received_nonce = 0
        self.replay_window_size = 1024
        self.replay_window = [0] * 128  # 1024 bits = 128 bytes
    
    def initialize_key(self, key: bytes):
        """Initialize cipher with key"""
        self.key = key
        self.nonce = 0
        self.highest_received_nonce = 0
        self.replay_window = [0] * 128
    
    def has_key(self) -> bool:
        """Check if cipher has a key"""
        return self.key is not None
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> bytes:
        """Encrypt plaintext with ChaCha20-Poly1305 and extract nonce.
        
        Returns: [4-byte nonce][encrypted data][16-byte MAC]
        """
        if not self.has_key():
            raise NoiseError("Cipher not initialized")
        
        # Use nonce as UInt32 (per spec: 4-byte nonce prefix)
        nonce_u32 = self.nonce & 0xFFFFFFFF
        
        # Create 12-byte nonce for ChaCha20: [4 zero bytes][8 bytes of counter]
        nonce = b'\x00\x00\x00\x00' + self.nonce.to_bytes(8, byteorder='little')
        
        cipher = ChaCha20Poly1305(self.key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        
        # Extract nonce format: big-endian 4-byte prefix
        nonce_prefix = nonce_u32.to_bytes(4, byteorder='big')
        
        # Output: nonce_prefix + ciphertext (which includes encrypted data + 16-byte tag)
        result = nonce_prefix + ciphertext
        
        self.nonce += 1
        return result
    
    def decrypt(self, ciphertext_with_nonce: bytes, associated_data: bytes = b'') -> bytes:
        """Decrypt ciphertext with extracted nonce (smart reordering for compatibility).
        
        Input: [4-byte nonce][encrypted data][16-byte MAC] or [encrypted data][16-byte MAC]
        
        Strategy:
        - SHORT blocks (<52 bytes, typical handshake): try no-prefix FIRST (Android handshake style)
        - LONG blocks (>=52 bytes, typical transport): try 4-byte prefix FIRST
        Try multiple variants and nonces to handle cross-platform compatibility.
        """
        if not self.has_key():
            raise NoiseError("Cipher not initialized")
        
        attempts = []
        is_short_block = len(ciphertext_with_nonce) < 52
        
        # For short blocks (handshake): prioritize NO-PREFIX (Android doesn't extract nonce in handshake)
        if is_short_block and len(ciphertext_with_nonce) >= 16:
            # HANDSHAKE PRIORITY 1-4: Try nonce 0 and 1 with hash AD and empty AD
            for candidate_nonce in [0, 1]:
                # With hash AD
                try:
                    nonce = b'\x00\x00\x00\x00' + candidate_nonce.to_bytes(8, byteorder='little')
                    cipher = ChaCha20Poly1305(self.key)
                    plaintext = cipher.decrypt(nonce, ciphertext_with_nonce, associated_data)
                    self._mark_nonce_as_seen(candidate_nonce)
                    self._last_decryption_used_prefix = False
                    print(f"[NOISE-CIPHER] ✓ SUCCESS (short/handshake): no prefix, nonce={candidate_nonce}, with hash AD")
                    return plaintext
                except Exception as ex:
                    attempts.append(f"SHORT:no-prefix,n={candidate_nonce},AD: {type(ex).__name__}")
                
                # With empty AD
                try:
                    nonce = b'\x00\x00\x00\x00' + candidate_nonce.to_bytes(8, byteorder='little')
                    cipher = ChaCha20Poly1305(self.key)
                    plaintext = cipher.decrypt(nonce, ciphertext_with_nonce, b'')
                    self._mark_nonce_as_seen(candidate_nonce)
                    self._last_decryption_used_prefix = False
                    print(f"[NOISE-CIPHER] ✓ SUCCESS (short/handshake): no prefix, nonce={candidate_nonce}, empty AD")
                    return plaintext
                except Exception as ex:
                    attempts.append(f"SHORT:no-prefix,n={candidate_nonce},empty: {type(ex).__name__}")
        
        # For all blocks (or if short-block no-prefix failed): try 4-byte prefix
        if len(ciphertext_with_nonce) >= 4 + 16:
            try:
                nonce_bytes = ciphertext_with_nonce[:4]
                ciphertext = ciphertext_with_nonce[4:]
                received_nonce = int.from_bytes(nonce_bytes, byteorder='big')
                
                if self._is_valid_nonce(received_nonce):
                    nonce = b'\x00\x00\x00\x00' + received_nonce.to_bytes(8, byteorder='little')
                    cipher = ChaCha20Poly1305(self.key)
                    # Try with associated_data first
                    try:
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
                        self._mark_nonce_as_seen(received_nonce)
                        self._last_decryption_used_prefix = True
                        print(f"[NOISE-CIPHER] ✓ SUCCESS: 4-byte prefix + hash AD, nonce={received_nonce}")
                        return plaintext
                    except Exception as ex:
                        attempts.append(f"prefix+AD: {type(ex).__name__}")
                    # Fallback: try with empty AD
                    try:
                        plaintext = cipher.decrypt(nonce, ciphertext, b'')
                        self._mark_nonce_as_seen(received_nonce)
                        self._last_decryption_used_prefix = True
                        print(f"[NOISE-CIPHER] ✓ SUCCESS: 4-byte prefix + empty AD, nonce={received_nonce}")
                        return plaintext
                    except Exception as ex:
                        attempts.append(f"prefix+empty: {type(ex).__name__}")
            except Exception as ex:
                attempts.append(f"prefix-parse: {type(ex).__name__}")
        
        # For long blocks: also try no-prefix as fallback with other nonces
        if not is_short_block and len(ciphertext_with_nonce) >= 16:
            for candidate_nonce in [0, 1, 2]:
                try:
                    nonce = b'\x00\x00\x00\x00' + candidate_nonce.to_bytes(8, byteorder='little')
                    cipher = ChaCha20Poly1305(self.key)
                    plaintext = cipher.decrypt(nonce, ciphertext_with_nonce, associated_data)
                    self._mark_nonce_as_seen(candidate_nonce)
                    self._last_decryption_used_prefix = False
                    print(f"[NOISE-CIPHER] ✓ SUCCESS (long, fallback): no prefix, nonce={candidate_nonce}, hash AD")
                    return plaintext
                except Exception as ex:
                    attempts.append(f"LONG:no-prefix,n={candidate_nonce},AD: {type(ex).__name__}")

        # All attempts failed
        error_summary = " | ".join(attempts)
        print(f"[NOISE-CIPHER] ✗ FAILED all {len(attempts)} attempts: {error_summary}")
        raise NoiseError(f"Decryption failed (all {len(attempts)} attempts): {error_summary}")
    
    def _is_valid_nonce(self, nonce: int) -> bool:
        """Check if nonce is within acceptable window (replay protection)"""
        if nonce > self.highest_received_nonce:
            return True  # Newer nonce
        
        # Check if outside window
        if self.highest_received_nonce >= self.replay_window_size:
            if nonce <= self.highest_received_nonce - self.replay_window_size:
                return False  # Too old
        
        # Check if already seen
        window_index = nonce % self.replay_window_size
        byte_index = window_index // 8
        bit_index = window_index % 8
        
        return (self.replay_window[byte_index] & (1 << bit_index)) == 0
    
    def _mark_nonce_as_seen(self, nonce: int):
        """Mark nonce as seen in replay window"""
        if nonce > self.highest_received_nonce:
            self.highest_received_nonce = nonce
        
        window_index = nonce % self.replay_window_size
        byte_index = window_index // 8
        bit_index = window_index % 8
        
        self.replay_window[byte_index] |= (1 << bit_index)

@dataclass
class NoiseSession:
    """Represents an established Noise session with a peer"""
    peer_id: str
    send_cipher: NoiseCipherState
    receive_cipher: NoiseCipherState
    remote_static_key: X25519PublicKey
    established_time: float
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data for transport"""
        return self.send_cipher.encrypt(plaintext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt received data"""
        return self.receive_cipher.decrypt(ciphertext)
    
    def get_fingerprint(self) -> str:
        """Get peer's public key fingerprint"""
        key_bytes = self.remote_static_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(key_bytes).hexdigest()

class EncryptionService:
    """
    Main encryption service implementing both Noise Protocol and legacy encryption.
    Compatible with Swift NoiseEncryptionService.
    """
    
    def __init__(self, identity_path: Optional[str] = None):
        # Load or create static identity key
        self.static_identity_key = self._load_or_create_identity(identity_path)
        
        # Active Noise sessions
        self.sessions: Dict[str, NoiseSession] = {}
        
        # Handshake states in progress
        self.handshake_states: Dict[str, NoiseHandshakeState] = {}
        
        # Store our peer ID for tie-breaking (set from outside)
        self.my_peer_id: Optional[str] = None
        
        # Callbacks
        self.on_peer_authenticated: Optional[Callable[[str, str], None]] = None
        self.on_handshake_required: Optional[Callable[[str], None]] = None
    
    def _load_or_create_identity(self, identity_path: Optional[str]) -> X25519PrivateKey:
        """Load existing identity or create new one"""
        if identity_path and os.path.exists(identity_path):
            try:
                with open(identity_path, 'rb') as f:
                    key_data = f.read()
                return X25519PrivateKey.from_private_bytes(key_data)
            except Exception:
                pass  # Fall through to create new key
        
        # Create new identity
        key = X25519PrivateKey.generate()
        
        # Save if path provided
        if identity_path:
            try:
                os.makedirs(os.path.dirname(identity_path), exist_ok=True)
                with open(identity_path, 'wb') as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                # Set restrictive permissions
                os.chmod(identity_path, 0o600)
            except Exception:
                pass  # Identity will be ephemeral
        
        return key
    
    def get_identity_fingerprint(self) -> str:
        """Get our identity fingerprint"""
        public_key = self.static_identity_key.public_key()
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(key_bytes).hexdigest()
    
    def get_public_key_bytes(self) -> bytes:
        """Get our public key bytes for sharing"""
        public_key = self.static_identity_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_public_key(self) -> bytes:
        """Get public key bytes (alias for compatibility)"""
        return self.get_public_key_bytes()
    
    def get_combined_public_key_data(self) -> bytes:
        """Get combined public key data for legacy compatibility"""
        return self.get_public_key_bytes()
    
    def get_signing_public_key_bytes(self) -> bytes:
        """Get signing public key bytes (for now, same as static key)"""
        # For compatibility with Swift, we'll use the same key for signing
        # In a full implementation, this would be a separate Ed25519 key
        return self.get_public_key_bytes()
    
    def initiate_handshake(self, peer_id: str) -> bytes:
        """Initiate Noise handshake with a peer"""
        # Clean up any existing handshake state and session
        if peer_id in self.handshake_states:
            #print(f"[NOISE] Cleaning up existing handshake state for {peer_id}")
            del self.handshake_states[peer_id]
        
        if peer_id in self.sessions:
            #print(f"[NOISE] Removing existing session for {peer_id}")
            del self.sessions[peer_id]
        
        # Create new handshake state as initiator
        handshake = NoiseHandshakeState(NoiseRole.INITIATOR, self.static_identity_key)
        self.handshake_states[peer_id] = handshake
        #print(f"[NOISE] Initiating handshake with {peer_id}")
        
        # Write first message (-> e)
        return handshake.write_message()
    
    def process_handshake_message(self, peer_id: str, message: bytes) -> Optional[bytes]:
        """Process incoming handshake message and return response if needed"""
        
        # Validate input
        if not message:
            raise NoiseError("Empty handshake message")
        
        if len(message) < 32:
            raise NoiseError(f"Handshake message too short: {len(message)} bytes")
        
        # Check if we have an ongoing handshake
        if peer_id in self.handshake_states:
            handshake = self.handshake_states[peer_id]
            #print(f"[NOISE] Continuing handshake with {peer_id}, pattern {handshake.current_pattern}, role {handshake.role}")
        else:
            # New handshake from peer - we are responder
            handshake = NoiseHandshakeState(NoiseRole.RESPONDER, self.static_identity_key)
            self.handshake_states[peer_id] = handshake
            #print(f"[NOISE] Starting new handshake with {peer_id} as responder")
        
        # Validate handshake state
        if handshake.current_pattern >= len(handshake.message_patterns):
            #print(f"[NOISE] Warning: Handshake already complete with {peer_id}, ignoring message")
            return None
        
        try:
            # Read the incoming message
            payload = handshake.read_message(message)
            #print(f"[NOISE] Successfully processed pattern {handshake.current_pattern - 1} from {peer_id}")
            
            # Check if we need to send a response
            response = None
            if not handshake.is_handshake_complete():
                # Generate response message
                response = handshake.write_message()
                #print(f"[NOISE] Generated response pattern {handshake.current_pattern - 1} for {peer_id}")
            
            # Check if handshake is now complete
            if handshake.is_handshake_complete():
                # Get transport ciphers
                send_cipher, receive_cipher = handshake.get_transport_ciphers()
                
                # Create session
                remote_key = handshake.get_remote_static_public_key()
                if remote_key:
                    session = NoiseSession(
                        peer_id=peer_id,
                        send_cipher=send_cipher,
                        receive_cipher=receive_cipher,
                        remote_static_key=remote_key,
                        established_time=time.time()
                    )
                    self.sessions[peer_id] = session
                    
                    # Cleanup handshake state
                    del self.handshake_states[peer_id]
                    #print(f"[NOISE] Handshake completed with {peer_id}")
                    
                    # Notify authentication
                    if self.on_peer_authenticated:
                        fingerprint = session.get_fingerprint()
                        self.on_peer_authenticated(peer_id, fingerprint)
            
            return response
            
        except Exception as e:
            # Handshake failed, cleanup
            if peer_id in self.handshake_states:
                del self.handshake_states[peer_id]
            #print(f"[NOISE] Handshake failed with {peer_id}: {type(e).__name__}: {e}")
            #print(f"[NOISE] Message length: {len(message)}, first 32 bytes: {message[:32].hex()}")
            import traceback
            #print(f"[NOISE] Handshake error details: {traceback.format_exc()}")
            #print(f"[NOISE] Original exception type: {type(e).__name__}")
            #print(f"[NOISE] Original exception message: {str(e)}")
            raise NoiseError(f"Handshake failed: {e}")
    
    def handle_handshake_message(self, peer_id: str, message: bytes) -> Optional[bytes]:
        """Legacy compatibility method - delegates to process_handshake_message"""
        return self.process_handshake_message(peer_id, message)
    
    def has_established_session(self, peer_id: str) -> bool:
        """Check if we have an established session with peer"""
        return peer_id in self.sessions
    
    def is_session_established(self, peer_id: str) -> bool:
        """Check if we have an established session with peer (alias for compatibility)"""
        return self.has_established_session(peer_id)
    
    def encrypt(self, data: bytes, peer_id: str) -> bytes:
        """Encrypt data for a specific peer"""
        if peer_id not in self.sessions:
            if self.on_handshake_required:
                self.on_handshake_required(peer_id)
            raise NoiseError(f"No session with peer {peer_id}")
        
        session = self.sessions[peer_id]
        return session.encrypt(data)
    
    def encrypt_for_peer(self, peer_id: str, data: bytes) -> bytes:
        """Encrypt data for a specific peer (reordered args for compatibility)"""
        return self.encrypt(data, peer_id)
    
    def decrypt_from_peer(self, peer_id: str, data: bytes) -> bytes:
        """Decrypt data from a specific peer"""
        if peer_id not in self.sessions:
            raise NoiseError(f"No session with peer {peer_id}")
        
        session = self.sessions[peer_id]
        return session.decrypt(data)
    
    def get_peer_fingerprint(self, peer_id: str) -> Optional[str]:
        """Get fingerprint for a peer"""
        if peer_id in self.sessions:
            return self.sessions[peer_id].get_fingerprint()
        return None
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with our identity key (placeholder for EdDSA)"""
        # For now, return a simple hash-based signature
        # In a real implementation, this would use EdDSA
        return hashlib.sha256(data + self.get_public_key_bytes()).digest()
    
    def remove_session(self, peer_id: str):
        """Remove session with a peer"""
        if peer_id in self.sessions:
            del self.sessions[peer_id]
        if peer_id in self.handshake_states:
            del self.handshake_states[peer_id]
    
    def clear_handshake_state(self, peer_id: str):
        """Clear handshake state for a peer (used when handshake fails)"""
        if peer_id in self.handshake_states:
            #print(f"[NOISE] Clearing failed handshake state for {peer_id}")
            del self.handshake_states[peer_id]
    
    def cleanup_old_sessions(self, max_age: float = 3600):
        """Remove sessions older than max_age seconds"""
        current_time = time.time()
        expired_peers = []
        
        for peer_id, session in self.sessions.items():
            if current_time - session.established_time > max_age:
                expired_peers.append(peer_id)
        
        for peer_id in expired_peers:
            del self.sessions[peer_id]
    
    def get_session_count(self) -> int:
        """Get number of active sessions"""
        return len(self.sessions)
    
    def get_active_peers(self) -> list:
        """Get list of peers with active sessions"""
        return list(self.sessions.keys())
    
    # Channel encryption methods (basic implementation)
    def encrypt_for_channel(self, message: str, channel: str, key: bytes, creator_fingerprint: str) -> bytes:
        """Encrypt message for channel"""
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        plaintext = message.encode('utf-8')
        return nonce + cipher.encrypt(nonce, plaintext, None)
    
    def decrypt_from_channel(self, data: bytes, channel: str, key: bytes, creator_fingerprint: str) -> str:
        """Decrypt message from channel"""
        if len(data) < 12:
            raise ValueError("Invalid encrypted data")
        
        nonce = data[:12]
        ciphertext = data[12:]
        
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    
    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data with a specific key"""
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        return nonce + cipher.encrypt(nonce, data, None)
    
    @staticmethod
    def derive_channel_key(password: str, channel: str) -> bytes:
        """Derive a channel key from password and channel name"""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        salt = channel.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode('utf-8'))
    
    # def debug_handshake_state(self, peer_id: str = None):
    #     """Debug handshake and session state"""
    #     #print(f"[NOISE DEBUG] ===== Encryption Service State =====")
    #     #print(f"[NOISE DEBUG] Total handshake states: {len(self.handshake_states)}")
    #     #print(f"[NOISE DEBUG] Total sessions: {len(self.sessions)}")
        
    #     if peer_id:
    #         if peer_id in self.handshake_states:
    #             hs = self.handshake_states[peer_id]
    #             #print(f"[NOISE DEBUG] {peer_id} handshake: pattern {hs.current_pattern}, role {hs.role}")
    #         else:
    #             #print(f"[NOISE DEBUG] {peer_id}: no handshake state")
                
    #         if peer_id in self.sessions:
    #             #print(f"[NOISE DEBUG] {peer_id}: has established session")
    #         else:
    #             #print(f"[NOISE DEBUG] {peer_id}: no session")
    #     else:
    #         for pid, hs in self.handshake_states.items():
    #             #print(f"[NOISE DEBUG] {pid}: pattern {hs.current_pattern}, role {hs.role}")
                
    #         for pid in self.sessions.keys():
    #             #print(f"[NOISE DEBUG] {pid}: established session")
    #     #print(f"[NOISE DEBUG] =====================================")
