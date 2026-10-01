"""Deepened post-quantum cryptography: hybrid KEM, HKDF, secure messaging, certificates.

Provides quantum-resistant key exchange (Kyber + X25519 hybrid), HKDF key derivation,
secure message protocol with replay protection, and certificate-based authentication.
"""
import os
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple, Set

from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ── Exceptions ─────────────────────────────────────────────────────────

class QuantumSafeError(Exception):
    """Raised when a security-critical operation fails."""


class QuantumSafeValidationError(Exception):
    """Raised when validation fails (wrong key, bad signature, etc.)."""


# ── Hybrid Key Exchange (Kyber + X25519) ──────────────────────────────

@dataclass
class HybridKeyPair:
    """Hybrid keypair combining Kyber-512 and X25519."""
    kyber_public_key: bytes
    kyber_secret_key: bytes
    x25519_public_key: bytes
    x25519_secret_key: bytes


class HybridKeyExchange:
    """Hybrid post-quantum key exchange: ML-KEM-512 + X25519.

    Combines lattice-based Kyber with elliptic-curve X25519 for defense-in-depth.
    The shared secret is derived from both mechanisms.
    """

    @staticmethod
    def generate_keypair() -> HybridKeyPair:
        """Generate a new hybrid keypair."""
        kyber_pk, kyber_sk = ml_kem_512.keygen()
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        x25519_pk = x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x25519_sk = x25519_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return HybridKeyPair(
            kyber_public_key=kyber_pk,
            kyber_secret_key=kyber_sk,
            x25519_public_key=x25519_pk,
            x25519_secret_key=x25519_sk,
        )

    @staticmethod
    def encapsulate(kyber_public_key: bytes, x25519_public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate: produce (combined_ciphertext, shared_secret).

        Combines Kyber encapsulation with X25519 ephemeral key exchange.
        """
        if len(kyber_public_key) != ml_kem_512.PUBLIC_KEY_SIZE:
            raise QuantumSafeValidationError("Invalid Kyber public key size")
        if len(x25519_public_key) != 32:
            raise QuantumSafeValidationError("Invalid X25519 public key size")

        # Kyber encapsulation
        kyber_ct, kyber_ss = ml_kem_512.encaps(kyber_public_key)

        # X25519 ephemeral key exchange
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_pk_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x25519_peer = X25519PublicKey.from_public_bytes(x25519_public_key)
        x25519_ss = ephemeral_private.exchange(x25519_peer)

        # Combine ciphertexts: kyber_ct (768) + x25519_ephemeral_pk (32) = 800
        combined_ct = kyber_ct + ephemeral_pk_bytes

        # Derive shared secret from both
        shared_secret = hashlib.sha256(kyber_ss + x25519_ss).digest()
        return combined_ct, shared_secret

    @staticmethod
    def decapsulate(combined_ct: bytes, kyber_secret_key: bytes, x25519_secret_key: bytes) -> bytes:
        """Decapsulate: recover shared secret using secret keys."""
        if len(combined_ct) != 800:
            raise QuantumSafeValidationError("Invalid combined ciphertext size")
        if len(kyber_secret_key) != ml_kem_512.SECRET_KEY_SIZE:
            raise QuantumSafeValidationError("Invalid Kyber secret key size")
        if len(x25519_secret_key) != 32:
            raise QuantumSafeValidationError("Invalid X25519 secret key size")

        # Split combined ciphertext
        kyber_ct = combined_ct[:768]
        x25519_ephemeral_pk = combined_ct[768:]

        # Kyber decapsulation
        try:
            kyber_ss = ml_kem_512.decaps(kyber_secret_key, kyber_ct)
        except Exception as e:
            raise QuantumSafeValidationError(f"Kyber decapsulation failed: {e}") from e

        # X25519 shared secret derivation
        x25519_private = X25519PrivateKey.from_private_bytes(x25519_secret_key)
        x25519_peer = X25519PublicKey.from_public_bytes(x25519_ephemeral_pk)
        x25519_ss = x25519_private.exchange(x25519_peer)

        # Derive shared secret (same as encapsulate)
        shared_secret = hashlib.sha256(kyber_ss + x25519_ss).digest()
        return shared_secret


# ── HKDF Key Derivation ───────────────────────────────────────────────

class HKDFDerivation:
    """HKDF-SHA256 key derivation for deriving session keys."""

    @staticmethod
    def derive(
        ikm: bytes,
        salt: Optional[bytes] = None,
        info: bytes = b"",
        length: int = 32,
    ) -> bytes:
        """Derive a key using HKDF-SHA256."""
        if salt is None:
            salt = b"\x00" * 32
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)


# ── Secure Message Protocol ───────────────────────────────────────────

class SecureMessageProtocol:
    """Secure message protocol with AES-256-GCM, sequence numbers, and replay protection.

    Message format:
    [sequence_number (8 bytes)] [timestamp (8 bytes)] [nonce (12 bytes)] [ciphertext]
    """

    def __init__(self, shared_secret: bytes):
        self._session_key = HKDFDerivation.derive(
            shared_secret, salt=b"secure-message", info=b"session-key"
        )
        self._sequence_number: int = 0
        self._used_sequence_numbers: Set[int] = set()
        self._max_replay_window: int = 1000

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """Encrypt a message with sequence number and replay protection."""
        self._sequence_number += 1
        seq = self._sequence_number
        timestamp = int(time.time())
        nonce = os.urandom(12)

        # Include seq and timestamp in authenticated data
        aad = struct.pack(">Q", seq) + struct.pack(">Q", timestamp)

        aesgcm = AESGCM(self._session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Format: [seq (8)] [timestamp (8)] [nonce (12)] [ciphertext]
        return aad + nonce + ciphertext

    def decrypt_message(self, message: bytes) -> bytes:
        """Decrypt a message, checking for replay and tampering."""
        if len(message) < 28:  # 8 + 8 + 12 minimum
            raise QuantumSafeError("Message too short")

        seq = struct.unpack(">Q", message[:8])[0]
        timestamp = struct.unpack(">Q", message[8:16])[0]
        nonce = message[16:28]
        ciphertext = message[28:]

        # Replay detection
        if seq in self._used_sequence_numbers:
            raise QuantumSafeError(f"Replay detected: sequence number {seq} already used")

        # Check timestamp is reasonable (within 5 minutes)
        now = int(time.time())
        if abs(now - timestamp) > 300:
            raise QuantumSafeError("Message timestamp too old or too far in future")

        # Decrypt
        aad = message[:16]  # seq + timestamp
        aesgcm = AESGCM(self._session_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise QuantumSafeError(f"Decryption failed: {e}") from e

        # Mark sequence number as used
        self._used_sequence_numbers.add(seq)

        # Cleanup old sequence numbers to prevent memory bloat
        if len(self._used_sequence_numbers) > self._max_replay_window:
            min_seq = min(self._used_sequence_numbers)
            self._used_sequence_numbers = {
                s for s in self._used_sequence_numbers
                if s > min_seq
            }

        return plaintext


# ── Certificate ───────────────────────────────────────────────────────

@dataclass
class Certificate:
    """Simple certificate for authenticating public keys."""
    subject: str
    public_key: bytes
    signature: Optional[bytes] = None
    timestamp: float = field(default_factory=time.time)

    @staticmethod
    def create(subject: str, public_key: bytes) -> "Certificate":
        """Create a new certificate."""
        return Certificate(subject=subject, public_key=public_key)

    def _signing_data(self) -> bytes:
        """Get the data that is signed."""
        return self.subject.encode() + self.public_key + struct.pack(">d", self.timestamp)

    def sign(self, signing_key: bytes) -> None:
        """Sign the certificate with HMAC-SHA256."""
        data = self._signing_data()
        self.signature = hmac.new(signing_key, data, hashlib.sha256).digest()

    def verify(self, signing_key: bytes) -> bool:
        """Verify the certificate signature."""
        if self.signature is None:
            return False
        data = self._signing_data()
        expected = hmac.new(signing_key, data, hashlib.sha256).digest()
        return hmac.compare_digest(self.signature, expected)


# ── Secure Channel ─────────────────────────────────────────────────────

class SecureChannel:
    """Secure channel combining hybrid KEM, HKDF, and secure messaging.

    Protocol:
    1. Alice generates hybrid keypair, sends public keys (ChannelHello)
    2. Bob generates hybrid keypair, encapsulates to Alice's keys,
       derives session key, sends response (ChannelResponse)
    3. Alice decapsulates, derives same session key
    4. Both use SecureMessageProtocol for encrypted communication
    """

    def __init__(self, name: str):
        self._name = name
        self._hybrid_kp: Optional[HybridKeyPair] = None
        self._session_key: Optional[bytes] = None
        self._message_protocol: Optional[SecureMessageProtocol] = None
        self._used_handshakes: Set[bytes] = set()

    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key

    def initiate(self) -> bytes:
        """Initiate channel: generate keys and return public key bundle."""
        self._hybrid_kp = HybridKeyExchange.generate_keypair()
        # Return: kyber_pk (800) + x25519_pk (32) = 832 bytes
        return self._hybrid_kp.kyber_public_key + self._hybrid_kp.x25519_public_key

    def respond(self, hello: bytes) -> bytes:
        """Respond to channel initiation."""
        if len(hello) != 832:
            raise QuantumSafeValidationError("Invalid hello message size")

        # Parse hello
        kyber_pk = hello[:800]
        x25519_pk = hello[800:]

        # Generate our keys
        self._hybrid_kp = HybridKeyExchange.generate_keypair()

        # Encapsulate to initiator's keys
        combined_ct, shared_secret = HybridKeyExchange.encapsulate(kyber_pk, x25519_pk)

        # Derive session key
        self._session_key = HKDFDerivation.derive(
            shared_secret, salt=b"secure-channel", info=b"session-key"
        )
        self._message_protocol = SecureMessageProtocol(self._session_key)

        # Return: combined_ct (800) + our_kyber_pk (800) + our_x25519_pk (32) = 1632
        return combined_ct + self._hybrid_kp.kyber_public_key + self._hybrid_kp.x25519_public_key

    def complete(self, response: bytes) -> None:
        """Complete channel establishment."""
        if len(response) != 1632:
            raise QuantumSafeValidationError("Invalid response message size")
        if self._hybrid_kp is None:
            raise QuantumSafeError("Channel not initiated")

        # Parse response
        combined_ct = response[:800]
        # server_kyber_pk = response[800:1600]  # Not needed for key derivation
        # server_x25519_pk = response[1600:]    # Not needed for key derivation

        # Check for replay
        handshake_id = hashlib.sha256(combined_ct).digest()
        if handshake_id in self._used_handshakes:
            raise QuantumSafeError("Replay attack detected: handshake already used")
        self._used_handshakes.add(handshake_id)

        # Decapsulate
        shared_secret = HybridKeyExchange.decapsulate(
            combined_ct,
            self._hybrid_kp.kyber_secret_key,
            self._hybrid_kp.x25519_secret_key,
        )

        # Derive session key (same as responder)
        self._session_key = HKDFDerivation.derive(
            shared_secret, salt=b"secure-channel", info=b"session-key"
        )
        self._message_protocol = SecureMessageProtocol(self._session_key)

    def send(self, plaintext: bytes) -> bytes:
        """Send an encrypted message."""
        if self._message_protocol is None:
            raise QuantumSafeError("Channel not established")
        return self._message_protocol.encrypt_message(plaintext)

    def receive(self, message: bytes) -> bytes:
        """Receive and decrypt a message."""
        if self._message_protocol is None:
            raise QuantumSafeError("Channel not established")
        return self._message_protocol.decrypt_message(message)
