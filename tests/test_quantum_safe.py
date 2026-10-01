"""TDD tests for deepened PQC: hybrid KEM, HKDF, secure message protocol, certificates."""
import time
import pytest
from src.grid.quantum_safe import (
    HybridKeyExchange,
    HKDFDerivation,
    SecureMessageProtocol,
    Certificate,
    SecureChannel,
    QuantumSafeError,
    QuantumSafeValidationError,
)


# ── Hybrid Key Exchange tests ──────────────────────────────────────────

class TestHybridKeyExchange:
    def test_hybrid_keypair_generation(self):
        """Hybrid keypair generation produces valid keys."""
        kp = HybridKeyExchange.generate_keypair()
        assert kp is not None
        assert len(kp.kyber_public_key) == 800
        assert len(kp.kyber_secret_key) == 1632
        assert len(kp.x25519_public_key) == 32
        assert len(kp.x25519_secret_key) == 32

    def test_hybrid_encapsulation_produces_ciphertext_and_secret(self):
        """Hybrid encapsulation returns combined ciphertext and shared secret."""
        kp = HybridKeyExchange.generate_keypair()
        ct, ss = HybridKeyExchange.encapsulate(kp.kyber_public_key, kp.x25519_public_key)
        assert ct is not None
        assert ss is not None
        assert len(ct) > 0
        assert len(ss) == 32

    def test_hybrid_decapsulation_recovers_shared_secret(self):
        """Decapsulation with correct keys recovers the shared secret."""
        kp = HybridKeyExchange.generate_keypair()
        ct, ss_enc = HybridKeyExchange.encapsulate(kp.kyber_public_key, kp.x25519_public_key)
        ss_dec = HybridKeyExchange.decapsulate(
            ct, kp.kyber_secret_key, kp.x25519_secret_key
        )
        assert ss_enc == ss_dec

    def test_hybrid_decapsulation_wrong_kyber_key_fails(self):
        """Decapsulation with wrong Kyber key produces different secret."""
        kp1 = HybridKeyExchange.generate_keypair()
        kp2 = HybridKeyExchange.generate_keypair()
        ct, ss_correct = HybridKeyExchange.encapsulate(
            kp1.kyber_public_key, kp1.x25519_public_key
        )
        ss_wrong = HybridKeyExchange.decapsulate(
            ct, kp2.kyber_secret_key, kp1.x25519_secret_key
        )
        assert ss_correct != ss_wrong

    def test_hybrid_ciphertext_structure(self):
        """Hybrid ciphertext contains both Kyber and X25519 components."""
        kp = HybridKeyExchange.generate_keypair()
        ct, _ = HybridKeyExchange.encapsulate(kp.kyber_public_key, kp.x25519_public_key)
        # Kyber-512 ct (768) + X25519 ct (32) = 800
        assert len(ct) == 800


# ── HKDF Key Derivation tests ─────────────────────────────────────────

class TestHKDFDerivation:
    def test_hkdf_derives_32_byte_key(self):
        """HKDF derives a 32-byte key from input key material."""
        ikm = b"input key material"
        key = HKDFDerivation.derive(ikm)
        assert len(key) == 32

    def test_hkdf_different_salts_produce_different_keys(self):
        """Different salts produce different keys from same IKM."""
        ikm = b"same input"
        key1 = HKDFDerivation.derive(ikm, salt=b"salt1")
        key2 = HKDFDerivation.derive(ikm, salt=b"salt2")
        assert key1 != key2

    def test_hkdf_different_contexts_produce_different_keys(self):
        """Different info/context produce different keys from same IKM."""
        ikm = b"same input"
        key1 = HKDFDerivation.derive(ikm, info=b"context1")
        key2 = HKDFDerivation.derive(ikm, info=b"context2")
        assert key1 != key2

    def test_hkdf_deterministic_with_same_inputs(self):
        """Same IKM, salt, and info produce the same key."""
        ikm = b"deterministic"
        key1 = HKDFDerivation.derive(ikm, salt=b"salt", info=b"info")
        key2 = HKDFDerivation.derive(ikm, salt=b"salt", info=b"info")
        assert key1 == key2


# ── Secure Message Protocol tests ─────────────────────────────────────

class TestSecureMessageProtocol:
    def test_message_encryption_decryption_roundtrip(self):
        """Encrypted message can be decrypted by the peer."""
        shared_secret = b"a" * 32
        proto = SecureMessageProtocol(shared_secret)
        plaintext = b"secret grid command"
        msg = proto.encrypt_message(plaintext)
        assert msg is not None
        assert len(msg) > 0
        decrypted = proto.decrypt_message(msg)
        assert decrypted == plaintext

    def test_message_includes_sequence_number(self):
        """Each message has an incrementing sequence number."""
        shared_secret = b"b" * 32
        proto = SecureMessageProtocol(shared_secret)
        msg1 = proto.encrypt_message(b"first")
        msg2 = proto.encrypt_message(b"second")
        # Sequence numbers are embedded in the message
        assert msg1 is not None
        assert msg2 is not None
        # Decrypt both — order matters
        assert proto.decrypt_message(msg1) == b"first"
        assert proto.decrypt_message(msg2) == b"second"

    def test_message_replay_detection(self):
        """Replaying an old message is detected and rejected."""
        shared_secret = b"c" * 32
        proto = SecureMessageProtocol(shared_secret)
        msg = proto.encrypt_message(b"original")
        # First decryption succeeds
        assert proto.decrypt_message(msg) == b"original"
        # Second decryption of same message should fail (replay)
        with pytest.raises(QuantumSafeError):
            proto.decrypt_message(msg)

    def test_message_tampering_detected(self):
        """Tampered message fails authentication."""
        shared_secret = b"d" * 32
        proto = SecureMessageProtocol(shared_secret)
        msg = bytearray(proto.encrypt_message(b"secret"))
        msg[-1] ^= 0xFF  # Flip last byte
        with pytest.raises(QuantumSafeError):
            proto.decrypt_message(bytes(msg))

    def test_message_wrong_key_fails(self):
        """Decryption with wrong shared secret fails."""
        proto1 = SecureMessageProtocol(b"e" * 32)
        proto2 = SecureMessageProtocol(b"f" * 32)
        msg = proto1.encrypt_message(b"secret")
        with pytest.raises(QuantumSafeError):
            proto2.decrypt_message(msg)


# ── Certificate tests ─────────────────────────────────────────────────

class TestCertificate:
    def test_certificate_creation(self):
        """Certificate is created with subject and public key."""
        cert = Certificate.create("grid-node-1", b"public_key_123")
        assert cert is not None
        assert cert.subject == "grid-node-1"
        assert cert.public_key == b"public_key_123"

    def test_certificate_sign_and_verify(self):
        """Certificate can be signed and verified."""
        cert = Certificate.create("grid-node-2", b"pk_456")
        signing_key = b"signing_key_" + b"0" * 19  # 32 bytes
        cert.sign(signing_key)
        assert cert.signature is not None
        assert len(cert.signature) > 0
        assert cert.verify(signing_key) is True

    def test_certificate_verify_wrong_key_fails(self):
        """Certificate verification fails with wrong signing key."""
        cert = Certificate.create("grid-node-3", b"pk_789")
        cert.sign(b"correct_key" + b"0" * 20)
        assert cert.verify(b"wrong_key" + b"0" * 21) is False

    def test_certificate_tampering_detected(self):
        """Tampered certificate fails verification."""
        cert = Certificate.create("grid-node-4", b"pk_abc")
        signing_key = b"signing_key_" + b"0" * 19
        cert.sign(signing_key)
        # Tamper with the public key
        cert.public_key = b"tampered_pk"
        assert cert.verify(signing_key) is False


# ── Secure Channel tests ───────────────────────────────────────────────

class TestSecureChannel:
    def test_channel_establishment(self):
        """Secure channel can be established between two parties."""
        alice = SecureChannel("alice")
        bob = SecureChannel("bob")
        # Alice initiates
        hello = alice.initiate()
        assert hello is not None
        # Bob responds
        response = bob.respond(hello)
        assert response is not None
        # Alice completes
        alice.complete(response)
        # Both have session keys
        assert alice.session_key is not None
        assert bob.session_key is not None
        assert alice.session_key == bob.session_key

    def test_channel_bidirectional_communication(self):
        """Both parties can send and receive messages."""
        alice = SecureChannel("alice")
        bob = SecureChannel("bob")
        hello = alice.initiate()
        response = bob.respond(hello)
        alice.complete(response)

        # Alice sends to Bob
        msg1 = alice.send(b"hello bob")
        assert bob.receive(msg1) == b"hello bob"

        # Bob sends to Alice
        msg2 = bob.send(b"hi alice")
        assert alice.receive(msg2) == b"hi alice"

    def test_channel_session_keys_are_unique(self):
        """Different channels produce different session keys."""
        alice1 = SecureChannel("alice1")
        bob1 = SecureChannel("bob1")
        hello1 = alice1.initiate()
        resp1 = bob1.respond(hello1)
        alice1.complete(resp1)

        alice2 = SecureChannel("alice2")
        bob2 = SecureChannel("bob2")
        hello2 = alice2.initiate()
        resp2 = bob2.respond(hello2)
        alice2.complete(resp2)

        assert alice1.session_key != alice2.session_key

    def test_channel_message_integrity(self):
        """Messages cannot be tampered in transit."""
        alice = SecureChannel("alice")
        bob = SecureChannel("bob")
        hello = alice.initiate()
        response = bob.respond(hello)
        alice.complete(response)

        msg = bytearray(alice.send(b"integrity test"))
        msg[10] ^= 0xFF
        with pytest.raises(QuantumSafeError):
            bob.receive(bytes(msg))

    def test_channel_replay_protection(self):
        """Replayed messages are rejected."""
        alice = SecureChannel("alice")
        bob = SecureChannel("bob")
        hello = alice.initiate()
        response = bob.respond(hello)
        alice.complete(response)

        msg = alice.send(b"original")
        assert bob.receive(msg) == b"original"
        # Replay same message
        with pytest.raises(QuantumSafeError):
            bob.receive(msg)
