"""TDD tests for post-quantum cryptography: Kyber KEM, Dilithium signatures, QR-TLS."""
import pytest
from src.grid.pqc import (
    KyberKeyPair,
    KyberKEM,
    DilithiumKeyPair,
    DilithiumSignature,
    QuantumResistantTLS,
    PQCSecurityError,
    PQCValidationError,
)


# ── Kyber KEM tests ────────────────────────────────────────────────────

class TestKyberKEM:
    def test_kyber_keypair_generation(self):
        """Kyber keypair generation produces valid public and secret keys."""
        kp = KyberKEM.generate_keypair()
        assert isinstance(kp, KyberKeyPair)
        assert kp.public_key is not None
        assert kp.secret_key is not None
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_kyber_keypair_sizes(self):
        """Kyber-512 keys have correct byte sizes."""
        kp = KyberKEM.generate_keypair()
        # ML-KEM-512: pk=800 bytes, sk=1632 bytes
        assert len(kp.public_key) == 800
        assert len(kp.secret_key) == 1632

    def test_kyber_encapsulation_produces_ciphertext_and_secret(self):
        """Encapsulation returns ciphertext and shared secret."""
        kp = KyberKEM.generate_keypair()
        ct, ss = KyberKEM.encapsulate(kp.public_key)
        assert ct is not None
        assert ss is not None
        assert len(ct) > 0
        assert len(ss) == 32  # SHARED_SECRET_SIZE

    def test_kyber_decapsulation_recovers_shared_secret(self):
        """Decapsulation with correct secret key recovers the shared secret."""
        kp = KyberKEM.generate_keypair()
        ct, ss_enc = KyberKEM.encapsulate(kp.public_key)
        ss_dec = KyberKEM.decapsulate(ct, kp.secret_key)
        assert ss_enc == ss_dec

    def test_kyber_decapsulation_wrong_key_produces_different_secret(self):
        """Decapsulation with wrong secret key produces different shared secret (implicit rejection)."""
        kp1 = KyberKEM.generate_keypair()
        kp2 = KyberKEM.generate_keypair()
        ct, ss_correct = KyberKEM.encapsulate(kp1.public_key)
        ss_wrong = KyberKEM.decapsulate(ct, kp2.secret_key)
        assert ss_correct != ss_wrong

    def test_kyber_ciphertext_size(self):
        """Kyber-512 ciphertext has correct byte size."""
        kp = KyberKEM.generate_keypair()
        ct, _ = KyberKEM.encapsulate(kp.public_key)
        # ML-KEM-512: ct=768 bytes
        assert len(ct) == 768

    def test_kyber_different_keypairs_produce_different_secrets(self):
        """Different keypairs produce different shared secrets."""
        kp1 = KyberKEM.generate_keypair()
        kp2 = KyberKEM.generate_keypair()
        _, ss1 = KyberKEM.encapsulate(kp1.public_key)
        _, ss2 = KyberKEM.encapsulate(kp2.public_key)
        assert ss1 != ss2


# ── Dilithium signature tests ──────────────────────────────────────────

class TestDilithiumSignature:
    def test_dilithium_keypair_generation(self):
        """Dilithium keypair generation produces valid keys."""
        kp = DilithiumSignature.generate_keypair()
        assert isinstance(kp, DilithiumKeyPair)
        assert kp.public_key is not None
        assert kp.secret_key is not None
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_dilithium_keypair_sizes(self):
        """ML-DSA-44 keys have correct byte sizes."""
        kp = DilithiumSignature.generate_keypair()
        # ML-DSA-44: pk=1312 bytes, sk=2560 bytes
        assert len(kp.public_key) == 1312
        assert len(kp.secret_key) == 2560

    def test_dilithium_sign_and_verify(self):
        """Signing and verification round-trip succeeds."""
        kp = DilithiumSignature.generate_keypair()
        msg = b"test message for dilithium"
        sig = DilithiumSignature.sign(kp.secret_key, msg)
        assert sig is not None
        assert len(sig) > 0
        assert DilithiumSignature.verify(kp.public_key, msg, sig)

    def test_dilithium_verify_wrong_message_fails(self):
        """Verification fails when message is tampered."""
        kp = DilithiumSignature.generate_keypair()
        msg = b"original message"
        sig = DilithiumSignature.sign(kp.secret_key, msg)
        assert not DilithiumSignature.verify(kp.public_key, b"tampered message", sig)

    def test_dilithium_verify_wrong_key_fails(self):
        """Verification fails with wrong public key."""
        kp1 = DilithiumSignature.generate_keypair()
        kp2 = DilithiumSignature.generate_keypair()
        msg = b"test message"
        sig = DilithiumSignature.sign(kp1.secret_key, msg)
        assert not DilithiumSignature.verify(kp2.public_key, msg, sig)

    def test_dilithium_signature_size(self):
        """ML-DSA-44 signature has correct byte size."""
        kp = DilithiumSignature.generate_keypair()
        msg = b"test"
        sig = DilithiumSignature.sign(kp.secret_key, msg)
        # ML-DSA-44: sig=2420 bytes
        assert len(sig) == 2420

    def test_dilithium_randomized_signing(self):
        """Same message and key produce different signatures (randomized)."""
        kp = DilithiumSignature.generate_keypair()
        msg = b"randomized test"
        sig1 = DilithiumSignature.sign(kp.secret_key, msg)
        sig2 = DilithiumSignature.sign(kp.secret_key, msg)
        assert sig1 != sig2
        # Both should verify
        assert DilithiumSignature.verify(kp.public_key, msg, sig1)
        assert DilithiumSignature.verify(kp.public_key, msg, sig2)


# ── Quantum-resistant TLS tests ────────────────────────────────────────

class TestQuantumResistantTLS:
    def test_tls_handshake_establishes_session(self):
        """QR-TLS handshake completes and derives session keys."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        # Client initiates
        client_hello = client.initiate_handshake()
        assert client_hello is not None
        # Server responds
        server_response = server.respond_to_handshake(client_hello)
        assert server_response is not None
        # Client completes
        client.complete_handshake(server_response)
        # Both have session keys
        assert client.session_key is not None
        assert server.session_key is not None
        assert client.session_key == server.session_key

    def test_tls_session_key_length(self):
        """Session key is 32 bytes (256-bit)."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        client.complete_handshake(server_response)
        assert len(client.session_key) == 32

    def test_tls_encrypt_decrypt_roundtrip(self):
        """Encrypted message can be decrypted by the peer."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        client.complete_handshake(server_response)

        plaintext = b"secret grid command"
        ciphertext = client.encrypt(plaintext)
        assert ciphertext != plaintext
        decrypted = server.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_tls_decrypt_with_wrong_key_fails(self):
        """Decryption with wrong session key raises PQCSecurityError."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        client.complete_handshake(server_response)

        # Create a third party with different session keys
        eve = QuantumResistantTLS()
        eve.initiate_handshake()
        eve.complete_handshake(server_response)

        ciphertext = client.encrypt(b"secret")
        with pytest.raises(PQCSecurityError):
            eve.decrypt(ciphertext)

    def test_tls_tampered_ciphertext_fails(self):
        """Tampered ciphertext fails authentication."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        client.complete_handshake(server_response)

        ciphertext = bytearray(client.encrypt(b"secret"))
        ciphertext[0] ^= 0xFF  # Flip bits in first byte
        with pytest.raises(PQCSecurityError):
            server.decrypt(bytes(ciphertext))

    def test_tls_server_authentication(self):
        """Server is authenticated via Dilithium signature."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        # Server response contains a Dilithium signature
        assert hasattr(server_response, 'signature')
        assert server_response.signature is not None
        assert len(server_response.signature) > 0

    def test_tls_replay_attack_prevented(self):
        """Replay of old handshake messages is rejected."""
        client = QuantumResistantTLS()
        server = QuantumResistantTLS()
        client_hello = client.initiate_handshake()
        server_response = server.respond_to_handshake(client_hello)
        client.complete_handshake(server_response)

        # Attempt to reuse old handshake with same client
        with pytest.raises(PQCSecurityError):
            client.complete_handshake(server_response)

    def test_tls_multiple_sessions_independent(self):
        """Multiple TLS sessions produce independent keys."""
        client1 = QuantumResistantTLS()
        server1 = QuantumResistantTLS()
        ch1 = client1.initiate_handshake()
        sr1 = server1.respond_to_handshake(ch1)
        client1.complete_handshake(sr1)

        client2 = QuantumResistantTLS()
        server2 = QuantumResistantTLS()
        ch2 = client2.initiate_handshake()
        sr2 = server2.respond_to_handshake(ch2)
        client2.complete_handshake(sr2)

        assert client1.session_key != client2.session_key
        assert server1.session_key != server2.session_key
