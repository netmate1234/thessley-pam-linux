"""The phone's attestation chain decides whether its key is hardware-backed.

These tests build a small chain (leaf -> intermediate -> root) that mimics
what an Android phone sends, so the checks run without a real device.
"""

import base64
import datetime
import os
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thessley_pam import attestation  # noqa: E402

KEY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
NOW = datetime.datetime.now(datetime.timezone.utc)


def _tlv(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        return bytes([tag, length]) + body
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + body


def key_description(attestation_level: int, key_level: int, challenge: bytes) -> bytes:
    body = (_tlv(0x02, b"\x03")            # attestationVersion
            + _tlv(0x0A, bytes([attestation_level]))
            + _tlv(0x02, b"\x04")          # keymasterVersion
            + _tlv(0x0A, bytes([key_level]))
            + _tlv(0x04, challenge)
            + _tlv(0x04, b"")              # uniqueId
            + _tlv(0x30, b"")              # softwareEnforced
            + _tlv(0x30, b""))             # teeEnforced
    return _tlv(0x30, body)


def _certificate(subject: str, issuer: str, public_key, signer, extension: bytes | None = None,
                 not_before=None, not_after=None):
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
               .public_key(public_key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before or NOW - datetime.timedelta(days=1))
               .not_valid_after(not_after or NOW + datetime.timedelta(days=30)))
    if extension is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(KEY_OID, extension), critical=False)
    return builder.sign(signer, hashes.SHA256())


class Chain:
    """A leaf key with its attestation certificate, an intermediate and a root."""

    def __init__(self, challenge: bytes = b"nonce-123", attestation_level: int = 1,
                 key_level: int = 1, with_extension: bool = True, expired: bool = False):
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        root_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _certificate("Fake Root", "Fake Root", root_key.public_key(), root_key)
        not_before = NOW - datetime.timedelta(days=40) if expired else NOW - datetime.timedelta(days=1)
        not_after = NOW - datetime.timedelta(days=10) if expired else NOW + datetime.timedelta(days=30)
        self.intermediate = _certificate("Fake Intermediate", "Fake Root",
                                         intermediate_key.public_key(), root_key,
                                         not_before=not_before, not_after=not_after)
        extension = key_description(attestation_level, key_level, challenge) if with_extension else None
        self.leaf = _certificate("Android Keystore Key", "Fake Intermediate",
                                 self.leaf_key.public_key(), intermediate_key, extension,
                                 not_before=not_before, not_after=not_after)
        self.root_spki = root_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def chain(self) -> list[str]:
        return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
                for cert in (self.leaf, self.intermediate)]

    def leaf_spki(self) -> bytes:
        return self.leaf_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify(chain: Chain, **kwargs):
    with patch.object(attestation, "_revocation_entries", return_value={}):
        return attestation.verify_chain(
            chain.chain(), expected_public_key_spki=chain.leaf_spki(),
            trusted_root_spki_der=chain.root_spki, **kwargs)


class AttestationTest(unittest.TestCase):
    def test_hardware_tee_chain_is_verified(self):
        chain = Chain()
        result = verify(chain, expected_challenge=b"nonce-123")
        self.assertEqual(result["status"], "verified_tee")
        self.assertEqual(result["reason"], "hardware_attestation_valid")

    def test_strongbox_is_reported_as_strongbox(self):
        result = verify(Chain(key_level=2))
        self.assertEqual(result["status"], "verified_strongbox")

    def test_software_key_is_genuine_but_not_hardware(self):
        result = verify(Chain(attestation_level=0, key_level=0))
        self.assertEqual(result["status"], "verified_software")

    def test_wrong_challenge_is_unverified(self):
        result = verify(Chain(), expected_challenge=b"another-nonce")
        self.assertEqual(result, {"status": "unverified", "reason": "challenge_mismatch"})

    def test_missing_extension_is_unverified(self):
        result = verify(Chain(with_extension=False))
        self.assertEqual(result["reason"], "missing_key_description")

    def test_expired_certificate_is_unverified(self):
        result = verify(Chain(expired=True))
        self.assertEqual(result["reason"], "certificate_out_of_validity")

    def test_untrusted_root_is_unverified(self):
        chain = Chain()
        with patch.object(attestation, "_revocation_entries", return_value={}):
            result = attestation.verify_chain(chain.chain(), expected_public_key_spki=chain.leaf_spki())
        self.assertEqual(result["reason"], "untrusted_attestation_root")

    def test_revoked_certificate_is_unverified(self):
        chain = Chain()
        serial = format(chain.leaf.serial_number, "x")
        with patch.object(attestation, "_revocation_entries", return_value={serial: {"status": "REVOKED"}}):
            result = attestation.verify_chain(chain.chain(), expected_public_key_spki=chain.leaf_spki(),
                                              trusted_root_spki_der=chain.root_spki)
        self.assertEqual(result["reason"], "attestation_certificate_revoked")

    def test_legacy_device_without_nonce_still_shows_hardware(self):
        result = verify(Chain())
        self.assertEqual(result["status"], "verified_tee")
        self.assertEqual(result["reason"], "hardware_attestation_valid_challenge_unchecked")

    def test_empty_chain_is_unverified(self):
        result = attestation.verify_chain([], expected_public_key_spki=b"key")
        self.assertEqual(result["status"], "unverified")


if __name__ == "__main__":
    unittest.main()
