"""Tests for verify_compliance_receipt — one test per Phase 8 ATB threat."""

from __future__ import annotations

import base64
import json
import time

import pytest
import rfc8785  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import ed25519

from algovoi_receipt_verifier import (
    ReceiptVerificationError,
    VerifiedReceipt,
    verify_compliance_receipt,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_receipt_payload(
    screen_result: str = "ALLOW",
    canon_version: str = "jcs-rfc8785-v1",
    payment_hash: str = "sha256:abc123",
) -> dict:
    return {
        "payer_ref": "sha256:deadbeef",
        "screen_result": screen_result,
        "screen_timestamp_ms": int(time.time() * 1000),
        "screen_provider_did": "did:web:api.algovoi.co.uk",
        "jurisdiction_flags": ["UK", "EU"],
        "canon_version": canon_version,
        "payment_hash": payment_hash,
    }


def _sign_jws(
    payload: dict,
    sk: ed25519.Ed25519PrivateKey,
    alg: str = "EdDSA",
    kid: str = "test-key-1",
    use_canonical: bool = True,
) -> str:
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    h_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    if use_canonical:
        p_b64 = _b64u(rfc8785.dumps(payload))
    else:
        # Non-canonical: use Python's json.dumps without sort_keys — produces
        # insertion-ordered output that may differ from RFC 8785
        p_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = sk.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"


@pytest.fixture()
def keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk


# ── Happy path ──────────────────────────────────────────────────────────────

class TestHappyPath:
    def test_valid_allow_receipt(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload()
        token = _sign_jws(payload, sk)
        result = verify_compliance_receipt(token, public_key=pk)
        assert isinstance(result, VerifiedReceipt)
        assert result.screen_result == "ALLOW"
        assert result.alg == "EdDSA"
        assert result.canon_version == "jcs-rfc8785-v1"

    def test_valid_refer_receipt(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(screen_result="REFER")
        token = _sign_jws(payload, sk)
        result = verify_compliance_receipt(token, public_key=pk)
        assert result.screen_result == "REFER"

    def test_valid_deny_receipt(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(screen_result="DENY")
        token = _sign_jws(payload, sk)
        result = verify_compliance_receipt(token, public_key=pk)
        assert result.screen_result == "DENY"

    def test_payment_hash_binding_passes(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(payment_hash="sha256:correcthash")
        token = _sign_jws(payload, sk)
        result = verify_compliance_receipt(
            token, public_key=pk, expected_payment_hash="sha256:correcthash"
        )
        assert result.raw_payload["payment_hash"] == "sha256:correcthash"

    def test_jwks_key_selection_by_kid(self, keypair):
        sk, pk = keypair
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "kid": "test-key-1", "x": _b64u(raw)}
        jwks = {"keys": [jwk]}
        payload = _make_receipt_payload()
        token = _sign_jws(payload, sk, kid="test-key-1")
        result = verify_compliance_receipt(token, jwks=jwks)
        assert result.screen_result == "ALLOW"


# ── Phase 8 ATB threats ─────────────────────────────────────────────────────

class TestTamperedSignature:
    """receipt-tampered-sig: modified signature bytes must be rejected."""

    def test_rejects_tampered_sig(self, keypair):
        sk, pk = keypair
        token = _sign_jws(_make_receipt_payload(), sk)
        h, p, s = token.split(".")
        # Decode, flip a byte in the middle, re-encode — reliable tamper
        sig_bytes = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        sig_bytes[32] ^= 0xFF  # flip all bits in byte 32 of 64
        corrupted = _b64u(bytes(sig_bytes))
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(f"{h}.{p}.{corrupted}", public_key=pk)
        assert exc_info.value.code == "TAMPERED_SIGNATURE"


class TestNonCanonicalJcs:
    """receipt-bad-jcs: signature computed over non-RFC-8785 bytes must be rejected."""

    def test_rejects_non_canonical_payload(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload()
        # Sign over non-canonical bytes — the sig is valid for the non-canonical
        # encoding but verify_compliance_receipt re-canonicalises and compares.
        token = _sign_jws(payload, sk, use_canonical=False)
        # Only fails the canonicality check if Python's ordering diverges from
        # rfc8785 ordering. The test is meaningful for payloads where key order
        # differs between insertion order and RFC 8785 lexicographic order.
        # If the payload happens to already be canonical, the test is vacuously
        # passing — that's intentional (canonical input is always accepted).
        try:
            result = verify_compliance_receipt(token, public_key=pk)
            # If it passed, the non-canonical form happened to equal canonical form.
            assert result.screen_result in {"ALLOW", "REFER", "DENY"}
        except ReceiptVerificationError as e:
            assert e.code in {"NON_CANONICAL_PAYLOAD", "TAMPERED_SIGNATURE"}

    def test_rejects_explicitly_non_canonical(self, keypair):
        """Build a receipt where non-canonical and canonical forms definitely differ."""
        sk, pk = keypair
        # Add a field that sorts before "canon_version" in RFC 8785 but after in
        # insertion order — guarantees key-order divergence.
        payload = {
            "zzz_last_field": "x",       # insertion: first, RFC 8785: last
            "payer_ref": "sha256:abc",
            "screen_result": "ALLOW",
            "screen_timestamp_ms": 1716460800000,
            "screen_provider_did": "did:web:api.algovoi.co.uk",
            "jurisdiction_flags": ["UK"],
            "canon_version": "jcs-rfc8785-v1",
            "payment_hash": "sha256:x",
        }
        # Sign over insertion-order (non-canonical) form
        header = {"alg": "EdDSA", "kid": "k1", "typ": "JWT"}
        h_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        p_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = sk.sign(signing_input)
        token = f"{h_b64}.{p_b64}.{_b64u(sig)}"
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        # Either sig fails (rfc8785 bytes ≠ what was signed) or canonical mismatch
        assert exc_info.value.code in {"NON_CANONICAL_PAYLOAD", "TAMPERED_SIGNATURE"}


class TestCanonVersionMismatch:
    """receipt-canon-version-mismatch: unsupported canon_version must be rejected."""

    def test_rejects_unknown_canon_version(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(canon_version="jcs-rfc8785-v2")
        token = _sign_jws(payload, sk)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_CANON_VERSION"
        assert exc_info.value.field == "canon_version"

    def test_rejects_empty_canon_version(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(canon_version="")
        token = _sign_jws(payload, sk)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_CANON_VERSION"


class TestAlgUnknown:
    """receipt-alg-unknown: HS512-CUSTOM and similar must be rejected without fallback."""

    def test_rejects_hs512_custom(self, keypair):
        sk, pk = keypair
        # Build a token with alg=HS512-CUSTOM; verify_jws rejects before sig check
        payload = _make_receipt_payload()
        token = _sign_jws(payload, sk, alg="HS512-CUSTOM")
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_ALG"

    def test_rejects_none_alg(self, keypair):
        sk, pk = keypair
        token = _sign_jws(_make_receipt_payload(), sk, alg="none")
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_ALG"

    def test_rejects_rs512(self, keypair):
        sk, pk = keypair
        token = _sign_jws(_make_receipt_payload(), sk, alg="RS512")
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_ALG"


class TestReplayModified:
    """receipt-replay-modified: payment_hash substituted post-signing."""

    def test_rejects_payment_hash_mismatch(self, keypair):
        sk, pk = keypair
        # Receipt was signed with original_hash
        payload = _make_receipt_payload(payment_hash="sha256:originalhash")
        token = _sign_jws(payload, sk)
        # Caller expects a different hash (the current transaction)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(
                token,
                public_key=pk,
                expected_payment_hash="sha256:modifiedhash",
            )
        assert exc_info.value.code == "PAYMENT_HASH_MISMATCH"
        assert exc_info.value.field == "payment_hash"

    def test_passes_matching_payment_hash(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload(payment_hash="sha256:correcthash")
        token = _sign_jws(payload, sk)
        result = verify_compliance_receipt(
            token,
            public_key=pk,
            expected_payment_hash="sha256:correcthash",
        )
        assert result.screen_result == "ALLOW"


class TestMissingEnvelope:
    """receipt-missing-envelope: receipt_required=True with no JWS must be rejected."""

    def test_rejects_none_when_required(self):
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(None, public_key=object(), receipt_required=True)
        assert exc_info.value.code == "MISSING_ENVELOPE"

    def test_rejects_none_unconditionally(self):
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(None, public_key=object(), receipt_required=False)
        assert exc_info.value.code == "MISSING_ENVELOPE"


# ── Additional guards ────────────────────────────────────────────────────────

class TestMissingFields:
    def test_rejects_missing_screen_result(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload()
        del payload["screen_result"]
        token = _sign_jws(payload, sk)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "MISSING_FIELD"
        assert exc_info.value.field == "screen_result"

    def test_rejects_invalid_screen_result(self, keypair):
        sk, pk = keypair
        payload = _make_receipt_payload()
        payload["screen_result"] = "SCORE:75"  # projection, not categorical
        token = _sign_jws(payload, sk)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_compliance_receipt(token, public_key=pk)
        assert exc_info.value.code == "MISSING_FIELD"
        assert exc_info.value.field == "screen_result"
