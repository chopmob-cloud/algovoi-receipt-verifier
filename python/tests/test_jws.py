"""Tests for JWS decode / verify layer."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from algovoi_receipt_verifier import (
    ReceiptVerificationError,
    decode_jws,
    verify_jws,
)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_jws(
    payload: dict,
    private_key: ed25519.Ed25519PrivateKey,
    alg: str = "EdDSA",
    header_extra: dict | None = None,
) -> str:
    import rfc8785  # type: ignore[import-untyped]

    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = _b64u(rfc8785.dumps(payload))
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = private_key.sign(signing_input)
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"


@pytest.fixture()
def ed25519_keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk


class TestDecodeJws:
    def test_decodes_three_parts(self, ed25519_keypair):
        sk, pk = ed25519_keypair
        token = _make_jws({"foo": "bar"}, sk)
        header, raw_payload, sig = decode_jws(token)
        assert header["alg"] == "EdDSA"
        assert json.loads(raw_payload) == {"foo": "bar"}
        assert len(sig) == 64

    def test_rejects_two_part_token(self):
        with pytest.raises(ReceiptVerificationError, match="INVALID_JWS_FORMAT"):
            decode_jws("a.b")

    def test_rejects_four_part_token(self):
        with pytest.raises(ReceiptVerificationError, match="INVALID_JWS_FORMAT"):
            decode_jws("a.b.c.d")

    def test_rejects_bad_header_json(self):
        bad_header = _b64u(b"not-json")
        with pytest.raises(ReceiptVerificationError, match="INVALID_JWS_FORMAT"):
            decode_jws(f"{bad_header}.cGF5bG9hZA.c2ln")


class TestVerifyJws:
    def test_valid_eddsa_token(self, ed25519_keypair):
        sk, pk = ed25519_keypair
        token = _make_jws({"screen_result": "ALLOW"}, sk)
        header, payload = verify_jws(token, public_key=pk)
        assert payload["screen_result"] == "ALLOW"
        assert header["alg"] == "EdDSA"

    def test_rejects_tampered_signature(self, ed25519_keypair):
        sk, pk = ed25519_keypair
        token = _make_jws({"foo": "bar"}, sk)
        h, p, s = token.split(".")
        # Flip one character in the signature
        corrupted_sig = s[:-1] + ("A" if s[-1] != "A" else "B")
        tampered = f"{h}.{p}.{corrupted_sig}"
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_jws(tampered, public_key=pk)
        assert exc_info.value.code == "TAMPERED_SIGNATURE"

    def test_rejects_unsupported_alg(self, ed25519_keypair):
        sk, pk = ed25519_keypair
        token = _make_jws({"foo": "bar"}, sk, alg="HS512-CUSTOM")
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_jws(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_ALG"

    def test_rejects_none_alg(self, ed25519_keypair):
        sk, pk = ed25519_keypair
        token = _make_jws({"foo": "bar"}, sk, alg="none")
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_jws(token, public_key=pk)
        assert exc_info.value.code == "UNSUPPORTED_ALG"

    def test_wrong_public_key_rejected(self):
        sk1 = ed25519.Ed25519PrivateKey.generate()
        pk2 = ed25519.Ed25519PrivateKey.generate().public_key()
        token = _make_jws({"foo": "bar"}, sk1)
        with pytest.raises(ReceiptVerificationError) as exc_info:
            verify_jws(token, public_key=pk2)
        assert exc_info.value.code == "TAMPERED_SIGNATURE"
