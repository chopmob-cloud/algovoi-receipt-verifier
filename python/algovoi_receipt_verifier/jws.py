"""
JWS compact-serialisation decoder and verifier.

Supports EdDSA (Ed25519), ES256K, and RS256 — the three algorithms in
the x402 compliance-receipt permitted-algorithm list. Any other alg value
raises ReceiptVerificationError with code UNSUPPORTED_ALG.

The module is intentionally minimal: no network calls, no key-fetching.
Callers supply the public key. The receipt layer (receipt.py) handles
did:web resolution and canon_version validation on top.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from algovoi_receipt_verifier.errors import ReceiptVerificationError

# Permitted algorithm list — mirrors bench.py Phase 8 profiles and the
# x402 compliance-receipt spec. Any other alg is UNSUPPORTED_ALG.
PERMITTED_ALGS: frozenset[str] = frozenset({"EdDSA", "ES256K", "RS256"})

# canon_version registry — extend when new versions are ratified.
SUPPORTED_CANON_VERSIONS: frozenset[str] = frozenset({"jcs-rfc8785-v1"})


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_jws(token: str) -> tuple[dict[str, Any], bytes, bytes]:
    """Decode a compact JWS string into (header, raw_payload_bytes, signature_bytes).

    Does NOT verify the signature. Use verify_jws() for that.

    Raises ReceiptVerificationError(INVALID_JWS_FORMAT) if the token is not
    a well-formed three-part base64url string or if the header is not valid JSON.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message=f"Expected 3-part compact JWS, got {len(parts)} parts",
        )
    h_b64, p_b64, s_b64 = parts
    try:
        header: dict[str, Any] = json.loads(_b64u_decode(h_b64))
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message=f"JWS protected header is not valid JSON: {exc}",
        ) from exc
    try:
        raw_payload = _b64u_decode(p_b64)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message=f"JWS payload is not valid base64url: {exc}",
        ) from exc
    try:
        sig = _b64u_decode(s_b64)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message=f"JWS signature is not valid base64url: {exc}",
        ) from exc
    return header, raw_payload, sig


def verify_jws(
    token: str,
    *,
    public_key: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a compact JWS and return (header, payload_dict).

    public_key must be one of:
      - cryptography Ed25519PublicKey
      - cryptography EllipticCurvePublicKey (secp256k1 for ES256K)
      - cryptography RSAPublicKey

    Raises ReceiptVerificationError with one of:
      INVALID_JWS_FORMAT   — malformed token
      UNSUPPORTED_ALG      — alg not in PERMITTED_ALGS
      TAMPERED_SIGNATURE   — signature verification failed
      INVALID_PAYLOAD      — payload is not valid JSON
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    h_b64, p_b64, _ = token.split(".") if token.count(".") == 2 else (None, None, None)
    if h_b64 is None:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message="Not a compact JWS",
        )

    header, raw_payload, sig = decode_jws(token)

    alg = header.get("alg", "")
    if alg not in PERMITTED_ALGS:
        raise ReceiptVerificationError(
            code="UNSUPPORTED_ALG",
            message=(
                f"Algorithm {alg!r} is not in the permitted list "
                f"({sorted(PERMITTED_ALGS)}). Reject without fallback."
            ),
        )

    signing_input = f"{h_b64}.{p_b64}".encode()

    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig, signing_input)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # ES256K — secp256k1 with SHA-256
            public_key.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            # RS256
            public_key.verify(
                sig, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            raise ReceiptVerificationError(
                code="UNSUPPORTED_ALG",
                message=f"Unrecognised public key type: {type(public_key).__name__}",
            )
    except InvalidSignature as exc:
        raise ReceiptVerificationError(
            code="TAMPERED_SIGNATURE",
            message="JWS signature verification failed — receipt has been tampered.",
        ) from exc

    try:
        payload: dict[str, Any] = json.loads(raw_payload)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_PAYLOAD",
            message=f"JWS payload is not valid JSON after signature verification: {exc}",
        ) from exc

    return header, payload


def public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Load a public key from a JWK dict.

    Supports kty=OKP (Ed25519), kty=EC (ES256K), kty=RSA (RS256).
    Raises ReceiptVerificationError(UNSUPPORTED_ALG) for unsupported kty/crv.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    kty = jwk.get("kty", "")
    if kty == "OKP":
        crv = jwk.get("crv", "")
        if crv != "Ed25519":
            raise ReceiptVerificationError(
                code="UNSUPPORTED_ALG",
                message=f"OKP curve {crv!r} is not supported (expected Ed25519)",
            )
        x_bytes = _b64u_decode(jwk["x"])
        return ed25519.Ed25519PublicKey.from_public_bytes(x_bytes)
    elif kty == "EC":
        crv = jwk.get("crv", "")
        if crv != "secp256k1":
            raise ReceiptVerificationError(
                code="UNSUPPORTED_ALG",
                message=f"EC curve {crv!r} is not supported (expected secp256k1 for ES256K)",
            )
        x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=ec.SECP256K1()
        )
        return pub_numbers.public_key()
    elif kty == "RSA":
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        n = int.from_bytes(_b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64u_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e=e, n=n).public_key()
    else:
        raise ReceiptVerificationError(
            code="UNSUPPORTED_ALG",
            message=f"JWK kty {kty!r} is not supported",
        )
