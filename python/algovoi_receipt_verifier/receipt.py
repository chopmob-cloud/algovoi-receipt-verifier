"""
Compliance receipt verifier.

Accepts a compact JWS string (as emitted by AlgoVoi's /compliance/screen
and /verify endpoints) and returns a VerifiedReceipt on success, or raises
ReceiptVerificationError with a machine-readable code on any failure.

Verification steps (in order):
  1. JWS format — must be three-part base64url
  2. alg whitelist — EdDSA / ES256K / RS256 only; reject without fallback
  3. Signature — cryptographic verification against supplied public key
  4. canon_version — must be in SUPPORTED_CANON_VERSIONS registry
  5. JCS re-canonicalisation — re-canonicalise payload; compare byte-for-byte
  6. Required fields — payer_ref, screen_result, screen_timestamp_ms,
                       screen_provider_did, jurisdiction_flags, canon_version
  7. screen_result enum — must be ALLOW, REFER, or DENY
  8. payment_hash binding — if expected_payment_hash supplied, must match

To verify a receipt returned by api.algovoi.co.uk, fetch the JWKS from
https://api.algovoi.co.uk/.well-known/jwks.json and pass it as jwks:

    import httpx
    from algovoi_receipt_verifier import verify_compliance_receipt

    jwks = httpx.get("https://api.algovoi.co.uk/.well-known/jwks.json").json()
    result = verify_compliance_receipt(jws_token, jwks=jwks)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from algovoi_receipt_verifier.errors import ReceiptVerificationError
from algovoi_receipt_verifier.jws import (
    SUPPORTED_CANON_VERSIONS,
    decode_jws,
    public_key_from_jwk,
    verify_jws,
)

_REQUIRED_FIELDS = (
    "payer_ref",
    "screen_result",
    "screen_timestamp_ms",
    "screen_provider_did",
    "jurisdiction_flags",
    "canon_version",
)

_SCREEN_RESULTS = frozenset({"ALLOW", "REFER", "DENY"})


@dataclass(frozen=True)
class VerifiedReceipt:
    """A cryptographically verified compliance receipt.

    All fields have passed:
      - JWS signature verification
      - canon_version registry check
      - RFC 8785 JCS re-canonicalisation check
      - Required-field presence
      - screen_result enum validation

    Attributes:
        payer_ref:            Content-addressed payer identity (e.g. "sha256:<hex>").
        screen_result:        One of ALLOW, REFER, DENY.
        screen_timestamp_ms:  Epoch-millisecond integer (Substrate Rule 1).
        screen_provider_did:  did:web of the screening provider.
        jurisdiction_flags:   Ordered list of jurisdiction codes.
        canon_version:        Canonicalisation version pinned in the receipt.
        alg:                  JWS algorithm used (EdDSA / ES256K / RS256).
        kid:                  JWS key ID from protected header, or None.
        raw_payload:          The raw receipt dict from the verified JWS payload.
    """

    payer_ref: str
    screen_result: str
    screen_timestamp_ms: int
    screen_provider_did: str
    jurisdiction_flags: list[str]
    canon_version: str
    alg: str
    kid: str | None
    raw_payload: dict[str, Any]


def verify_compliance_receipt(
    jws_token: str | None,
    *,
    public_key: Any = None,
    jwks: dict[str, Any] | None = None,
    expected_payment_hash: str | None = None,
    receipt_required: bool = False,
) -> VerifiedReceipt:
    """Verify a compact JWS compliance receipt and return a VerifiedReceipt.

    Args:
        jws_token:              Compact JWS string ("h.p.s"). Pass None to trigger
                                MISSING_ENVELOPE when receipt_required=True.
        public_key:             A cryptography public key object. Supply either
                                this or jwks, not both.
        jwks:                   A JWK Set dict ({"keys": [...]}) from the issuer's
                                JWKS endpoint. The kid in the JWS header is used to
                                select the matching key; if no kid match, the first
                                key is tried.
        expected_payment_hash:  If supplied, the receipt's payment_hash field (if
                                present) must equal this value. Raises
                                PAYMENT_HASH_MISMATCH otherwise.
        receipt_required:       If True and jws_token is None, raises
                                MISSING_ENVELOPE.

    Raises:
        ReceiptVerificationError with one of:
          MISSING_ENVELOPE          — jws_token is None and receipt_required=True
          INVALID_JWS_FORMAT        — malformed compact JWS
          UNSUPPORTED_ALG           — alg not in permitted list
          TAMPERED_SIGNATURE        — signature failed
          UNSUPPORTED_CANON_VERSION — canon_version not in registry
          NON_CANONICAL_PAYLOAD     — JCS re-canonicalisation mismatch
          MISSING_FIELD             — required field absent
          PAYMENT_HASH_MISMATCH     — payment_hash doesn't match expected
    """
    if jws_token is None:
        if receipt_required:
            raise ReceiptVerificationError(
                code="MISSING_ENVELOPE",
                message=(
                    "receipt_required=True but no JWS receipt envelope was provided. "
                    "A bare acknowledgement string is not sufficient proof of settlement."
                ),
            )
        raise ReceiptVerificationError(
            code="MISSING_ENVELOPE",
            message="jws_token is None — no receipt to verify.",
        )

    if public_key is None and jwks is None:
        raise ValueError("Supply either public_key or jwks")

    if public_key is not None and jwks is not None:
        raise ValueError("Supply either public_key or jwks, not both")

    # Resolve key from JWKS if needed
    if jwks is not None:
        # Peek at the kid in the JWS header to select the right key
        header, _, _ = decode_jws(jws_token)
        kid = header.get("kid")
        keys = jwks.get("keys", [])
        if not keys:
            raise ReceiptVerificationError(
                code="INVALID_JWS_FORMAT",
                message="JWKS contains no keys",
            )
        matched = next(
            (k for k in keys if kid and k.get("kid") == kid),
            keys[0],  # fall back to first key if no kid match
        )
        public_key = public_key_from_jwk(matched)

    # Steps 1–3: format, alg whitelist, signature
    header, payload = verify_jws(jws_token, public_key=public_key)

    # Step 4: canon_version registry
    canon_version = payload.get("canon_version", "")
    if canon_version not in SUPPORTED_CANON_VERSIONS:
        raise ReceiptVerificationError(
            code="UNSUPPORTED_CANON_VERSION",
            message=(
                f"canon_version {canon_version!r} is not in the supported registry "
                f"({sorted(SUPPORTED_CANON_VERSIONS)}). "
                "Receipts claiming unrecognised canonicalisation versions must be rejected."
            ),
            field="canon_version",
        )

    # Step 5: JCS re-canonicalisation — re-canonicalise the payload dict and
    # compare against the raw bytes that were signed. Any whitespace, key-order,
    # or encoding divergence will produce a different byte sequence.
    try:
        import rfc8785  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "rfc8785 package is required for JCS re-canonicalisation. "
            "pip install rfc8785"
        ) from exc

    # Re-derive the raw payload bytes from the JWS token (before JSON-parsing)
    _, raw_payload_bytes, _ = decode_jws(jws_token)
    try:
        canonical_bytes = rfc8785.dumps(payload)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="NON_CANONICAL_PAYLOAD",
            message=f"RFC 8785 re-canonicalisation failed: {exc}",
        ) from exc

    if raw_payload_bytes != canonical_bytes:
        raise ReceiptVerificationError(
            code="NON_CANONICAL_PAYLOAD",
            message=(
                "Payload bytes do not match RFC 8785 JCS re-canonicalisation. "
                "The signature was computed over a non-canonical encoding. "
                f"Expected {len(canonical_bytes)} bytes, got {len(raw_payload_bytes)} bytes."
            ),
        )

    # Step 6: required fields
    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise ReceiptVerificationError(
                code="MISSING_FIELD",
                message=f"Required field {field!r} is absent from the receipt payload.",
                field=field,
            )

    # Step 7: screen_result enum
    screen_result = payload["screen_result"]
    if screen_result not in _SCREEN_RESULTS:
        raise ReceiptVerificationError(
            code="MISSING_FIELD",
            message=(
                f"screen_result {screen_result!r} is not one of "
                f"{sorted(_SCREEN_RESULTS)}. The categorical outcome is "
                "load-bearing for UK POCA s.330 SAR obligations."
            ),
            field="screen_result",
        )

    # Step 8: payment_hash binding
    if expected_payment_hash is not None:
        actual_hash = payload.get("payment_hash")
        if actual_hash != expected_payment_hash:
            raise ReceiptVerificationError(
                code="PAYMENT_HASH_MISMATCH",
                message=(
                    f"payment_hash in receipt ({actual_hash!r}) does not match "
                    f"expected ({expected_payment_hash!r}). "
                    "The receipt was signed over a different transaction."
                ),
                field="payment_hash",
            )

    return VerifiedReceipt(
        payer_ref=payload["payer_ref"],
        screen_result=screen_result,
        screen_timestamp_ms=payload["screen_timestamp_ms"],
        screen_provider_did=payload["screen_provider_did"],
        jurisdiction_flags=list(payload["jurisdiction_flags"]),
        canon_version=canon_version,
        alg=header.get("alg", ""),
        kid=header.get("kid"),
        raw_payload=payload,
    )
