"""Structured error type for receipt verification failures."""

from __future__ import annotations

# Valid error codes — mirrors the Phase 8 ATB threat surface exactly.
ERROR_CODES = frozenset({
    "INVALID_JWS_FORMAT",        # not 3-part base64url or bad JSON header
    "UNSUPPORTED_ALG",           # alg not in {EdDSA, ES256K, RS256}
    "UNSUPPORTED_CANON_VERSION", # canon_version not in supported registry
    "TAMPERED_SIGNATURE",        # Ed25519/ES256K/RS256 verify() failed
    "PAYMENT_HASH_MISMATCH",     # payment_hash field doesn't match expected tx
    "MISSING_ENVELOPE",          # receipt_required=True but no JWS present
    "NON_CANONICAL_PAYLOAD",     # payload doesn't re-canonicalise to same bytes
    "INVALID_PAYLOAD",           # payload bytes are not valid JSON post-decode
    "MISSING_FIELD",             # required receipt field absent from payload
})


class ReceiptVerificationError(Exception):
    """Raised when a compliance receipt fails any verification step.

    Attributes:
        code:    One of ERROR_CODES — machine-readable failure category.
        message: Human-readable description of the failure.
        field:   Optional — the specific field that failed (for MISSING_FIELD,
                 NON_CANONICAL_PAYLOAD, etc.)
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        field: str | None = None,
    ) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"Unknown error code {code!r}. Valid: {sorted(ERROR_CODES)}")
        self.code = code
        self.message = message
        self.field = field
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict:
        d: dict = {"code": self.code, "message": self.message}
        if self.field is not None:
            d["field"] = self.field
        return d
