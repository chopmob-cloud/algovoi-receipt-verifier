"""
algovoi-receipt-verifier — cryptographic compliance receipt verifier.

Verifies AlgoVoi compact JWS compliance receipts emitted by
/compliance/screen and /verify endpoints.

Quick start::

    from algovoi_receipt_verifier import verify_compliance_receipt, ReceiptVerificationError

    try:
        receipt = verify_compliance_receipt(
            jws_token,
            jwks={"keys": [...]},              # from /.well-known/jwks.json
            expected_payment_hash="sha256:...", # optional binding check
        )
        print(receipt.screen_result)  # ALLOW / REFER / DENY
    except ReceiptVerificationError as e:
        print(e.code, e.message)      # TAMPERED_SIGNATURE / UNSUPPORTED_ALG / ...

Error codes::

    INVALID_JWS_FORMAT        malformed compact JWS
    UNSUPPORTED_ALG           alg not in {EdDSA, ES256K, RS256}
    TAMPERED_SIGNATURE        signature failed
    UNSUPPORTED_CANON_VERSION canon_version not in supported registry
    NON_CANONICAL_PAYLOAD     JCS re-canonicalisation mismatch
    MISSING_FIELD             required receipt field absent
    PAYMENT_HASH_MISMATCH     payment_hash doesn't match expected
    MISSING_ENVELOPE          jws_token is None and receipt_required=True
    INVALID_PAYLOAD           payload is not valid JSON post-decode
"""

from algovoi_receipt_verifier.errors import ERROR_CODES, ReceiptVerificationError
from algovoi_receipt_verifier.jws import (
    PERMITTED_ALGS,
    SUPPORTED_CANON_VERSIONS,
    decode_jws,
    public_key_from_jwk,
    verify_jws,
)
from algovoi_receipt_verifier.receipt import VerifiedReceipt, verify_compliance_receipt

__all__ = [
    # Primary API
    "verify_compliance_receipt",
    "VerifiedReceipt",
    "ReceiptVerificationError",
    # Lower-level JWS helpers
    "verify_jws",
    "decode_jws",
    "public_key_from_jwk",
    # Constants
    "PERMITTED_ALGS",
    "SUPPORTED_CANON_VERSIONS",
    "ERROR_CODES",
]

__version__ = "0.1.1"
