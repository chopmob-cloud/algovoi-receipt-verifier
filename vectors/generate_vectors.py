#!/usr/bin/env python3
"""
Generate cross-validation vectors for algovoi-receipt-verifier.

Produces:
  vectors/valid/   — known-good JWS receipts; all implementations must accept
  vectors/invalid/ — one fixture per error code; all implementations must reject

Run from the repo root:
    python vectors/generate_vectors.py

Requires: algovoi-receipt-verifier (pip install -e python/[test])
          cryptography rfc8785
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# ── ensure we can import the local package ───────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

import rfc8785
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VECTORS = Path(__file__).parent
VALID_DIR   = VECTORS / "valid"
INVALID_DIR = VECTORS / "invalid"
VALID_DIR.mkdir(exist_ok=True)
INVALID_DIR.mkdir(exist_ok=True)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jws(
    payload: dict,
    sk: ed25519.Ed25519PrivateKey,
    alg: str = "EdDSA",
    kid: str = "v0-key",
    canonical: bool = True,
) -> str:
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    h_b64 = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p_b64 = b64u(rfc8785.dumps(payload) if canonical else
                 json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = sk.sign(signing_input)
    return f"{h_b64}.{p_b64}.{b64u(sig)}"


def jwk_for(sk: ed25519.Ed25519PrivateKey, kid: str = "v0-key") -> dict:
    pk_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pk_raw), "kid": kid}


def base_receipt(
    screen_result: str = "ALLOW",
    canon_version: str = "jcs-rfc8785-v1",
    payment_hash: str = "sha256:deadbeef00000000000000000000000000000000000000000000000000000000",
) -> dict:
    return {
        "canon_version": canon_version,
        "jurisdiction_flags": ["UK", "EU"],
        "payer_ref": "sha256:aabbccdd",
        "payment_hash": payment_hash,
        "screen_provider_did": "did:web:api.algovoi.co.uk",
        "screen_result": screen_result,
        "screen_timestamp_ms": 1748649600000,
    }


def write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  wrote {path.relative_to(VECTORS)}")


# ── Deterministic key — same key across all vectors so JWKS is reusable ──────
# We generate a fresh key each run but embed the public JWK in every fixture,
# so implementations don't need a global JWKS — each fixture is self-contained.

sk = ed25519.Ed25519PrivateKey.generate()
jwk = jwk_for(sk)
jwks = {"keys": [jwk]}

print("Generating valid vectors …")

# v01 — ALLOW receipt
write(VALID_DIR / "v01_allow.json", {
    "description": "Valid ALLOW compliance receipt, EdDSA/Ed25519, jcs-rfc8785-v1.",
    "jws": make_jws(base_receipt("ALLOW"), sk),
    "jwks": jwks,
    "expected_screen_result": "ALLOW",
})

# v02 — REFER receipt
write(VALID_DIR / "v02_refer.json", {
    "description": "Valid REFER compliance receipt. REFER is load-bearing for UK POCA s.330 SAR obligations.",
    "jws": make_jws(base_receipt("REFER"), sk),
    "jwks": jwks,
    "expected_screen_result": "REFER",
})

# v03 — DENY receipt
write(VALID_DIR / "v03_deny.json", {
    "description": "Valid DENY compliance receipt.",
    "jws": make_jws(base_receipt("DENY"), sk),
    "jwks": jwks,
    "expected_screen_result": "DENY",
})

# v04 — payment_hash binding
KNOWN_HASH = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
write(VALID_DIR / "v04_payment_hash_binding.json", {
    "description": "Valid ALLOW receipt with payment_hash binding. "
                   "Verifier must accept when expected_payment_hash matches.",
    "jws": make_jws(base_receipt("ALLOW", payment_hash=KNOWN_HASH), sk),
    "jwks": jwks,
    "expected_payment_hash": KNOWN_HASH,
    "expected_screen_result": "ALLOW",
})

# v05 — minimal jurisdiction_flags (single jurisdiction)
minimal = base_receipt("ALLOW")
minimal["jurisdiction_flags"] = ["UK"]
write(VALID_DIR / "v05_single_jurisdiction.json", {
    "description": "Valid ALLOW receipt with a single jurisdiction flag.",
    "jws": make_jws(minimal, sk),
    "jwks": jwks,
    "expected_screen_result": "ALLOW",
})


print("Generating invalid vectors …")

# i01 — tampered signature (Phase 8: receipt-tampered-sig)
jws_ok = make_jws(base_receipt("ALLOW"), sk)
h, p, s = jws_ok.split(".")
sig_bytes = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
sig_bytes[32] ^= 0xFF
tampered_s = b64u(bytes(sig_bytes))
write(INVALID_DIR / "i01_tampered_signature.json", {
    "description": "Tampered Ed25519 signature — byte 32 flipped. "
                   "Phase 8 ATB threat: receipt-tampered-sig. "
                   "Verifier must reject with TAMPERED_SIGNATURE.",
    "jws": f"{h}.{p}.{tampered_s}",
    "jwks": jwks,
    "expected_error_code": "TAMPERED_SIGNATURE",
})

# i02 — unsupported alg (Phase 8: receipt-alg-unknown)
jws_bad_alg = make_jws(base_receipt("ALLOW"), sk, alg="HS512-CUSTOM")
write(INVALID_DIR / "i02_unsupported_alg.json", {
    "description": "JWS header declares alg=HS512-CUSTOM — not in the permitted list "
                   "(EdDSA, ES256K, RS256). Phase 8 ATB threat: receipt-alg-unknown. "
                   "Verifier must reject with UNSUPPORTED_ALG without attempting verification.",
    "jws": jws_bad_alg,
    "jwks": jwks,
    "expected_error_code": "UNSUPPORTED_ALG",
})

# i03 — unsupported canon_version (Phase 8: receipt-canon-version-mismatch)
write(INVALID_DIR / "i03_unsupported_canon_version.json", {
    "description": "canon_version claims 'jcs-rfc8785-v2' — a non-existent future version. "
                   "Phase 8 ATB threat: receipt-canon-version-mismatch. "
                   "Verifier must reject with UNSUPPORTED_CANON_VERSION.",
    "jws": make_jws(base_receipt(canon_version="jcs-rfc8785-v2"), sk),
    "jwks": jwks,
    "expected_error_code": "UNSUPPORTED_CANON_VERSION",
})

# i04 — payment_hash mismatch (Phase 8: receipt-replay-modified)
write(INVALID_DIR / "i04_payment_hash_mismatch.json", {
    "description": "Receipt was signed with payment_hash A; verifier checks for hash B. "
                   "Phase 8 ATB threat: receipt-replay-modified. "
                   "Verifier must reject with PAYMENT_HASH_MISMATCH.",
    "jws": make_jws(base_receipt(payment_hash="sha256:originalhash" + "0" * 44), sk),
    "jwks": jwks,
    "expected_payment_hash": "sha256:modifiedhash" + "0" * 44,
    "expected_error_code": "PAYMENT_HASH_MISMATCH",
})

# i05 — missing envelope (Phase 8: receipt-missing-envelope)
write(INVALID_DIR / "i05_missing_envelope.json", {
    "description": "jws field is null and receipt_required=true. "
                   "Phase 8 ATB threat: receipt-missing-envelope. "
                   "Verifier must reject with MISSING_ENVELOPE.",
    "jws": None,
    "jwks": jwks,
    "receipt_required": True,
    "expected_error_code": "MISSING_ENVELOPE",
})

# i06 — non-canonical payload (Phase 8: receipt-bad-jcs)
# Sign over insertion-order JSON where first key sorts last in RFC 8785
nc_payload: dict = {
    "zzz_not_in_schema": "x",   # sorts last in RFC 8785, first in insertion order
    "canon_version": "jcs-rfc8785-v1",
    "jurisdiction_flags": ["UK"],
    "payer_ref": "sha256:aabbccdd",
    "payment_hash": "sha256:x",
    "screen_provider_did": "did:web:api.algovoi.co.uk",
    "screen_result": "ALLOW",
    "screen_timestamp_ms": 1748649600000,
}
nc_jws = make_jws(nc_payload, sk, canonical=False)
write(INVALID_DIR / "i06_non_canonical_payload.json", {
    "description": "JWS payload is valid JSON but not RFC 8785 canonical — "
                   "key 'zzz_not_in_schema' appears first in insertion order "
                   "but sorts last under RFC 8785 §3.2.1 lexicographic ordering. "
                   "Phase 8 ATB threat: receipt-bad-jcs. "
                   "Verifier must detect that re-canonicalised bytes differ from "
                   "the signed bytes and reject with TAMPERED_SIGNATURE or NON_CANONICAL_PAYLOAD.",
    "jws": nc_jws,
    "jwks": jwks,
    "expected_error_codes": ["TAMPERED_SIGNATURE", "NON_CANONICAL_PAYLOAD"],
    "expected_error_code": "TAMPERED_SIGNATURE",  # primary; both are conformant
})

# i07 — malformed JWS (not 3 parts)
write(INVALID_DIR / "i07_malformed_jws.json", {
    "description": "JWS string has only two parts (missing signature segment). "
                   "Verifier must reject with INVALID_JWS_FORMAT.",
    "jws": "onlytwo.parts",
    "jwks": jwks,
    "expected_error_code": "INVALID_JWS_FORMAT",
})

# i08 — missing required field (screen_result absent)
missing_field = {k: v for k, v in base_receipt("ALLOW").items() if k != "screen_result"}
write(INVALID_DIR / "i08_missing_screen_result.json", {
    "description": "screen_result field is absent from the receipt payload. "
                   "Verifier must reject with MISSING_FIELD.",
    "jws": make_jws(missing_field, sk),
    "jwks": jwks,
    "expected_error_code": "MISSING_FIELD",
})

print("\nDone. Vectors written to vectors/valid/ and vectors/invalid/")
print(f"  {len(list(VALID_DIR.glob('*.json')))} valid, "
      f"{len(list(INVALID_DIR.glob('*.json')))} invalid")
