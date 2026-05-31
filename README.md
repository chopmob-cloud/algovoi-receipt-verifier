# algovoi-receipt-verifier

Cryptographic verifier for AlgoVoi JWS compliance receipts. Offline-capable — no AlgoVoi infrastructure trust required. Implementations in Python and TypeScript with 13 shared cross-validation vectors (5 valid, 8 invalid).

## What it verifies

Receipts emitted by `POST /compliance/screen` and `POST /verify` at `api.algovoi.co.uk` are compact JWS strings (`header.payload.signature`) signed with Ed25519. This verifier checks:

1. **JWS format** — must be three-part base64url
2. **Algorithm whitelist** — `EdDSA` / `ES256K` / `RS256` only; reject without fallback
3. **Signature** — cryptographic verification against the issuer's Ed25519 key
4. **`canon_version`** — must be in the supported registry (`jcs-rfc8785-v1`)
5. **JCS re-canonicalisation** — re-canonicalise payload via RFC 8785; compare byte-for-byte
6. **Required fields** — `payer_ref`, `screen_result`, `screen_timestamp_ms`, `screen_provider_did`, `jurisdiction_flags`, `canon_version`
7. **`screen_result` enum** — must be `ALLOW`, `REFER`, or `DENY`
8. **`payment_hash` binding** — if `expected_payment_hash` is supplied, must match exactly

Error codes map 1:1 to the Phase 8 [Agent Trust Bench](https://agent-trust-bench.algovoi.co.uk/) threat surface (OWASP LLM09).

## Python

```bash
pip install algovoi-receipt-verifier
```

```python
from algovoi_receipt_verifier import verify_compliance_receipt, ReceiptVerificationError

try:
    receipt = verify_compliance_receipt(
        jws_token,
        jwks={"keys": [...]},              # from /.well-known/jwks.json
        expected_payment_hash="sha256:...",
    )
    print(receipt.screen_result)  # ALLOW / REFER / DENY
except ReceiptVerificationError as e:
    print(e.code, e.message)
    # TAMPERED_SIGNATURE / UNSUPPORTED_ALG / UNSUPPORTED_CANON_VERSION /
    # NON_CANONICAL_PAYLOAD / PAYMENT_HASH_MISMATCH / MISSING_ENVELOPE /
    # MISSING_FIELD / INVALID_JWS_FORMAT / INVALID_PAYLOAD
```

## TypeScript / Node.js

```bash
npm install @algovoi/receipt-verifier
```

```typescript
import { verifyComplianceReceipt, ReceiptVerificationError } from '@algovoi/receipt-verifier';

try {
  const receipt = verifyComplianceReceipt({
    jws: token,
    jwks: { keys: [...] },
    expectedPaymentHash: 'sha256:...',
  });
  console.log(receipt.screenResult);
} catch (e) {
  if (e instanceof ReceiptVerificationError) {
    console.error(e.code, e.message);
  }
}
```

## JWKS endpoint

Fetch AlgoVoi's public key from:

```
GET https://api.algovoi.co.uk/.well-known/jwks.json
```

Pass the response body directly as `jwks`. The `kid` in the JWS header is used for key selection; falls back to the first key.

## Cross-validation vectors

`vectors/valid/` and `vectors/invalid/` contain 13 JSON fixtures run by both test suites. Regenerate with:

```bash
python vectors/generate_vectors.py
```

Each invalid fixture maps to a Phase 8 ATB threat:

| File | Threat | Expected error |
|---|---|---|
| `i01_tampered_signature.json` | receipt-tampered-sig | `TAMPERED_SIGNATURE` |
| `i02_unsupported_alg.json` | receipt-alg-unknown | `UNSUPPORTED_ALG` |
| `i03_unsupported_canon_version.json` | receipt-canon-version-mismatch | `UNSUPPORTED_CANON_VERSION` |
| `i04_payment_hash_mismatch.json` | receipt-replay-modified | `PAYMENT_HASH_MISMATCH` |
| `i05_missing_envelope.json` | receipt-missing-envelope | `MISSING_ENVELOPE` |
| `i06_non_canonical_payload.json` | receipt-bad-jcs | `TAMPERED_SIGNATURE` or `NON_CANONICAL_PAYLOAD` |
| `i07_malformed_jws.json` | — | `INVALID_JWS_FORMAT` |
| `i08_missing_screen_result.json` | — | `MISSING_FIELD` |

## Test results

| Implementation | Unit tests | Vector tests | Total |
|---|---|---|---|
| Python | 28/28 | 13/13 | **41/41** |
| TypeScript | 19/19 (incl. vectors) | — | **19/19** |

## Related

- [`algovoi-substrate`](https://github.com/chopmob-cloud/algovoi-substrate) — receipt builder + JCS canonicalisation
- [`algovoi-audit-verifier`](https://github.com/chopmob-cloud/algovoi-audit-verifier) — audit bundle verifier
- [Agent Trust Bench](https://agent-trust-bench.algovoi.co.uk/) — Phase 8 receipt/substrate-integrity profiles
- [AlgoVoi platform](https://api.algovoi.co.uk) — live gateway

## License

Apache-2.0 © AlgoVoi
