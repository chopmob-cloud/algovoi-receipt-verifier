# algovoi-receipt-verifier — offline-verifiable x402 agentic payment receipt

[![PyPI](https://img.shields.io/pypi/v/algovoi-receipt-verifier?label=PyPI)](https://pypi.org/project/algovoi-receipt-verifier/)
[![npm](https://img.shields.io/npm/v/@algovoi/receipt-verifier?label=npm)](https://www.npmjs.com/package/@algovoi/receipt-verifier)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)
[![Vectors](https://img.shields.io/badge/cross--validation-13%2F13-brightgreen)](https://github.com/chopmob-cloud/algovoi-receipt-verifier/tree/main/vectors)

Offline-verifiable x402 agentic payment receipt verifier. Re-derives the canonical bytes under JCS (RFC 8785), checks the Ed25519 signature, and validates `canon_version: jcs-rfc8785-v1` binding — all offline, with no AlgoVoi infrastructure trust required. Implementations in Python and TypeScript with 13 shared cross-validation vectors (5 valid, 8 invalid).

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

## Hosted endpoint

```bash
curl -X POST https://api.algovoi.co.uk/v1/receipt/verify \
  -H 'Content-Type: application/json' \
  -d '{"jws": "<compact-jws>", "expected_payment_hash": "sha256:<hex>"}'
```

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

| Implementation | Unit tests | Vector tests | E2E (from registry) | Total |
|---|---|---|---|---|
| Python | 28/28 | 13/13 | 13/13 | **41/41** |
| TypeScript | 19/19 (incl. vectors) | — | 13/13 | **19/19** |

E2E tests install from the live registries into a clean environment:

```bash
node e2e/test_registry_npm.mjs
python e2e/test_registry_python.py
```

## Application matrix

This package is part of the AlgoVoi open-source package suite. All packages share the same JCS canonicalisation substrate and Apache 2.0 licence.

| Package | Role | Relation |
|---|---|---|
| [`algovoi-substrate`](https://pypi.org/project/algovoi-substrate/) / [`@algovoi/substrate`](https://www.npmjs.com/package/@algovoi/substrate) | JCS canonicalisation + compliance receipt **emitter** | Builds the receipts this verifier checks; `canon_version` pin comes from here |
| [`algovoi-substrate-pqc`](https://pypi.org/project/algovoi-substrate-pqc/) / [`@algovoi/substrate-pqc`](https://www.npmjs.com/package/@algovoi/substrate-pqc) | PQC-aware additive layer over substrate | Future: ML-DSA-65 / hybrid signing of compliance receipts |
| [`algovoi-audit-verifier`](https://pypi.org/project/algovoi-audit-verifier/) / [`@algovoi/audit-verifier`](https://www.npmjs.com/package/@algovoi/audit-verifier) | Selective-disclosure audit bundle verifier | Receipt verification outcome is chained into the audit bundle |
| [`algovoi-settlement-attestation`](https://pypi.org/project/algovoi-settlement-attestation/) / [`@algovoi/settlement-attestation`](https://www.npmjs.com/package/@algovoi/settlement-attestation) | Multi-chain settlement record | Pairs with the compliance receipt in the payment lifecycle |
| [`algovoi-cancellation-receipt`](https://pypi.org/project/algovoi-cancellation-receipt/) / [`@algovoi/cancellation-receipt`](https://www.npmjs.com/package/@algovoi/cancellation-receipt) | Mandate cancellation receipt | Shares the same JCS substrate and `canon_version` discipline |
| [`algovoi-refund-receipt`](https://pypi.org/project/algovoi-refund-receipt/) / [`@algovoi/refund-receipt`](https://www.npmjs.com/package/@algovoi/refund-receipt) | Post-settlement refund receipt | Composes with compliance receipts in the audit chain |
| [`algovoi-composite-trust-query`](https://pypi.org/project/algovoi-composite-trust-query/) / [`@algovoi/composite-trust-query`](https://www.npmjs.com/package/@algovoi/composite-trust-query) | Top-of-stack verifier aggregator | Consumes receipt verification signals; emits `TRUSTED` / `PROVISIONAL` / `UNTRUSTED` |
| [`algovoi-rfc9421-verifier`](https://pypi.org/project/algovoi-rfc9421-verifier/) / [`@algovoi/rfc9421-verifier`](https://www.npmjs.com/package/@algovoi/rfc9421-verifier) | RFC 9421 HTTP message signature verifier | Verifies request signatures; receipt verifier covers the JWS receipt payload |
| [`algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors) | 53-vector JCS conformance corpus | The `jcs-rfc8785-v1` canon_version this verifier enforces is specified here |
| [`algovoi-mcp-server`](https://pypi.org/project/algovoi-mcp/) / [`@algovoi/mcp-server`](https://www.npmjs.com/package/@algovoi/mcp-server) | 28-tool MCP gateway server | `get_compliance_attestation` and `screen_recipient` tools emit receipts verified by this package |

Full package suite documentation: [docs.algovoi.co.uk/package-suite](https://docs.algovoi.co.uk/package-suite)

## Related

- [`algovoi-substrate`](https://github.com/chopmob-cloud/algovoi-substrate) — receipt builder + JCS canonicalisation
- [`algovoi-audit-verifier`](https://github.com/chopmob-cloud/algovoi-audit-verifier) — audit bundle verifier
- [Agent Trust Bench](https://agent-trust-bench.algovoi.co.uk/) — Phase 8 receipt/substrate-integrity profiles
- [AlgoVoi platform](https://api.algovoi.co.uk) — live gateway
- [Docs](https://docs.algovoi.co.uk/receipt-verifier) — full documentation

## License

Apache-2.0 © AlgoVoi
## Attribution

This package is Apache-2.0. Use it freely and build whatever you are building on top of it. The only ask is the one the licence already makes: keep the NOTICE, and name who authored the substrate. To attribute it in your own product, add this to your NOTICE file:

```
This product includes the AlgoVoi substrate,
authored by Christopher Hopley / AlgoVoi (chopmob-cloud), Apache-2.0.
https://docs.algovoi.co.uk/canonicalisation-substrate
```

The full invitation is at https://docs.algovoi.co.uk/canonicalisation-substrate#adopt-the-substrate

## Related

- [AlgoVoi substrate hub](https://chopmob-cloud.github.io/): the open JCS (RFC 8785) canonicalisation substrate for agentic payments
- [Canonicalisation substrate docs](https://docs.algovoi.co.uk/canonicalisation-substrate)
- [Agentic payment receipts](https://docs.algovoi.co.uk/agentic-payment-receipts): verifiable receipts across x402, AP2, A2A and MPP
