/**
 * Compliance receipt verifier.
 *
 * Mirrors algovoi_receipt_verifier.receipt (Python) exactly — same 8 steps,
 * same error codes, same field names.
 *
 * Verification steps:
 *   1. JWS format — must be three-part base64url
 *   2. alg whitelist — EdDSA / ES256K / RS256 only
 *   3. Signature — cryptographic verification
 *   4. canon_version — must be in SUPPORTED_CANON_VERSIONS registry
 *   5. JCS re-canonicalisation — re-canonicalise payload; compare byte-for-byte
 *   6. Required fields — payer_ref, screen_result, screen_timestamp_ms,
 *                        screen_provider_did, jurisdiction_flags, canon_version
 *   7. screen_result enum — ALLOW / REFER / DENY
 *   8. payment_hash binding — if expectedPaymentHash supplied, must match
 */

import canonicalize from 'canonicalize';
import { ReceiptVerificationError } from './errors.js';
import {
  SUPPORTED_CANON_VERSIONS,
  type JwkSet,
  type Jwk,
  decodeJws,
  selectJwk,
  verifyJws,
} from './jws.js';

const REQUIRED_FIELDS = [
  'payer_ref',
  'screen_result',
  'screen_timestamp_ms',
  'screen_provider_did',
  'jurisdiction_flags',
  'canon_version',
] as const;

const SCREEN_RESULTS = new Set<string>(['ALLOW', 'REFER', 'DENY']);

// ── VerifiedReceipt ───────────────────────────────────────────────────────────

export interface VerifiedReceipt {
  /** Content-addressed payer identity (e.g. "sha256:<hex>"). */
  payerRef:            string;
  /** One of ALLOW, REFER, DENY. */
  screenResult:        string;
  /** Epoch-millisecond integer (Substrate Rule 1). */
  screenTimestampMs:   number;
  /** did:web of the screening provider. */
  screenProviderDid:   string;
  /** Ordered list of jurisdiction codes. */
  jurisdictionFlags:   string[];
  /** Canonicalisation version pinned in the receipt. */
  canonVersion:        string;
  /** JWS algorithm used (EdDSA / ES256K / RS256). */
  alg:                 string;
  /** JWS key ID from protected header, or undefined. */
  kid?:                string;
  /** The raw receipt dict from the verified JWS payload. */
  rawPayload:          Record<string, unknown>;
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface VerifyOptions {
  /** Compact JWS string. Pass undefined/null to trigger MISSING_ENVELOPE. */
  jws:                   string | null | undefined;
  /** Cryptography public key object (supply either this or jwks). */
  publicKey?:            Jwk;
  /** JWK Set (supply either this or publicKey). */
  jwks?:                 JwkSet;
  /** If supplied, receipt's payment_hash must equal this value. */
  expectedPaymentHash?:  string;
  /** If true and jws is absent, raise MISSING_ENVELOPE. */
  receiptRequired?:      boolean;
}

// ── Main ─────────────────────────────────────────────────────────────────────

/**
 * Verify a compact JWS compliance receipt and return a VerifiedReceipt.
 * Throws ReceiptVerificationError on any failure.
 */
export function verifyComplianceReceipt(opts: VerifyOptions): VerifiedReceipt {
  const { jws, publicKey, jwks, expectedPaymentHash, receiptRequired } = opts;

  // Step 0: missing envelope guard
  if (jws == null) {
    throw new ReceiptVerificationError({
      code: 'MISSING_ENVELOPE',
      message: receiptRequired
        ? 'receipt_required=true but no JWS receipt envelope was provided. ' +
          'A bare acknowledgement string is not sufficient proof of settlement.'
        : 'jws is null/undefined — no receipt to verify.',
    });
  }

  if (!publicKey && !jwks) {
    throw new Error('Supply either publicKey or jwks');
  }
  if (publicKey && jwks) {
    throw new Error('Supply either publicKey or jwks, not both');
  }

  // Resolve the JWK to use
  let resolvedJwk: Jwk;
  if (jwks) {
    const { header } = decodeJws(jws);
    const kid = typeof header['kid'] === 'string' ? header['kid'] : undefined;
    resolvedJwk = selectJwk(jwks, kid);
  } else {
    resolvedJwk = publicKey!;
  }

  // Steps 1–3: format, alg whitelist, signature
  const { header, payload } = verifyJws(jws, resolvedJwk);

  // Step 4: canon_version registry
  const canonVersion = String(payload['canon_version'] ?? '');
  if (!SUPPORTED_CANON_VERSIONS.has(canonVersion)) {
    throw new ReceiptVerificationError({
      code: 'UNSUPPORTED_CANON_VERSION',
      message:
        `canon_version ${JSON.stringify(canonVersion)} is not in the supported registry ` +
        `(${[...SUPPORTED_CANON_VERSIONS].join(', ')}). ` +
        'Receipts claiming unrecognised canonicalisation versions must be rejected.',
      field: 'canon_version',
    });
  }

  // Step 5: JCS re-canonicalisation — re-canonicalise the decoded payload dict
  // and compare byte-for-byte against the raw bytes from the JWS.
  const { rawPayload } = decodeJws(jws);
  const canonicalStr = canonicalize(payload);
  if (canonicalStr === undefined) {
    throw new ReceiptVerificationError({
      code: 'NON_CANONICAL_PAYLOAD',
      message: 'RFC 8785 canonicalize() returned undefined — payload cannot be canonicalised.',
    });
  }
  const canonicalBytes = Buffer.from(canonicalStr, 'utf8');
  if (!rawPayload.equals(canonicalBytes)) {
    throw new ReceiptVerificationError({
      code: 'NON_CANONICAL_PAYLOAD',
      message:
        'Payload bytes do not match RFC 8785 JCS re-canonicalisation. ' +
        'The signature was computed over a non-canonical encoding. ' +
        `Expected ${canonicalBytes.length} bytes, got ${rawPayload.length} bytes.`,
    });
  }

  // Step 6: required fields
  for (const field of REQUIRED_FIELDS) {
    if (!(field in payload)) {
      throw new ReceiptVerificationError({
        code: 'MISSING_FIELD',
        message: `Required field ${JSON.stringify(field)} is absent from the receipt payload.`,
        field,
      });
    }
  }

  // Step 7: screen_result enum
  const screenResult = String(payload['screen_result'] ?? '');
  if (!SCREEN_RESULTS.has(screenResult)) {
    throw new ReceiptVerificationError({
      code: 'MISSING_FIELD',
      message:
        `screen_result ${JSON.stringify(screenResult)} is not one of ` +
        `${[...SCREEN_RESULTS].sort().join(', ')}. The categorical outcome is ` +
        'load-bearing for UK POCA s.330 SAR obligations.',
      field: 'screen_result',
    });
  }

  // Step 8: payment_hash binding
  if (expectedPaymentHash !== undefined) {
    const actualHash = payload['payment_hash'] as string | undefined;
    if (actualHash !== expectedPaymentHash) {
      throw new ReceiptVerificationError({
        code: 'PAYMENT_HASH_MISMATCH',
        message:
          `payment_hash in receipt (${JSON.stringify(actualHash)}) does not match ` +
          `expected (${JSON.stringify(expectedPaymentHash)}). ` +
          'The receipt was signed over a different transaction.',
        field: 'payment_hash',
      });
    }
  }

  return {
    payerRef:          String(payload['payer_ref']),
    screenResult,
    screenTimestampMs: Number(payload['screen_timestamp_ms']),
    screenProviderDid: String(payload['screen_provider_did']),
    jurisdictionFlags: (payload['jurisdiction_flags'] as string[]),
    canonVersion,
    alg:               String(header['alg'] ?? ''),
    kid:               typeof header['kid'] === 'string' ? header['kid'] : undefined,
    rawPayload:        payload,
  };
}
