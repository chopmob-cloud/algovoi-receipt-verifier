/**
 * JWS compact-serialisation decoder and verifier.
 *
 * Supports EdDSA (Ed25519), ES256K, and RS256 — the three algorithms in
 * the x402 compliance-receipt permitted-algorithm list.
 *
 * Uses Node.js built-in `crypto` — no extra runtime dependencies beyond
 * the `canonicalize` package used for RFC 8785 JCS checks.
 *
 * Mirrors algovoi_receipt_verifier.jws (Python) exactly.
 */

import { createPublicKey, createVerify, verify as cryptoVerify } from 'node:crypto';
import { ReceiptVerificationError } from './errors.js';

export const PERMITTED_ALGS = new Set<string>(['EdDSA', 'ES256K', 'RS256']);
export const SUPPORTED_CANON_VERSIONS = new Set<string>(['jcs-rfc8785-v1']);

// ── Base64url helpers ────────────────────────────────────────────────────────

export function b64uDecode(s: string): Buffer {
  const pad = '='.repeat((-s.length) & 3);
  return Buffer.from(s + pad, 'base64url');
}

export function b64uEncode(b: Buffer | Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

// ── JWK types ────────────────────────────────────────────────────────────────

export interface JwkOkp  { kty: 'OKP'; crv: string; x: string; kid?: string; alg?: string; use?: string }
export interface JwkEc   { kty: 'EC';  crv: string; x: string; y: string; kid?: string }
export interface JwkRsa  { kty: 'RSA'; n: string; e: string; kid?: string }
export type Jwk = JwkOkp | JwkEc | JwkRsa;
export interface JwkSet  { keys: Jwk[] }

// ── Decode ───────────────────────────────────────────────────────────────────

export interface DecodedJws {
  headerB64:   string;
  payloadB64:  string;
  header:      Record<string, unknown>;
  rawPayload:  Buffer;
  signature:   Buffer;
}

/** Decode a compact JWS string. Does NOT verify the signature. */
export function decodeJws(token: string): DecodedJws {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new ReceiptVerificationError({
      code: 'INVALID_JWS_FORMAT',
      message: `Expected 3-part compact JWS, got ${parts.length} parts`,
    });
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(b64uDecode(headerB64).toString('utf8')) as Record<string, unknown>;
  } catch (e) {
    throw new ReceiptVerificationError({
      code: 'INVALID_JWS_FORMAT',
      message: `JWS protected header is not valid JSON: ${String(e)}`,
    });
  }

  const rawPayload = b64uDecode(payloadB64);
  const signature  = b64uDecode(sigB64);

  return { headerB64, payloadB64, header, rawPayload, signature };
}

// ── Verify ───────────────────────────────────────────────────────────────────

export interface VerifyJwsResult {
  header:  Record<string, unknown>;
  payload: Record<string, unknown>;
}

/** Verify a compact JWS and return { header, payload }. */
export function verifyJws(token: string, jwk: Jwk): VerifyJwsResult {
  const { headerB64, payloadB64, header, rawPayload, signature } = decodeJws(token);

  const alg = String(header['alg'] ?? '');
  if (!PERMITTED_ALGS.has(alg)) {
    throw new ReceiptVerificationError({
      code: 'UNSUPPORTED_ALG',
      message:
        `Algorithm ${JSON.stringify(alg)} is not in the permitted list ` +
        `(${[...PERMITTED_ALGS].sort().join(', ')}). Reject without fallback.`,
    });
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  let ok = false;

  try {
    if (jwk.kty === 'OKP' && alg === 'EdDSA') {
      if (jwk.crv !== 'Ed25519') {
        throw new ReceiptVerificationError({
          code: 'UNSUPPORTED_ALG',
          message: `OKP curve ${jwk.crv} is not supported (expected Ed25519)`,
        });
      }
      const pubKeyRaw = b64uDecode(jwk.x);
      // Wrap raw 32-byte key in SubjectPublicKeyInfo DER for Node crypto
      const spki  = buildEd25519Spki(pubKeyRaw);
      const keyObj = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      // Ed25519 uses null hash — cryptoVerify handles internally
      ok = cryptoVerify(null, signingInput, keyObj, signature);

    } else if (jwk.kty === 'EC' && alg === 'ES256K') {
      if (jwk.crv !== 'secp256k1') {
        throw new ReceiptVerificationError({
          code: 'UNSUPPORTED_ALG',
          message: `EC curve ${jwk.crv} is not supported for ES256K (expected secp256k1)`,
        });
      }
      const keyObj = createPublicKey({ key: jwk as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
      ok = createVerify('SHA256').update(signingInput).verify(keyObj, signature);

    } else if (jwk.kty === 'RSA' && alg === 'RS256') {
      const keyObj = createPublicKey({ key: jwk as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
      ok = createVerify('SHA256').update(signingInput).verify(keyObj, signature);

    } else {
      throw new ReceiptVerificationError({
        code: 'UNSUPPORTED_ALG',
        message: `Algorithm ${alg} is not compatible with key type ${jwk.kty}`,
      });
    }
  } catch (e) {
    if (e instanceof ReceiptVerificationError) throw e;
    // Crypto errors (bad key material, wrong sig length, etc.)
    throw new ReceiptVerificationError({
      code: 'TAMPERED_SIGNATURE',
      message: `JWS signature verification failed — receipt has been tampered. (${String(e)})`,
    });
  }

  if (!ok) {
    throw new ReceiptVerificationError({
      code: 'TAMPERED_SIGNATURE',
      message: 'JWS signature verification failed — receipt has been tampered.',
    });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawPayload.toString('utf8')) as Record<string, unknown>;
  } catch (e) {
    throw new ReceiptVerificationError({
      code: 'INVALID_PAYLOAD',
      message: `JWS payload is not valid JSON after signature verification: ${String(e)}`,
    });
  }

  return { header, payload };
}

// ── Ed25519 SPKI DER builder ─────────────────────────────────────────────────

/**
 * Wrap a 32-byte Ed25519 raw public key in SubjectPublicKeyInfo DER.
 *
 * Structure:
 *   SEQUENCE {
 *     SEQUENCE { OID 1.3.101.112 }   -- Ed25519 OID
 *     BIT STRING { 0x00 || rawKey }  -- 0x00 = no unused bits
 *   }
 */
function buildEd25519Spki(raw: Buffer): Buffer {
  // OID 1.3.101.112 encoded: 06 03 2b 65 70
  const oidBytes  = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
  // AlgorithmIdentifier SEQUENCE
  const algoId    = Buffer.concat([Buffer.from([0x30, oidBytes.length]), oidBytes]);
  // BIT STRING: tag 0x03, length 33 (1 unused-bits byte + 32 key bytes), 0x00
  const bitString = Buffer.concat([Buffer.from([0x03, 0x21, 0x00]), raw]);
  // Outer SEQUENCE
  const inner     = Buffer.concat([algoId, bitString]);
  const outerLen  = inner.length;
  const lenBuf    = outerLen < 0x80
    ? Buffer.from([outerLen])
    : Buffer.from([0x81, outerLen]);
  return Buffer.concat([Buffer.from([0x30]), lenBuf, inner]);
}

// ── JWKS key selection ───────────────────────────────────────────────────────

/** Select the JWK matching kid from the JWS header; fall back to first key. */
export function selectJwk(jwks: JwkSet, kid?: string): Jwk {
  const { keys } = jwks;
  if (!keys?.length) {
    throw new ReceiptVerificationError({
      code: 'INVALID_JWS_FORMAT',
      message: 'JWKS contains no keys',
    });
  }
  if (kid) {
    const match = keys.find((k) => k.kid === kid);
    if (match) return match;
  }
  return keys[0]!;
}
