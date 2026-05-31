/**
 * @algovoi/receipt-verifier
 *
 * Cryptographic verifier for AlgoVoi JWS compliance receipts.
 * TypeScript port — byte-for-byte parity with Python algovoi-receipt-verifier.
 *
 * Quick start:
 *
 *   import { verifyComplianceReceipt, ReceiptVerificationError } from '@algovoi/receipt-verifier';
 *
 *   try {
 *     const receipt = verifyComplianceReceipt({
 *       jws: token,
 *       jwks: { keys: [...] },          // from /.well-known/jwks.json
 *       expectedPaymentHash: 'sha256:...',
 *     });
 *     console.log(receipt.screenResult); // ALLOW / REFER / DENY
 *   } catch (e) {
 *     if (e instanceof ReceiptVerificationError) {
 *       console.error(e.code, e.message); // TAMPERED_SIGNATURE / ...
 *     }
 *   }
 */

export { ReceiptVerificationError, ERROR_CODES } from './errors.js';
export type { ErrorCode } from './errors.js';

export {
  decodeJws,
  verifyJws,
  selectJwk,
  PERMITTED_ALGS,
  SUPPORTED_CANON_VERSIONS,
  b64uDecode,
  b64uEncode,
} from './jws.js';
export type { DecodedJws, VerifyJwsResult, Jwk, JwkOkp, JwkEc, JwkRsa, JwkSet } from './jws.js';

export { verifyComplianceReceipt } from './receipt.js';
export type { VerifiedReceipt, VerifyOptions } from './receipt.js';
