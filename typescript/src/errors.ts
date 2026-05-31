/**
 * Structured error type for receipt verification failures.
 * Mirrors algovoi_receipt_verifier.errors (Python) exactly.
 */

export const ERROR_CODES = [
  'INVALID_JWS_FORMAT',
  'UNSUPPORTED_ALG',
  'UNSUPPORTED_CANON_VERSION',
  'TAMPERED_SIGNATURE',
  'PAYMENT_HASH_MISMATCH',
  'MISSING_ENVELOPE',
  'NON_CANONICAL_PAYLOAD',
  'INVALID_PAYLOAD',
  'MISSING_FIELD',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export class ReceiptVerificationError extends Error {
  readonly code: ErrorCode;
  readonly field?: string;

  constructor(opts: { code: ErrorCode; message: string; field?: string }) {
    super(`[${opts.code}] ${opts.message}`);
    this.name = 'ReceiptVerificationError';
    this.code = opts.code;
    this.field = opts.field;
  }

  toJSON(): Record<string, unknown> {
    const r: Record<string, unknown> = { code: this.code, message: this.message };
    if (this.field !== undefined) r['field'] = this.field;
    return r;
  }
}
