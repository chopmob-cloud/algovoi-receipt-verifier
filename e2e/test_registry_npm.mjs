#!/usr/bin/env node
/**
 * E2E test: install @algovoi/receipt-verifier from npm in a temp dir
 * and run all 13 cross-validation vectors against it.
 *
 * Usage:
 *   node e2e/test_registry_npm.mjs
 *
 * Requires: node 18+, npm
 */

import { execSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO      = join(__dirname, '..');
const VECTORS   = join(REPO, 'vectors');
const PACKAGE   = '@algovoi/receipt-verifier@0.1.0';

const run = (cmd, cwd) => execSync(cmd, { cwd, stdio: 'pipe' }).toString();

console.log(`E2E: installing ${PACKAGE} from npm …`);

const tmp = mkdtempSync(join(tmpdir(), 'arv-e2e-'));
try {
  // Minimal package.json for ESM
  writeFileSync(join(tmp, 'package.json'),
    JSON.stringify({ name: 'e2e', version: '1.0.0', type: 'module', private: true }));

  run(`npm install ${PACKAGE} --save --prefer-online`, tmp);
  console.log(`  installed ${PACKAGE} OK`);

  // Write inline test script
  const testScript = join(tmp, 'run_vectors.mjs');
  writeFileSync(testScript, inlineTest(VECTORS));

  execSync(`node ${testScript}`, { stdio: 'inherit' });
  console.log('\nE2E PASS — all vectors verified from npm install');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

function inlineTest(vectorsDir) {
  return `
import { verifyComplianceReceipt, ReceiptVerificationError } from '@algovoi/receipt-verifier';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const VECTORS = ${JSON.stringify(vectorsDir)};
let passed = 0, failed = 0;

for (const file of readdirSync(join(VECTORS, 'valid')).filter(f => f.endsWith('.json')).sort()) {
  const v = JSON.parse(readFileSync(join(VECTORS, 'valid', file), 'utf8'));
  try {
    const r = verifyComplianceReceipt({ jws: v.jws, jwks: v.jwks, expectedPaymentHash: v.expected_payment_hash });
    if (r.screenResult !== v.expected_screen_result)
      throw new Error('wrong screenResult: ' + r.screenResult);
    console.log('  PASS valid/' + file);
    passed++;
  } catch (e) { console.log('  FAIL valid/' + file + ': ' + e.message); failed++; }
}

for (const file of readdirSync(join(VECTORS, 'invalid')).filter(f => f.endsWith('.json')).sort()) {
  const v = JSON.parse(readFileSync(join(VECTORS, 'invalid', file), 'utf8'));
  const expected = v.expected_error_codes ?? [v.expected_error_code];
  try {
    verifyComplianceReceipt({ jws: v.jws, jwks: v.jwks ?? { keys: [] },
      receiptRequired: v.receipt_required, expectedPaymentHash: v.expected_payment_hash });
    console.log('  FAIL invalid/' + file + ': expected ' + JSON.stringify(expected) + ' but passed');
    failed++;
  } catch (e) {
    if (e instanceof ReceiptVerificationError && expected.includes(e.code)) {
      console.log('  PASS invalid/' + file + ' (' + e.code + ')');
      passed++;
    } else {
      console.log('  FAIL invalid/' + file + ': expected ' + JSON.stringify(expected) + ', got ' + e.code);
      failed++;
    }
  }
}

console.log('\\n' + passed + '/' + (passed + failed) + ' vectors passed');
if (failed > 0) process.exit(1);
`;
}
