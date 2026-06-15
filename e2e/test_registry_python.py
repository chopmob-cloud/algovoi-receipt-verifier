#!/usr/bin/env python3
"""
E2E test: install algovoi-receipt-verifier from PyPI into a clean venv
and run all 13 cross-validation vectors against it.

Usage:
    python e2e/test_registry_python.py

Requires: pip, python3.10+
Reads vectors from: vectors/valid/ and vectors/invalid/
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

REPO = Path(__file__).parent.parent
VECTORS = REPO / "vectors"
PACKAGE = "algovoi-receipt-verifier==0.1.1"


def run(cmd: list[str], cwd: Path | None = None, capture: bool = True) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True)
    if result.returncode != 0:
        print(f"FAIL: {' '.join(cmd)}")
        print(result.stderr)
        sys.exit(1)
    return result.stdout


def main() -> None:
    print(f"E2E: installing {PACKAGE} from PyPI …")

    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        venv_dir = Path(tmp) / "venv"

        # Create venv
        venv.create(str(venv_dir), with_pip=True, clear=True)
        pip = str(venv_dir / "Scripts" / "pip.exe") if sys.platform == "win32" \
              else str(venv_dir / "bin" / "pip")
        python = str(venv_dir / "Scripts" / "python.exe") if sys.platform == "win32" \
                 else str(venv_dir / "bin" / "python")

        run([pip, "install", PACKAGE, "--quiet"])
        print(f"  installed {PACKAGE} OK")

        # Write inline test script
        test_script = Path(tmp) / "run_vectors.py"
        test_script.write_text(_inline_test(VECTORS), encoding="utf-8")

        result = subprocess.run([python, str(test_script)], capture_output=False, text=True)
        if result.returncode != 0:
            print("E2E FAILED")
            sys.exit(1)

    print("\nE2E PASS — all vectors verified from PyPI install")


def _inline_test(vectors: Path) -> str:
    """Generate a self-contained test script to run inside the venv."""
    return f"""
import json, sys
from pathlib import Path
from algovoi_receipt_verifier import verify_compliance_receipt, ReceiptVerificationError

VECTORS = Path({str(vectors)!r})
passed = failed = 0

for p in sorted((VECTORS / "valid").glob("*.json")):
    v = json.loads(p.read_text())
    try:
        r = verify_compliance_receipt(v["jws"], jwks=v["jwks"],
            expected_payment_hash=v.get("expected_payment_hash"))
        assert r.screen_result == v["expected_screen_result"], \\
            f"{{p.name}}: expected {{v['expected_screen_result']!r}}, got {{r.screen_result!r}}"
        print(f"  PASS valid/{{p.name}}")
        passed += 1
    except Exception as e:
        print(f"  FAIL valid/{{p.name}}: {{e}}")
        failed += 1

for p in sorted((VECTORS / "invalid").glob("*.json")):
    v = json.loads(p.read_text())
    expected = v.get("expected_error_codes") or [v["expected_error_code"]]
    try:
        verify_compliance_receipt(v["jws"],
            jwks=v.get("jwks") or {{"keys": []}},
            receipt_required=v.get("receipt_required", False),
            expected_payment_hash=v.get("expected_payment_hash"))
        print(f"  FAIL invalid/{{p.name}}: expected error {{expected}} but passed")
        failed += 1
    except ReceiptVerificationError as e:
        if e.code in expected:
            print(f"  PASS invalid/{{p.name}} ({{e.code}})")
            passed += 1
        else:
            print(f"  FAIL invalid/{{p.name}}: expected {{expected}}, got {{e.code}}")
            failed += 1

print(f"\\n{{passed}}/{{passed+failed}} vectors passed")
sys.exit(0 if failed == 0 else 1)
"""


if __name__ == "__main__":
    main()
