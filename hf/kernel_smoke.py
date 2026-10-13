# SPDX-License-Identifier: Apache-2.0
"""Smoke hook for hf-kernel-publish (szl-govsign).

`smoke(kernel)` receives the module that the `kernels` loader imported, from a local
build (check-local) or from the Hub (verify). Raise, or return False, to fail the run.

selfcheck() signs, verifies and tampers with a DSSE envelope, and since #19 it also
covers the fail-closed numeric contract from fix #7 (NaN/Infinity energy and payloads
are refused). A served package that predates #7 fails here, so a PASS proves the Hub
serves the fixed code, not just importable code.
"""
from __future__ import annotations

REQUIRED = (
    "sign_ok",
    "verify_ok",
    "tamper_detected",
    "honest_blocked_signed_as_blocked",
    "nonfinite_energy_refused",
    "nonfinite_payload_refused",
    "all_passed",
)


def smoke(kernel):
    report = kernel.selfcheck(verbose=False)
    failed = [key for key in REQUIRED if report.get(key) is not True]
    if failed:
        raise AssertionError(f"szl_govsign.selfcheck() failed: {failed}")
    return {key: report[key] for key in REQUIRED}
