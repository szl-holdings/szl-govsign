# SPDX-License-Identifier: Apache-2.0
"""CPU smoke: import szl_govsign and run selfcheck (sign / verify / tamper /
fail-closed numeric contract)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "torch-ext"))

import szl_govsign as gs
from szl_govsign import envelope as gs_envelope

# The package re-exports the selfcheck() function under the submodule's name,
# so take the module itself from sys.modules.
gs_selfcheck = sys.modules["szl_govsign.selfcheck"]

ROOT = Path(__file__).resolve().parents[1]


def test_selfcheck():
    report = gs.selfcheck(verbose=False)
    assert report["sign_ok"] is True
    assert report["verify_ok"] is True
    assert report["tamper_detected"] is True
    assert report["honest_blocked_signed_as_blocked"] is True
    assert report["nonfinite_energy_refused"] is True
    assert report["nonfinite_payload_refused"] is True
    assert report["all_passed"] is True


class _PreFixEnergyLabel(gs.EnergyLabel):
    """The pre-#7 Hub behaviour: label check only, no finite/non-negative guard."""

    def __post_init__(self) -> None:
        if self.label != "MEASURED":
            raise ValueError("energy label must be MEASURED-only")


def _pre_fix_canonical_json_bytes(obj):
    """The pre-#7 Hub behaviour: json.dumps without allow_nan=False."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def test_selfcheck_fails_against_pre_fix_numeric_behaviour(monkeypatch):
    # The selfcheck must be able to tell the published pre-fix code apart from
    # the fixed code; otherwise selfcheck()['all_passed'] proves nothing.
    monkeypatch.setattr(gs_selfcheck, "EnergyLabel", _PreFixEnergyLabel)
    report = gs.selfcheck(verbose=False)
    assert report["nonfinite_energy_refused"] is False
    assert report["all_passed"] is False

    monkeypatch.undo()
    monkeypatch.setattr(gs_envelope, "_canonical_json_bytes", _pre_fix_canonical_json_bytes)
    report = gs.selfcheck(verbose=False)
    assert report["nonfinite_energy_refused"] is True
    assert report["nonfinite_payload_refused"] is False
    assert report["all_passed"] is False


def test_no_committed_build_copy():
    # build/ is generated from torch-ext/ by scripts/szl_kernel_publish.py at the
    # source commit and exists only on the Kernel Hub. A committed copy here would
    # be a second, drifting source.
    tracked = subprocess.run(["git", "ls-files", "--", "build"], cwd=ROOT, check=True,
                             capture_output=True, text=True).stdout.split()
    assert tracked == []


if __name__ == "__main__":
    test_selfcheck()
    print("OK — szl_govsign CPU smoke")
