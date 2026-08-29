# SPDX-License-Identifier: Apache-2.0
"""CPU smoke: import szl_govsign and run selfcheck (sign / verify / tamper)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "torch-ext"))

import szl_govsign as gs


def test_selfcheck():
    report = gs.selfcheck(verbose=False)
    assert report["sign_ok"] is True
    assert report["verify_ok"] is True
    assert report["tamper_detected"] is True
    assert report["honest_blocked_signed_as_blocked"] is True
    assert report["all_passed"] is True


if __name__ == "__main__":
    test_selfcheck()
    print("OK — szl_govsign CPU smoke")
