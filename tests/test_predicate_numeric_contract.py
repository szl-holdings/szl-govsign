# SPDX-License-Identifier: Apache-2.0
"""Fail-closed numeric contracts for signed governance predicates."""
from __future__ import annotations

import math
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "torch-ext"))

import szl_govsign as gs


@pytest.mark.parametrize(
    "value",
    [
        -0.001,
        float("nan"),
        float("inf"),
        float("-inf"),
        True,
        "12.5",
    ],
)
def test_measured_energy_rejects_nonfinite_negative_and_non_numeric_values(value):
    with pytest.raises(ValueError, match="finite non-negative"):
        gs.EnergyLabel(value=value, unit="joules")


def test_zero_and_positive_measured_energy_remain_valid():
    assert gs.EnergyLabel(value=0.0).to_dict()["value"] == 0.0
    assert gs.EnergyLabel(value=12.5).to_dict()["value"] == 12.5


def test_attest_rejects_nonfinite_values_elsewhere_in_signed_statement():
    subjects = [gs.Subject(name="artifact", digest={"sha256": "a" * 64})]
    predicate = gs.build_governance_predicate(
        lambda_verdict=gs.LambdaVerdict(score=math.nan, notes="advisory only"),
        energy=gs.EnergyLabel(value=1.0, unit="joules"),
        decision=gs.GovernanceDecision(status="ALLOWED", reason="passed gates"),
        honest_blocked=False,
    )

    with pytest.raises(ValueError, match="JSON compliant"):
        gs.attest(subjects, predicate, gs.generate_ephemeral_keypair())
