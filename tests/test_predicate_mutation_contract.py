# SPDX-License-Identifier: Apache-2.0
"""Constructor checks remain enforced when mutable predicate inputs are emitted."""
import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "torch-ext"))

import szl_govsign as gs


def predicate(**overrides):
    values = {
        "lambda_verdict": gs.LambdaVerdict(score=0.5),
        "energy": gs.EnergyLabel(value=1.0),
        "decision": gs.GovernanceDecision(status="ALLOWED"),
        "honest_blocked": False,
    }
    values.update(overrides)
    return gs.build_governance_predicate(**values)


@pytest.mark.parametrize("field,value", [
    ("label", "ESTIMATED"),
    ("label", "FABRICATED"),
    ("value", -1.0),
    ("value", float("nan")),
    ("value", float("inf")),
    ("value", True),
    ("value", "1"),
    ("value", 10 ** 1000),
])
def test_modified_energy_is_refused_at_both_emission_boundaries(field, value):
    energy = gs.EnergyLabel(value=1.0)
    setattr(energy, field, value)
    with pytest.raises(ValueError):
        energy.to_dict()
    with pytest.raises(ValueError):
        predicate(energy=energy)


@pytest.mark.parametrize("field,value", [
    ("basis", "PROVEN"), ("proven_trust", True), ("proven_trust", 0),
])
def test_advisory_fields_cannot_be_rewritten_before_emission(field, value):
    verdict = gs.LambdaVerdict(score=0.5)
    setattr(verdict, field, value)
    with pytest.raises(ValueError, match="fixed advisory"):
        verdict.to_dict()
    with pytest.raises(ValueError, match="fixed advisory"):
        predicate(lambda_verdict=verdict)


@pytest.mark.parametrize("status", ["UNKNOWN", "allowed", None, True])
def test_modified_decision_is_validated_before_emission(status):
    decision = gs.GovernanceDecision(status="ALLOWED")
    decision.status = status
    with pytest.raises(ValueError, match="decision status"):
        decision.to_dict()
    with pytest.raises(ValueError, match="decision status"):
        predicate(decision=decision)


def test_valid_mutations_preserve_honest_blocked_and_signable_results():
    energy = gs.EnergyLabel(value=1.0)
    energy.value = 2.5
    decision = gs.GovernanceDecision(status="ALLOWED")
    decision.status = "BLOCKED"
    decision.reason = "policy changed"
    verdict = gs.LambdaVerdict(score=0.5)
    verdict.score = 0.8
    verdict.notes = "still advisory"
    result = predicate(energy=energy, decision=decision, lambda_verdict=verdict)
    assert result["decision"]["status"] == "BLOCKED"
    assert result["honest_blocked"] is True
    assert result["energy"]["value"] == 2.5
    assert result["lambda_verdict"]["proven_trust"] is False
    key = gs.generate_ephemeral_keypair()
    envelope = gs.attest([gs.Subject("fixture", {"sha256": "a" * 64})], result, key)
    assert gs.verify(envelope, key.public_key()) is True
    assert json.loads(base64.b64decode(envelope["payload"]))["predicate"] == result


def test_valid_allowed_mutation_still_cannot_override_honest_blocked():
    decision = gs.GovernanceDecision(status="BLOCKED")
    decision.status = "ALLOWED"
    with pytest.raises(ValueError, match="honest_blocked=True"):
        predicate(decision=decision, honest_blocked=True)


def test_predicate_snapshot_does_not_change_after_later_valid_edits():
    energy = gs.EnergyLabel(value=1.0)
    decision = gs.GovernanceDecision(status="BLOCKED")
    verdict = gs.LambdaVerdict(score=0.5)
    result = predicate(energy=energy, decision=decision, lambda_verdict=verdict)
    energy.value = 20
    decision.status = "ALLOWED"
    verdict.score = 0.9
    assert result["energy"]["value"] == 1.0
    assert result["decision"]["status"] == "BLOCKED"
    assert result["lambda_verdict"]["score"] == 0.5
