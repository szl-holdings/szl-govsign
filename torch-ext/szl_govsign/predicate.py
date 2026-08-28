"""Governance predicate for the SZL signed-attestation layer.

The predicate is carried inside an in-toto Statement under a custom
predicateType. It encodes the governance verdict that gates a kernel build
or a forward-pass receipt chain.

HONESTY DOCTRINE is enforced structurally here:
  * `lambda_verdict.basis` is fixed to "Conjecture-1-advisory" and the field
    `proven_trust` is hard-coded False — there is no code path that sets it
    True. The signature never upgrades advisory -> proven.
  * `energy.label` may only be "MEASURED" (no MODELED / ESTIMATED / FABRICATED).
  * `decision.status` honestly records BLOCKED when blocked; a blocked input
    is never silently flipped to ALLOWED (see build_governance_predicate).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

GOVERNANCE_PREDICATE_TYPE = "https://szl.holdings/governance/v1"

# Allowed enumerations -----------------------------------------------------
_ALLOWED_ENERGY_LABELS = ("MEASURED",)  # MEASURED-only doctrine
_ALLOWED_DECISIONS = ("ALLOWED", "BLOCKED")
_LAMBDA_BASIS = "Conjecture-1-advisory"  # never "proven"


@dataclass
class EnergyLabel:
    """A MEASURED-only energy claim.

    `joules` (or any unit) must be an actually-measured quantity. We do not
    permit modeled/estimated/fabricated labels — `label` is constrained.
    """

    value: float
    unit: str = "joules"
    label: str = "MEASURED"
    method: str = "direct-measurement"

    def __post_init__(self) -> None:
        if self.label not in _ALLOWED_ENERGY_LABELS:
            raise ValueError(
                "energy label must be MEASURED-only (got %r); "
                "modeled/estimated/fabricated energy is forbidden by doctrine"
                % (self.label,)
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "unit": self.unit,
            "label": self.label,
            "method": self.method,
        }


@dataclass
class LambdaVerdict:
    """The Lambda advisory verdict.

    `basis` is locked to Conjecture-1-advisory and `proven_trust` is locked
    False. There is intentionally no constructor argument to set proven_trust
    True — uniqueness of Lambda remains Conjecture 1 and is NOT proven by a
    signature.
    """

    score: float
    notes: str = ""
    basis: str = field(default=_LAMBDA_BASIS, init=False)
    proven_trust: bool = field(default=False, init=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "notes": self.notes,
            "basis": self.basis,
            "proven_trust": self.proven_trust,
            "advisory": True,
            "disclaimer": (
                "Lambda verdict is ADVISORY ONLY. Uniqueness of Lambda is "
                "Conjecture 1 and is NOT proven. The DSSE signature attests "
                "authorship+integrity of this attestation, not Lambda "
                "uniqueness and not 'proven trust'."
            ),
        }


@dataclass
class GovernanceDecision:
    """Allowed/blocked gate decision with honest-BLOCKED semantics."""

    status: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status not in _ALLOWED_DECISIONS:
            raise ValueError(
                "decision status must be one of %r (got %r)"
                % (_ALLOWED_DECISIONS, self.status)
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason}


def build_governance_predicate(
    lambda_verdict: LambdaVerdict,
    energy: EnergyLabel,
    decision: GovernanceDecision,
    honest_blocked: bool,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the governance predicate body.

    honest-BLOCKED enforcement: if `honest_blocked` is True OR the decision is
    BLOCKED, the resulting predicate's decision status is pinned to BLOCKED.
    A blocked verdict can never be silently flipped to ALLOWED here.
    """
    status = decision.status
    if honest_blocked and status != "BLOCKED":
        # honest-BLOCKED: never flip a blocked verdict to allowed.
        raise ValueError(
            "honest_blocked=True but decision.status != BLOCKED — refusing to "
            "sign a flipped verdict (honest-BLOCKED doctrine)."
        )

    predicate: Dict[str, Any] = {
        "schemaVersion": "v1",
        "producer": "szl_govsign",
        "lambda_verdict": lambda_verdict.to_dict(),
        "energy": energy.to_dict(),
        "decision": decision.to_dict(),
        "honest_blocked": bool(honest_blocked or status == "BLOCKED"),
        "doctrine": {
            "signature_proves": [
                "authorship_of_attestation",
                "integrity_of_attestation",
            ],
            "signature_does_not_prove": [
                "lambda_uniqueness (remains Conjecture 1)",
                "proven_trust (advisory verdict is not upgraded)",
            ],
            "energy_policy": "MEASURED-only",
        },
    }
    if extra:
        # extra metadata is allowed but cannot override doctrine keys.
        reserved = set(predicate.keys())
        for k, v in extra.items():
            if k in reserved:
                raise ValueError("extra key %r collides with reserved key" % k)
            predicate[k] = v
    return predicate
