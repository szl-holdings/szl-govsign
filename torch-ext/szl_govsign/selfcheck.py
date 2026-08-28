"""selfcheck(): sign a sample governance attestation, verify it, then TAMPER
the payload and confirm verification FAILS.

Returns a dict report; prints human-readable lines if run as a script.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Dict, Any

from .predicate import (
    GOVERNANCE_PREDICATE_TYPE,
    EnergyLabel,
    LambdaVerdict,
    GovernanceDecision,
    build_governance_predicate,
)
from .envelope import (
    Subject,
    attest,
    verify,
    generate_ephemeral_keypair,
)


def _sample_subjects():
    """Two realistic subjects: a receipt-chain head + a build manifest sha256."""
    chain_head = hashlib.sha256(b"szl_kernels::UnifiedReceiptChain::head").hexdigest()
    manifest = hashlib.sha256(b"build/manifest.json contents").hexdigest()
    return [
        Subject(name="szl_kernels/UnifiedReceiptChain", digest={"sha256": chain_head}),
        Subject(name="build/manifest.json", digest={"sha256": manifest}),
    ]


def selfcheck(verbose: bool = True) -> Dict[str, Any]:
    report: Dict[str, Any] = {}

    # Ephemeral, in-process keypair (no key material on disk).
    priv = generate_ephemeral_keypair()
    pub = priv.public_key()

    # Build a sample ALLOWED governance predicate.
    predicate = build_governance_predicate(
        lambda_verdict=LambdaVerdict(score=0.92, notes="advisory only"),
        energy=EnergyLabel(value=12.5, unit="joules"),
        decision=GovernanceDecision(status="ALLOWED", reason="passed gates"),
        honest_blocked=False,
    )

    subjects = _sample_subjects()
    env = attest(subjects, predicate, priv, predicate_type=GOVERNANCE_PREDICATE_TYPE)

    sign_ok = isinstance(env, dict) and "signatures" in env and env["signatures"]
    report["sign_ok"] = bool(sign_ok)

    verify_ok = verify(env, pub)
    report["verify_ok"] = bool(verify_ok)

    # TAMPER: decode payload, flip ALLOWED -> BLOCKED, re-encode, keep old sig.
    tampered = copy.deepcopy(env)
    body = base64.b64decode(tampered["payload"])
    stmt = json.loads(body)
    stmt["predicate"]["decision"]["status"] = "BLOCKED"
    tampered_body = json.dumps(
        stmt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    tampered["payload"] = base64.b64encode(tampered_body).decode("ascii")

    tamper_detected = (verify(tampered, pub) is False)
    report["tamper_detected"] = bool(tamper_detected)

    # Honest-BLOCKED demonstration: a BLOCKED verdict signs as BLOCKED.
    blocked_pred = build_governance_predicate(
        lambda_verdict=LambdaVerdict(score=0.10, notes="advisory only"),
        energy=EnergyLabel(value=12.5, unit="joules"),
        decision=GovernanceDecision(status="BLOCKED", reason="policy violation"),
        honest_blocked=True,
    )
    blocked_env = attest(subjects, blocked_pred, priv, predicate_type=GOVERNANCE_PREDICATE_TYPE)
    blocked_stmt = json.loads(base64.b64decode(blocked_env["payload"]))
    blocked_status = blocked_stmt["predicate"]["decision"]["status"]
    report["honest_blocked_signed_as_blocked"] = (
        verify(blocked_env, pub) and blocked_status == "BLOCKED"
    )

    report["all_passed"] = all(
        [
            report["sign_ok"],
            report["verify_ok"],
            report["tamper_detected"],
            report["honest_blocked_signed_as_blocked"],
        ]
    )

    if verbose:
        print("=== szl_govsign selfcheck ===")
        print("sign OK:            %s" % report["sign_ok"])
        print("verify OK:          %s" % report["verify_ok"])
        print("tamper-detected:    %s" % report["tamper_detected"])
        print("honest-BLOCKED:     %s (signed status=%s)" % (
            report["honest_blocked_signed_as_blocked"], blocked_status))
        print("ALL PASSED:         %s" % report["all_passed"])

    return report


if __name__ == "__main__":
    selfcheck()
