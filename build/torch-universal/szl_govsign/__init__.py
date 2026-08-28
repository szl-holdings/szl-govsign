"""szl_govsign — Signed Governance Provenance layer for SZL Holdings.

Produces in-toto / DSSE-style signed governance attestations that bind:
  * artifact digest(s) (e.g. a szl_kernels UnifiedReceiptChain head, or a
    build/ file manifest sha256), AND
  * a GOVERNANCE PREDICATE carrying the Lambda advisory verdict, energy label,
    honest-BLOCKED status, and an allowed/blocked decision,
into a DSSE envelope signed with ECDSA P-256.

HONESTY DOCTRINE (binding):
  * The signature proves AUTHORSHIP + INTEGRITY of the attestation only.
  * It does NOT prove Lambda uniqueness (that remains Conjecture 1, advisory).
  * It does NOT upgrade an advisory verdict to "proven trust".
  * Energy is MEASURED-only; no fabricated benchmarks.
  * honest-BLOCKED: a blocked verdict is signed as BLOCKED, never flipped.

Prior art (attributed honestly):
  * in-toto attestation framework (predicate/subject statement shape).
  * DSSE — Dead Simple Signing Envelope (secure-systems-lab/dsse): PAE + envelope.
  * Sigstore / model-transparency: keyless signing model used in production.

Imports: stdlib + `cryptography` only. Python 3.9+ parseable.
"""
from .pae import pae, PAYLOAD_TYPE
from .predicate import (
    GOVERNANCE_PREDICATE_TYPE,
    EnergyLabel,
    LambdaVerdict,
    GovernanceDecision,
    build_governance_predicate,
)
from .envelope import (
    Subject,
    build_statement,
    attest,
    verify,
    generate_ephemeral_keypair,
    public_key_pem,
)
from .selfcheck import selfcheck

__all__ = [
    "pae",
    "PAYLOAD_TYPE",
    "GOVERNANCE_PREDICATE_TYPE",
    "EnergyLabel",
    "LambdaVerdict",
    "GovernanceDecision",
    "build_governance_predicate",
    "Subject",
    "build_statement",
    "attest",
    "verify",
    "generate_ephemeral_keypair",
    "public_key_pem",
    "selfcheck",
]

__version__ = "0.1.0"
