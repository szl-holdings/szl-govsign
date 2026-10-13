---
license: apache-2.0
library_name: kernels
tags:
  - kernel
  - szl-holdings
  - signing
  - attestation
  - dsse
  - in-toto
  - governance
  - doi:10.5281/zenodo.19944926
---

# {{KERNEL_NAME}}: signed governance provenance

`szl-govsign` produces **in-toto / DSSE signed governance attestations**. Each one binds
an artifact digest (for example a `szl-kernels` `UnifiedReceiptChain` head, or a build
manifest) to a governance predicate (`https://szl.holdings/governance/v1`) carrying the
Lambda advisory verdict, MEASURED energy, honest-BLOCKED status and an allow/block
decision, signed with ECDSA P-256.

Pure-Python (noarch) kernel published from GitHub
[{{GITHUB_REPOSITORY}}](https://github.com/{{GITHUB_REPOSITORY}}) by its
`hf-kernel-publish` workflow. GitHub is the source of truth; this repository is
written only by that workflow.

## Load it

```bash
pip install "kernels>=0.17.2" torch cryptography
```

```python
from kernels import get_kernel

gs = get_kernel("{{REPO_ID}}", version={{KERNEL_VERSION}}, trust_remote_code=True)

report = gs.selfcheck(verbose=False)
assert report["all_passed"]  # sign, verify, tamper, honest-BLOCKED, non-finite refusal

priv = gs.generate_ephemeral_keypair()  # production: Sigstore keyless or a cosign key held out of band
pred = gs.build_governance_predicate(
    lambda_verdict=gs.LambdaVerdict(score=0.92, notes="advisory only"),
    energy=gs.EnergyLabel(value=12.5, unit="joules"),  # MEASURED-only, finite, non-negative
    decision=gs.GovernanceDecision(status="ALLOWED", reason="passed gates"),
    honest_blocked=False,
)
subjects = [gs.Subject(name="szl_kernels/UnifiedReceiptChain", digest={"sha256": "<64-hex digest>"})]
envelope = gs.attest(subjects, pred, priv)
assert gs.verify(envelope, priv.public_key())  # tampered or malformed envelopes verify False
```

- `version={{KERNEL_VERSION}}` resolves the `v{{KERNEL_VERSION}}` branch, the stable API channel. It is
  republished from GitHub by the workflow. The `kernels` library refuses a call that names
  neither a version nor a revision.
- `trust_remote_code` is required: SZLHOLDINGS is not a trusted kernel publisher on the Hub.
  The narrowest form is `trust_remote_code=["{{REPO_ID}}"]`.
- `cryptography` must be installed by the consumer. It is outside the `kernels` curated
  dependency set, so `metadata.json` cannot declare it.
- CPU hosts load `build/torch-cpu`; CUDA and other hosts load `build/torch-universal`.
  Both variants carry identical code, built from the same GitHub commit.

### Pin an exact build (production)

```python
from huggingface_hub import HfApi
from kernels import get_kernel

refs = HfApi().list_repo_refs("{{REPO_ID}}", repo_type="kernel")
pin = next(b.target_commit for b in refs.branches if b.name == "v{{KERNEL_VERSION}}")
gs = get_kernel("{{REPO_ID}}", revision=pin, trust_remote_code=["{{REPO_ID}}"])
```

Record `pin` (a commit of this kernel repository) in your lockfile.
`SZL_KERNEL_SOURCE.json` in this repository names the GitHub commit each build came from.
Commits of the model repository
[{{MODEL_TWIN_URL}}]({{MODEL_TWIN_URL}}) are not kernel revisions and do not resolve here.

## What it proves, and what it does not

- With a trusted public key, the signature proves possession of the corresponding private
  key and the integrity of the attestation (DSSE PAE + ECDSA P-256). It does not establish
  a real-world author identity by itself.
- It does **not** prove Lambda uniqueness, which remains **Conjecture 1 (open)**. The
  predicate's `proven_trust` field is fixed to `False`; no code path sets it.
- It does **not** upgrade an advisory verdict to proven trust.
- Energy is **MEASURED-only**, and NaN, infinite or negative values are refused at
  construction and at signing.
- **honest-BLOCKED**: a BLOCKED verdict is signed as BLOCKED, never flipped.

## API

| Symbol | What it does |
|---|---|
| `build_governance_predicate(...)` | Assemble the `https://szl.holdings/governance/v1` predicate. |
| `LambdaVerdict` / `EnergyLabel` / `GovernanceDecision` | Typed predicate parts: `proven_trust` fixed False, energy MEASURED-only, decision ALLOWED or BLOCKED. |
| `Subject`, `build_statement(...)` | in-toto v1 Statement (subjects + predicate). |
| `attest(subjects, predicate, private_key)` | Build and sign a DSSE envelope (ECDSA P-256, DSSE PAE). |
| `verify(envelope, public_key)` | Verify; fails closed (tampered or malformed gives False). |
| `generate_ephemeral_keypair()`, `public_key_pem(...)` | Demo keypair; no key material is written to disk. |
| `selfcheck()` | Signs, verifies, tampers, checks honest-BLOCKED and the non-finite refusals. |

Imports: Python standard library and `cryptography` only. Prior art: the
[in-toto attestation framework](https://github.com/in-toto/attestation),
[DSSE](https://github.com/secure-systems-lab/dsse) and
[Sigstore model-transparency](https://github.com/sigstore/model-transparency).
The `https://szl.holdings/governance/v1` predicate is SZL's own.

## Citation

Part of the SZL Holdings *Ouroboros Thesis*. Concept DOI (always the latest version):
[10.5281/zenodo.19944926](https://doi.org/10.5281/zenodo.19944926). Author: Stephen P. Lutar Jr.
([ORCID 0009-0001-0110-4173](https://orcid.org/0009-0001-0110-4173)).

## License

Apache-2.0. Copyright 2026 SZL Holdings.
