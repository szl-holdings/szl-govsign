# Canonical GitHub source for SZLHOLDINGS/szl-govsign

This repository is the **source of truth**. Hugging Face Kernel Hub is the **publish mirror**.

ATELIER owns Hub cards. Do not treat this README as a second model card.

## What it is / is NOT

- Hub `model.joblib` is **QUARANTINED** executable serialization. Do not `joblib.load` it. GitHub source is the approved path.

- **IS:** a software kernel — signed governance provenance (in-toto / DSSE attestations over SZL kernel receipts)
- **IS NOT:** trained weights
- **IS NOT:** a CUDA bench

Λ = Conjecture 1, never a theorem. Doctrine v11. Apache-2.0.

## Load

Set `SZL_GOVSIGN_HF_REVISION` to the immutable **first-class Kernel Hub** commit
from a verified publication of [`kernels/SZLHOLDINGS/szl-govsign`](https://huggingface.co/kernels/SZLHOLDINGS/szl-govsign). Use the `kernels`
client version qualified with that publication. The GitHub source commit,
model-type mirror commit, and Kernel Hub commit are separate identities.
An observed head, a branch name, or a successful import does not qualify a release.

`trust_remote_code=True` permits execution of the selected repository's Python.
Review that exact revision, its provenance and publication evidence before enabling it.
The format check below only rejects missing or mutable revision inputs; it does not
verify hashes, publisher authorization or compatibility. If that evidence is unavailable,
stop the Hub load and use separately reviewed local source for development.

```python
import os
import re

hf_revision = os.environ.get("SZL_GOVSIGN_HF_REVISION", "")
if re.fullmatch(r"[0-9a-f]{40}", hf_revision) is None:
    raise ValueError("A verified immutable Kernel Hub revision is required")

from kernels import get_kernel

get_kernel("SZLHOLDINGS/szl-govsign", revision=hf_revision, trust_remote_code=True)
```


## Source-only development

Review [`torch-ext/szl_govsign/`](https://github.com/szl-holdings/szl-govsign/tree/7bff004d12347ac23ae60ffbfb78ce7f9ef15829/torch-ext/szl_govsign)
at that immutable GitHub source revision, separately from any Hub release.
With the source's dependencies already available, run from the reviewed checkout root:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("torch-ext").resolve()))
import szl_govsign as local_kernel
```

This selects local Python source rather than calling the Hub loader. Importing local
source also executes Python. This documentation check does not run that import,
install dependencies, qualify a runtime or establish a Hub publication.
## Native kernel license publication

The source-owned `Native kernel license publication` workflow is the sole
committed writer for the native kernel. Its reviewed manifest permits appending
the canonical full Apache-2.0 terms to the existing `LICENSE` notice, preserving
the original notice bytes and every other Git blob and mode. PR and push events
run local contract checks without Hugging Face credentials. A manual run from
the current `main` tip defaults to a dry run; publication requires the exact
reviewed native parent and successful canonical CPU/CodeQL checks. The uploaded
receipt records immutable source and native commits. This license repair does
not qualify a kernel runtime or publish the model-type mirror.

## Links

- Native Kernel Hub (publish mirror): https://huggingface.co/kernels/SZLHOLDINGS/szl-govsign
- Model-type card mirror: https://huggingface.co/SZLHOLDINGS/szl-govsign
- Hologram space: https://huggingface.co/spaces/SZLHOLDINGS/govsign-live
