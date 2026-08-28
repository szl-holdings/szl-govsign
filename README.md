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

```python
from kernels import get_kernel
get_kernel("SZLHOLDINGS/szl-govsign", revision="main", trust_remote_code=True)
```

## Links

- Hub (publish mirror): https://huggingface.co/SZLHOLDINGS/szl-govsign
- Hologram space: https://huggingface.co/spaces/SZLHOLDINGS/govsign-live
