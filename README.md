# Canonical GitHub source for SZLHOLDINGS/szl-govsign

This repository is the **source of truth**. Hugging Face Kernel Hub is the **publish mirror**.

The Kernel Hub card is `hf/kernel-card.md`, published by the `hf-kernel-publish` workflow. Do not treat this README as a second model card.

<!-- szl:header v1 -->
<!-- Native identity: szl-brand@4309f6fce89179331b0b3ed8c99494e76c5be256; Orbit v2 icon. -->
<p>
  <a href="https://github.com/szl-holdings">
    <img src="https://raw.githubusercontent.com/szl-holdings/szl-brand/4309f6fce89179331b0b3ed8c99494e76c5be256/kit/logos/orbit-v2/suite/szl-icon-32.svg" alt="SZL Holdings — Orbit v2" width="32" height="32" />
  </a>
</p>

**Control before action. Evidence after.**

[Product](https://a-11-oy.com) · [Proof](https://a11oy.net) · [GitHub organization](https://github.com/szl-holdings)
<!-- /szl:header -->

## What it is / is NOT

- Hub `model.joblib` is **QUARANTINED** executable serialization. Do not `joblib.load` it. GitHub source is the approved path.

- **IS:** a software kernel — signed governance provenance (in-toto / DSSE attestations over SZL kernel receipts)
- **IS NOT:** trained weights
- **IS NOT:** a CUDA bench

Λ = Conjecture 1, never a theorem. Doctrine v11. Apache-2.0.

## Load

The Kernel Hub repository [`kernels/SZLHOLDINGS/szl-govsign`](https://huggingface.co/kernels/SZLHOLDINGS/szl-govsign)
is built from `torch-ext/szl_govsign/` in this repository and is written only by the
`hf-kernel-publish` workflow (see below).

```python
# pip install "kernels>=0.17.2" torch cryptography
from kernels import get_kernel

gs = get_kernel("SZLHOLDINGS/szl-govsign", version=1, trust_remote_code=True)
assert gs.selfcheck(verbose=False)["all_passed"]
```

- `version=1` resolves the `v1` branch of the kernel repository (the stable API channel).
  For production, pin the `v1` head commit of the **kernel** repository instead, with
  `revision=<40-hex kernel commit>`. The GitHub source commit, the model-type mirror
  commit and the Kernel Hub commit are separate identities; `SZL_KERNEL_SOURCE.json` on
  the Hub names the GitHub commit each build came from.
- `trust_remote_code=True` permits execution of the selected repository's Python
  (SZLHOLDINGS is not a trusted kernel publisher). The narrowest form is
  `trust_remote_code=["SZLHOLDINGS/szl-govsign"]`. Review the revision and its
  publication receipts before enabling it.
- `cryptography` is a runtime import. It is outside the `kernels` curated dependency
  set, so the kernel metadata cannot declare it; install it yourself.

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

## Kernel Hub publication

`.github/workflows/hf-kernel-publish.yml` with `scripts/szl_kernel_publish.py` is the
only committed Hub writer in this repository (`tests/test_hub_single_writer.py`
enforces that). Configuration lives in `.github/hf-kernels.json`; the kernel card is
`hf/kernel-card.md` and the smoke hook is `hf/kernel_smoke.py`.

- **Pull requests** build `build/torch-cpu` and `build/torch-universal` from Git objects
  (byte-identical, LF-normalised, with a generated `metadata.json` and sha256 digest) and
  load both with `kernels==0.17.2` and CPU torch. No Hub access, no secret.
- **Published releases** and **manual runs** from `main` (`source_ref`, optional
  `dry_run`) write the same tree to the kernel repo's `main` and `v1` branches with
  fast-forward Git pushes, read it back byte for byte, then verify anonymously in a
  fresh job that `get_kernel(version=1)` and `get_kernel(revision="main")` serve this
  source. Only then is the model-type twin turned into a pointer card.
- **Weekly**, a drift guard re-verifies what the Hub serves and fails if the latest
  release changed the kernel without being published.

`build/` is not committed here: it is generated at the source commit. The kernel major
(`version` in `.github/hf-kernels.json`) is independent of the package semver.

## Links

- Native Kernel Hub (publish mirror): https://huggingface.co/kernels/SZLHOLDINGS/szl-govsign
- Model-type twin (pointer to the kernel repo): https://huggingface.co/SZLHOLDINGS/szl-govsign
- Hologram space: https://huggingface.co/spaces/SZLHOLDINGS/govsign-live
