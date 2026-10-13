# Changelog

## 2026-10-13

- Adopt the canonical kernel publish pipeline (`hf-kernel-publish.yml`,
  `scripts/szl_kernel_publish.py`, `.github/hf-kernels.json`, `hf/`). It builds
  `build/torch-cpu` and `build/torch-universal` from `torch-ext/szl_govsign` at the
  source commit, publishes them to the Kernel Hub repo's `main` and `v1` branches,
  verifies `get_kernel(version=1)` in a fresh anonymous job (including `selfcheck()`
  with the #7 non-finite refusals), then turns the model-type twin into a pointer card.
  This ships fix #7, which no Hub surface served, and adds the missing CUDA variant to `v1`.
- Retire the LICENSE-only publisher (`publish-kernel-license.yml`,
  `scripts/publish_kernel_license.py`, `hf-publication/license.json`), which preferred
  `HF_ORG_TOKEN`; LICENSE now comes from `license_file`. Retire the offline candidate
  builder (`scripts/build_kernel_candidate.py`), which produced the legacy root-shim
  layout, and the committed `build/` copy. Their tests go with them.
- `tests/test_hub_single_writer.py` allowlists the new writer and its detector now
  also recognises `run("push", ...)` Git transports.
- `selfcheck()` now covers the fail-closed numeric contract from fix #7. It
  reports `nonfinite_energy_refused` (EnergyLabel refuses NaN, +inf, -inf and
  -5.0) and `nonfinite_payload_refused` (attest() refuses a Statement with a NaN
  Lambda score), and both are part of `all_passed`. A published package that
  predates the fix now fails its own selfcheck instead of passing it.

## 2026-09-29

- Retire the one-shot Hub joblib quarantine writer (`hub-joblib-quarantine.yml`,
  `scripts/hub_quarantine_joblib.py`). The live Hub model and kernel repos hold no
  `model.joblib`, and the workflow was an unlocked Hub writer with an
  `HF_TOKEN || HF_ORG_TOKEN` fallback. The source-side refusal of joblib, pickle and
  dill loaders is unchanged. `tests/test_hub_single_writer.py` now fails if any file
  here gains a Hub write path outside a committed mirror.

## 2026-08-28

- Quarantine joblib/pickle: forge no longer dumps `model.joblib`; eval refuses the file; Hub deletion is a dispatched PR with exact parent commit.
