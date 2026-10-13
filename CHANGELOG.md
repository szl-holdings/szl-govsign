# Changelog

## 2026-10-13

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
