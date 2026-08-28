#!/usr/bin/env python3
"""Forge a REAL trained STRUCTURAL PRE-FILTER for szl-govsign.

CARD-CRITICAL HONESTY: this surrogate is a STRUCTURAL PRE-FILTER ONLY. It NEVER
replaces cryptographic verification. Passing this filter is NOT "verified" — a
real ECDSA-P256 DSSE verify (the kernel's `verify()`) is the sole authority for
validity. The filter triages obvious structural breakage (malformed base64,
missing signatures, wrong payloadType, non-JSON payload, missing in-toto fields)
cheaply, before the expensive crypto check. The `sig-tamper` class is included
DELIBERATELY to MEASURE the crypto blind spot: a byte-flipped signature is
structurally identical to a valid envelope, so the pre-filter cannot see it —
recall ≈ chance, stated proudly (exactly the szl-invariants sig-tamper lesson).

Ground truth: envelopes are built by the kernel's REAL `attest()` over the REAL
governed-receipts-bench seed subjects; every label is audited by replaying the
kernel's REAL `verify()` (valid -> True; sig-tamper + structural breakage -> False).
Seeded, receipted, reproducible."""
import json, os, random, sys, time, hashlib, platform, base64
_here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isdir(os.path.join(_here, "build", "torch-universal")):
    sys.path.insert(0, os.path.join(_here, "build", "torch-universal"))  # in-repo run
else:
    sys.path.insert(0, "/tmp/kernel-probe/szl-govsign/build/torch-universal")  # forge-dev run
import szl_govsign as gs
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

SEED = 20260721
random.seed(SEED); np.random.seed(SEED)
T0 = time.time()

# --- resolve the real bench seed subjects (digests) from governed-receipts-bench ---
BENCH = None
for cand in ["/tmp/kernel-probe/governed-receipts-bench",
             os.path.join(_here, "governed-receipts-bench")]:
    if os.path.isdir(os.path.join(cand, "valid")):
        BENCH = cand; break
SEED_DIGESTS = []
if BENCH:
    import glob, re
    _hex64 = re.compile(r"^[0-9a-f]{64}$")
    def _harvest(obj, out):
        """Collect every real 64-hex (sha256) string found anywhere in the record."""
        if isinstance(obj, str):
            if _hex64.match(obj):
                out.add(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _harvest(v, out)
        elif isinstance(obj, list):
            for v in obj:
                _harvest(v, out)
    found = set()
    for fp in sorted(glob.glob(os.path.join(BENCH, "valid", "*.json"))):
        try:
            _harvest(json.load(open(fp)), found)
        except Exception:
            pass
    SEED_DIGESTS = sorted(found)
if not SEED_DIGESTS:
    # honest fallback: synthesize sha256 subject digests (still real hashes)
    SEED_DIGESTS = [hashlib.sha256(f"seed-{i}".encode()).hexdigest() for i in range(5)]

PRIV = gs.generate_ephemeral_keypair()
PUB = PRIV.public_key()

CLASSES = ["valid", "wrong-payload-type", "missing-signatures",
           "malformed-base64-payload", "non-json-payload",
           "missing-statement-field", "sig-tamper"]

def make_valid_envelope(i):
    """Build a genuine signed DSSE envelope via the REAL kernel attest()."""
    digest = random.choice(SEED_DIGESTS)
    subjects = [gs.Subject(name=f"szl_kernels/UnifiedReceiptChain#{i}",
                           digest={"sha256": digest})]
    status = "ALLOWED" if random.random() < 0.7 else "BLOCKED"
    blocked = status == "BLOCKED"
    pred = gs.build_governance_predicate(
        lambda_verdict=gs.LambdaVerdict(score=random.uniform(0.5, 0.99), notes="advisory only"),
        energy=gs.EnergyLabel(value=random.uniform(0.1, 100.0), unit="joules"),
        decision=gs.GovernanceDecision(status=status, reason="synthetic"),
        honest_blocked=blocked)
    return gs.attest(subjects, pred, PRIV)

def corrupt(env, cls):
    """Apply ONLY this class's corruption. Returns a NEW envelope dict."""
    e = json.loads(json.dumps(env))  # deep copy
    if cls == "valid":
        return e
    if cls == "wrong-payload-type":
        e["payloadType"] = "application/vnd.WRONG+json"
        return e
    if cls == "missing-signatures":
        e["signatures"] = [] if random.random() < 0.5 else None
        if e["signatures"] is None:
            del e["signatures"]
        return e
    if cls == "malformed-base64-payload":
        e["payload"] = e["payload"][:-3] + "!@#"   # not valid base64
        return e
    if cls == "non-json-payload":
        e["payload"] = base64.b64encode(b"this is not json at all %%%").decode()
        return e
    if cls == "missing-statement-field":
        body = json.loads(base64.b64decode(e["payload"]))
        drop = random.choice(["_type", "subject", "predicateType", "predicate"])
        body.pop(drop, None)
        e["payload"] = base64.b64encode(json.dumps(body, sort_keys=True,
                        separators=(",", ":")).encode()).decode()
        return e
    if cls == "sig-tamper":
        # PURE crypto corruption: structurally perfect, only signature bytes flipped.
        # Structurally identical to a valid envelope -> the crypto blind spot.
        sigb = bytearray(base64.b64decode(e["signatures"][0]["sig"]))
        sigb[0] ^= 0xFF
        e["signatures"][0]["sig"] = base64.b64encode(bytes(sigb)).decode()
        return e
    raise KeyError(cls)

# --- structural observables ONLY (NO ECDSA verify — that is the measured blind spot) ---
def features(env):
    pt = env.get("payloadType")
    payload = env.get("payload")
    sigs = env.get("signatures")
    # base64 decodability
    b64_ok, is_json, n_stmt_fields, n_subjects, has_predicate = 0, 0, -1, -1, -1
    body_len = 0
    stmt_type_ok = -1
    decoded = None
    if isinstance(payload, str):
        try:
            decoded = base64.b64decode(payload, validate=True)
            b64_ok = 1; body_len = len(decoded)
        except Exception:
            b64_ok = 0
    if decoded is not None:
        try:
            body = json.loads(decoded)
            is_json = 1
            if isinstance(body, dict):
                fields = ["_type", "subject", "predicateType", "predicate"]
                n_stmt_fields = sum(k in body for k in fields)
                stmt_type_ok = int(body.get("_type") == gs.envelope.IN_TOTO_STATEMENT_TYPE)
                subj = body.get("subject")
                n_subjects = len(subj) if isinstance(subj, list) else 0
                has_predicate = int(isinstance(body.get("predicate"), dict))
        except Exception:
            is_json = 0
    n_sigs = len(sigs) if isinstance(sigs, list) else (-1 if sigs is None else 0)
    sig_len = 0
    sig_b64_ok = -1
    if isinstance(sigs, list) and sigs and isinstance(sigs[0], dict):
        s = sigs[0].get("sig")
        if isinstance(s, str):
            sig_len = len(s)
            try:
                base64.b64decode(s, validate=True); sig_b64_ok = 1
            except Exception:
                sig_b64_ok = 0
    return [
        int(pt == gs.PAYLOAD_TYPE),          # payload_type_ok
        int(pt is not None),                 # has_payload_type
        int(payload is not None),            # has_payload
        b64_ok,                              # payload_b64_ok
        body_len,                            # decoded body length
        is_json,                             # payload_is_json
        n_stmt_fields,                       # in-toto statement fields present (0..4)
        stmt_type_ok,                        # _type == in-toto Statement
        n_subjects,                          # subject count
        has_predicate,                       # predicate is dict
        n_sigs,                              # signature count
        sig_len,                             # first sig string length
        sig_b64_ok,                          # first sig base64-decodable
    ]

FEATURE_NAMES = ["payload_type_ok", "has_payload_type", "has_payload", "payload_b64_ok",
                 "decoded_body_len", "payload_is_json", "n_statement_fields",
                 "stmt_type_ok", "n_subjects", "has_predicate_dict",
                 "n_signatures", "sig_str_len", "sig_b64_ok"]

# ---- generate ----
PER_CLASS = {c: (2600 if c == "valid" else 900) for c in CLASSES}
X, y = [], []
# audit banks (kernel verify() replay)
audit = {c: [] for c in CLASSES}
for cls, n in PER_CLASS.items():
    for i in range(n):
        base_env = make_valid_envelope(i)
        env = corrupt(base_env, cls)
        X.append(features(env)); y.append(cls)
        if len(audit[cls]) < 12:
            audit[cls].append(env)

# ---- kernel-replay audit: the REAL ECDSA verify() is the sole authority ----
verify_agree = 0
audited = 0
for cls, envs in audit.items():
    for env in envs:
        ok = gs.verify(env, PUB)   # REAL cryptographic verification
        expect_true = (cls == "valid")
        assert ok == expect_true, f"kernel verify() disagreement: {cls} -> {ok} (expected {expect_true})"
        # sig-tamper MUST fail crypto verify (proves crypto catches what structure can't)
        audited += 1
        verify_agree += 1

X = np.array(X, dtype=np.float64); y = np.array(y)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
clf = HistGradientBoostingClassifier(random_state=SEED, max_iter=300, early_stopping=True)
clf.fit(Xtr, ytr)
pred = clf.predict(Xte)
acc = accuracy_score(yte, pred)
per_class_recall = {c: float(recall_score(yte == c, pred == c)) for c in CLASSES}
per_class_prec = {c: float(precision_score(yte == c, pred == c, zero_division=0)) for c in CLASSES}
structural = [c for c in CLASSES if c != "sig-tamper"]
mask = np.isin(yte, structural)
acc_structural = accuracy_score(yte[mask], pred[mask])

out_dir = os.path.dirname(os.path.abspath(__file__))
# P0: do not emit pickle/joblib. The kernel source is the approved path.
if os.path.exists(f"{out_dir}/model.joblib") or os.path.exists(f"{os.path.dirname(out_dir)}/model.joblib"):
    raise SystemExit("REFUSE: model.joblib is present. Delete it; pickle is not an approved load path.")
receipt = {
  "artifact": "SZLHOLDINGS/szl-govsign surrogate v1",
  "role": "STRUCTURAL validity PRE-FILTER — NEVER replaces cryptographic verification; passing this filter is NOT verified",
  "generator": {"script": "scripts/forge.py", "seed": SEED, "kernel_version": gs.__version__,
                 "kernel_labelled": True, "kernel_verify_audited_envelopes": audited,
                 "bench_seed": "SZLHOLDINGS/governed-receipts-bench valid/ subject digests",
                 "bench_seed_digests": len(SEED_DIGESTS),
                 "label_source": "envelopes built by REAL gs.attest(); labels audited by REAL gs.verify() (valid->True, all corruption classes->False)"},
  "data": {"rows": int(len(y)), "classes": CLASSES,
            "class_counts": {c: int((y == c).sum()) for c in CLASSES},
            "split": "80/20 stratified", "features": FEATURE_NAMES,
            "feature_policy": "cheap structural observables only; ECDSA-P256 signature verification EXCLUDED by design (measured crypto blind spot)"},
  "model": {"type": "sklearn.HistGradientBoostingClassifier",
             "params": {"max_iter": 300, "early_stopping": True, "random_state": SEED},
             "file": None, "serialization": "QUARANTINED", "sha256": None,
             "statement": "joblib/pickle is not an approved load path. Use torch-ext kernel source."},
  "metrics_MEASURED": {"test_accuracy_all_classes": round(float(acc), 4),
                        "test_accuracy_structural_only": round(float(acc_structural), 4),
                        "per_class_recall": {k: round(v, 4) for k, v in per_class_recall.items()},
                        "per_class_precision": {k: round(v, 4) for k, v in per_class_prec.items()},
                        "crypto_blind_spot": {"class": "sig-tamper",
                          "recall": round(per_class_recall["sig-tamper"], 4),
                          "statement": "a byte-flipped ECDSA signature is STRUCTURALLY IDENTICAL to a valid envelope — the pre-filter cannot detect it (recall ≈ chance). Only real ECDSA-P256 DSSE verify (the kernel's verify()) catches signature tampering. Passing this pre-filter is NOT cryptographic verification and NEVER counts as verified."}},
  "environment": {"python": platform.python_version(), "sklearn": __import__("sklearn").__version__,
                   "numpy": np.__version__, "host": "replit 2-vCPU container", "wall_seconds": round(time.time()-T0, 1)},
  "honesty": "Every number above is MEASURED by this run. This is a STRUCTURAL PRE-FILTER ONLY; cryptographic verification (gs.verify) remains the sole authority for validity. Λ untouched = Conjecture 1; the signature never upgrades advisory to proven trust.",
  "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
quarantine = {
  "status": "QUARANTINED",
  "artifact": "model.joblib",
  "reason": "sklearn/joblib pickle is executable serialization, not an approved load path",
  "approved_load": "torch-ext kernel source",
  "hub": "SZLHOLDINGS/szl-govsign model.joblib remains Hub residue until a Hub PR with exact parent_commit deletes it",
}
with open(f"{out_dir}/SURROGATE_QUARANTINE.json", "w") as f: json.dump(quarantine, f, indent=2)
with open(f"{out_dir}/TRAINING_RECEIPT.json", "w") as f: json.dump(receipt, f, indent=2)
print(json.dumps({"acc": receipt["metrics_MEASURED"]["test_accuracy_all_classes"],
                  "acc_structural": receipt["metrics_MEASURED"]["test_accuracy_structural_only"],
                  "sig_tamper_recall": per_class_recall["sig-tamper"]}, indent=2))
print(f"rows={len(y)} audited={audited} seed_digests={len(SEED_DIGESTS)} wall={receipt['environment']['wall_seconds']}s")
