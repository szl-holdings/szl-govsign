"""DSSE envelope: in-toto Statement construction, signing, and verification.

Statement shape follows the in-toto attestation framework:

    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": ..., "digest": {"sha256": ...}}, ...],
      "predicateType": "https://szl.holdings/governance/v1",
      "predicate": { ...governance predicate... }
    }

The Statement is JSON-serialized (canonical: sorted keys, compact separators),
base64-encoded into the DSSE `payload`, and signed via
Sign(PAE(payloadType, payloadBytes)) using ECDSA P-256 / SHA-256.

Production note: this demo generates an EPHEMERAL in-process keypair. In
production, signing is keyless via Sigstore (Fulcio short-lived cert + Rekor
transparency log) or a real cosign key managed out-of-band — see GOVSIGN_SPEC.md.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Dict, List, Any, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from .pae import pae, PAYLOAD_TYPE

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


@dataclass
class Subject:
    """An in-toto subject: a name plus a digest map (algo -> hex digest)."""

    name: str
    digest: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "digest": dict(self.digest)}


def _canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def build_statement(
    subjects: List[Subject], predicate_type: str, predicate: Dict[str, Any]
) -> Dict[str, Any]:
    """Construct an in-toto v1 Statement dict."""
    if not subjects:
        raise ValueError("at least one subject is required")
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [s.to_dict() for s in subjects],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def generate_ephemeral_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate an EPHEMERAL ECDSA P-256 private key (in-process, demo only).

    No private key is ever written to disk by this library.
    """
    return ec.generate_private_key(ec.SECP256R1())


def public_key_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Return the PEM-encoded public key for distribution/verification."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _keyid(public_key: ec.EllipticCurvePublicKey) -> str:
    """SHA-256 (hex) over the DER SubjectPublicKeyInfo — an unauthenticated hint."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def attest(
    subjects: List[Subject],
    predicate: Dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    predicate_type: str = "https://szl.holdings/governance/v1",
) -> Dict[str, Any]:
    """Build the Statement, then sign it into a DSSE envelope.

    Returns the DSSE envelope dict:
        {"payloadType", "payload" (b64), "signatures":[{"keyid","sig"(b64)}]}
    """
    statement = build_statement(subjects, predicate_type, predicate)
    body = _canonical_json_bytes(statement)

    to_sign = pae(PAYLOAD_TYPE, body)
    signature = private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode("ascii"),
        "signatures": [
            {
                "keyid": _keyid(private_key.public_key()),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def _b64decode_any(s: str) -> bytes:
    """Accept standard or URL-safe base64 (DSSE verifiers must accept either)."""
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(
    envelope: Dict[str, Any], public_key: ec.EllipticCurvePublicKey
) -> bool:
    """Verify a DSSE envelope against `public_key`.

    Recomputes PAE over the decoded payload and checks the ECDSA signature.
    Returns True only if at least one signature verifies; False otherwise.
    Never raises on a bad signature — returns False (so tamper => False).
    """
    try:
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            return False
        body = _b64decode_any(envelope["payload"])
        to_verify = pae(PAYLOAD_TYPE, body)
        sigs = envelope.get("signatures") or []
        if not sigs:
            return False
        for sig_entry in sigs:
            sig = _b64decode_any(sig_entry["sig"])
            try:
                public_key.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                continue
        return False
    except Exception:
        # Malformed envelope, bad base64, etc. -> verification fails closed.
        return False
