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
import re
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
    """Deterministic RFC-compatible JSON: sorted keys, compact separators, UTF-8.

    Non-finite floats are refused instead of emitting JavaScript-style NaN or
    Infinity tokens that are outside the JSON data model and are not portable
    across DSSE/in-toto implementations.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
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
    """Accept either Base64 alphabet and optional padding without discarding junk."""
    if not isinstance(s, str):
        raise TypeError("DSSE Base64 fields must be strings")
    if not re.fullmatch(r"[A-Za-z0-9+/_-]*={0,2}", s) or ("=" in s and len(s) % 4):
        raise ValueError("malformed DSSE Base64 encoding")
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)


def verify(
    envelope: Dict[str, Any], public_key: ec.EllipticCurvePublicKey
) -> bool:
    """Verify a DSSE envelope against `public_key`.

    Recomputes PAE over the decoded payload and checks the ECDSA signature.
    Requires well-encoded signature entries and at least one signature that
    verifies. Malformed entries fail regardless of their order; well-encoded
    signatures from other keys do not prevent a matching signer from verifying.
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
        # Validate every encoded entry before accepting any signer. Otherwise a
        # malformed entry after the first valid signature bypasses validation,
        # while the same entry before it fails the identical envelope.
        signatures = [_b64decode_any(sig_entry["sig"]) for sig_entry in sigs]
        for sig in signatures:
            try:
                public_key.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                continue
        return False
    except Exception:
        # Malformed envelope, bad base64, etc. -> verification fails closed.
        return False
