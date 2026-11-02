"""Malformed signature entries cannot be hidden behind a valid first signer."""
import base64
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "torch-ext"))
from szl_govsign.envelope import Subject, attest, generate_ephemeral_keypair, verify


@pytest.fixture
def signed():
    key = generate_ephemeral_keypair()
    envelope = attest([Subject("artifact", {"sha256": "0" * 64})], {}, key)
    assert verify(envelope, key.public_key()) is True
    return key, envelope


@pytest.mark.parametrize("malformed", [
    None, {}, "signature", 1, {"sig": None}, {"sig": 1},
    {"sig": "#"}, {"sig": "AAAA="}, {"sig": "AA=A"}, {"sig": "é"},
])
@pytest.mark.parametrize("valid_first", [False, True])
def test_malformed_signature_entry_rejected_in_either_order(signed, malformed, valid_first):
    key, envelope = signed
    valid = envelope["signatures"][0]
    envelope["signatures"] = [valid, malformed] if valid_first else [malformed, valid]
    assert verify(envelope, key.public_key()) is False


@pytest.mark.parametrize("valid_first", [False, True])
@pytest.mark.parametrize("other_kind", ["wrong_key", "invalid_der"])
def test_well_encoded_nonmatching_signature_preserves_valid_signer(signed, valid_first, other_kind):
    key, envelope = signed
    valid = envelope["signatures"][0]
    if other_kind == "wrong_key":
        other = attest([Subject("artifact", {"sha256": "0" * 64})], {},
                       generate_ephemeral_keypair())["signatures"][0]
    else:
        other = {"sig": base64.b64encode(b"not-an-ECDSA-signature").decode("ascii")}
    envelope["signatures"] = [valid, other] if valid_first else [other, valid]
    assert verify(envelope, key.public_key()) is True
    assert verify(envelope, generate_ephemeral_keypair().public_key()) is False

    tampered = deepcopy(envelope)
    tampered["payload"] = base64.b64encode(b"tampered payload").decode("ascii")
    assert verify(tampered, key.public_key()) is False


def test_valid_multi_signer_envelope_accepts_each_signer(signed):
    key, envelope = signed
    other_key = generate_ephemeral_keypair()
    other = attest([Subject("artifact", {"sha256": "0" * 64})], {}, other_key)
    envelope["signatures"].extend(other["signatures"])
    for signatures in (envelope["signatures"], list(reversed(envelope["signatures"]))):
        envelope["signatures"] = signatures
        assert verify(envelope, key.public_key()) is True
        assert verify(envelope, other_key.public_key()) is True


def test_no_cryptographically_valid_signature_still_fails(signed):
    key, envelope = signed
    envelope["signatures"] = [{"sig": base64.b64encode(b"invalid").decode("ascii")}]
    assert verify(envelope, key.public_key()) is False
    envelope["signatures"] = []
    assert verify(envelope, key.public_key()) is False
