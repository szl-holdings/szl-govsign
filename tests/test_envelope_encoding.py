"""Malformed Base64 must not be silently normalized into a valid envelope."""
import base64
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'torch-ext'))
from szl_govsign.envelope import Subject, _b64decode_any, attest, generate_ephemeral_keypair, verify


@pytest.mark.parametrize('field', ['payload', 'signature'])
@pytest.mark.parametrize('junk', ['#', ' ', '\n', '\t', '!'])
def test_non_alphabet_characters_fail_verification(field, junk):
    key = generate_ephemeral_keypair()
    envelope = attest([Subject('artifact', {'sha256': '0' * 64})], {}, key)
    assert verify(envelope, key.public_key()) is True
    if field == 'payload':
        envelope['payload'] = junk + envelope['payload']
    else:
        envelope['signatures'][0]['sig'] = junk + envelope['signatures'][0]['sig']
    assert verify(envelope, key.public_key()) is False


@pytest.mark.parametrize('raw', [b'\xfb\xff', b'\xfb\xff\x00', b'f', b'fo', b'foo'])
@pytest.mark.parametrize('url_safe', [False, True])
@pytest.mark.parametrize('padded', [False, True])
def test_both_base64_alphabets_and_padding_forms_remain_supported(raw, url_safe, padded):
    encoder = base64.urlsafe_b64encode if url_safe else base64.b64encode
    encoded = encoder(raw).decode('ascii')
    if not padded:
        encoded = encoded.rstrip('=')
    assert _b64decode_any(encoded) == raw


@pytest.mark.parametrize('encoded', ['AAAA====', 'AAAA=', 'AA=A', 'A', 'AA==\n', 'é', None, 12, b'Zg=='])
def test_malformed_encoding_is_rejected(encoded):
    with pytest.raises((TypeError, ValueError)):
        _b64decode_any(encoded)


def test_url_safe_unpadded_envelope_still_verifies():
    key = generate_ephemeral_keypair()
    envelope = attest([Subject('artifact', {'sha256': '0' * 64})], {}, key)
    converted = deepcopy(envelope)
    converted['payload'] = converted['payload'].translate(str.maketrans('+/', '-_')).rstrip('=')
    converted['signatures'][0]['sig'] = converted['signatures'][0]['sig'].translate(str.maketrans('+/', '-_')).rstrip('=')
    assert verify(converted, key.public_key()) is True
