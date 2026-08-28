"""DSSE Pre-Authentication Encoding (PAE).

Implements the canonical PAE from the DSSE spec
(secure-systems-lab/dsse, protocol.md):

    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type
                                + SP + LEN(body) + SP + body

where SP is ASCII space (0x20) and LEN(s) is the ASCII decimal byte length
of s with no leading zeros. The signature is computed over
PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY).

This module is pure stdlib.
"""
from __future__ import annotations

# DSSE payloadType for in-toto Statements.
PAYLOAD_TYPE = "application/vnd.in-toto+json"

_SP = b"\x20"
_PREFIX = b"DSSEv1"


def pae(payload_type: str, body: bytes) -> bytes:
    """Return the DSSE Pre-Authentication Encoding for (payload_type, body).

    `payload_type` is UTF-8 encoded; `body` is the raw serialized payload bytes.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be bytes")
    type_bytes = payload_type.encode("utf-8")
    return (
        _PREFIX
        + _SP
        + str(len(type_bytes)).encode("ascii")
        + _SP
        + type_bytes
        + _SP
        + str(len(body)).encode("ascii")
        + _SP
        + bytes(body)
    )
