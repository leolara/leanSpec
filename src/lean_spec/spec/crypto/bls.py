"""
BLS12-381 signature operations for the Gloas reference port.

Overview
--------
Gloas is a literal port of the mainnet consensus protocol, which authenticates
proposer blocks, builder bids, and payload-timeliness attestations with BLS12-381
signatures in the minimal-public-key-size variant (public keys in G1, signatures
in G2). This module is the single surface the Gloas spec calls, mirroring the
upstream consensus-specs signature helpers.

Two compiled backends cooperate, matching the upstream default:

- Milagro carries the signature scheme: signing, verification, and aggregation.
- Arkworks supplies the group arithmetic that validates a public key, since the
  Milagro binding exposes no standalone key-validation entry point.

Both are treated as trusted primitives and are not re-verified here; the official
signature and key-validation test suites are out of scope for this port.

The toggle
----------
A module-level switch disables verification for vectors that ship with their
signatures stripped (the test format carries a per-case setting that selects
this). When disabled, verification predicates return true and the signing and
aggregation helpers return fixed stubs, so the state transition still runs.
Verification is deterministic, so the backend never affects conformance, only
speed.
"""

from collections.abc import Sequence
from typing import Any

import milagro_bls_binding
from py_arkworks_bls12381 import G1Point

from lean_spec.spec.ssz.byte_arrays import Bytes48, Bytes96

# The compiled Milagro binding ships no type information.
# The type checker cannot see its call surface through the module object.
# Binding it through a dynamically typed alias keeps the helpers below readable
# while the checker treats every call into the backend as opaque.
milagro: Any = milagro_bls_binding

BLSPubkey = Bytes48
"""A compressed BLS12-381 public key, a 48-byte point in G1."""

BLSSignature = Bytes96
"""A compressed BLS12-381 signature, a 96-byte point in G2."""

SECRET_KEY_BYTE_LENGTH = 32
"""Byte width of a secret-key scalar handed to the backend, big-endian.

The BLS12-381 scalar field order is just under two to the 255th power, so every
secret key fits in 32 bytes. The IETF BLS signature scheme fixes the big-endian
serialization, and the backend expects exactly that width.
"""

bls_active: bool = True
"""Whether the cryptographic backend actually runs.

The vector format may strip signatures from a case.
When this is false, verification predicates pass and the producing helpers return
stubs, so the state transition runs without real cryptography.
"""

STUB_SIGNATURE = BLSSignature(b"\x11" * 96)
"""Signature returned when verification is disabled.

The exact bytes are arbitrary, but pinned to the value the upstream consensus
specs use, so a vector run with verification off produces the same placeholder
on both sides and the resulting states stay comparable.
"""

STUB_PUBKEY = BLSPubkey(b"\x22" * 48)
"""Public key returned when verification is disabled.

The exact bytes are arbitrary, but pinned to the value the upstream consensus
specs use, so cross-checks against that reference line up.
"""


def Sign(secret_key: int, message: bytes) -> BLSSignature:  # noqa: N802
    """Produce a signature over a message with a secret-key scalar."""
    if not bls_active:
        return STUB_SIGNATURE
    secret_key_bytes = secret_key.to_bytes(SECRET_KEY_BYTE_LENGTH, "big")
    return BLSSignature(milagro.Sign(secret_key_bytes, bytes(message)))


def Verify(public_key: BLSPubkey, message: bytes, signature: BLSSignature) -> bool:  # noqa: N802
    """
    Verify one signature against one public key and message.

    A malformed public key or signature verifies as false rather than raising,
    matching the upstream convention where a bad encoding is simply invalid.
    """
    if not bls_active:
        return True
    try:
        return milagro.Verify(bytes(public_key), bytes(message), bytes(signature))
    except Exception:
        return False


def Aggregate(signatures: Sequence[BLSSignature]) -> BLSSignature:  # noqa: N802
    """Combine signatures into a single aggregate signature."""
    if not bls_active:
        return STUB_SIGNATURE
    return BLSSignature(milagro.Aggregate([bytes(signature) for signature in signatures]))


def FastAggregateVerify(  # noqa: N802
    public_keys: Sequence[BLSPubkey], message: bytes, signature: BLSSignature
) -> bool:
    """
    Verify one aggregate signature of a single message under many public keys.

    A malformed input verifies as false rather than raising.
    """
    if not bls_active:
        return True
    try:
        return milagro.FastAggregateVerify(
            [bytes(public_key) for public_key in public_keys],
            bytes(message),
            bytes(signature),
        )
    except Exception:
        return False


G2_POINT_AT_INFINITY = BLSSignature(b"\xc0" + b"\x00" * 95)
"""Compressed encoding of the G2 identity, the signature an empty key set signs."""


def eth_fast_aggregate_verify(  # noqa: N802
    public_keys: Sequence[BLSPubkey], message: bytes, signature: BLSSignature
) -> bool:
    """
    Verify an aggregate signature, accepting the infinity signature for an empty key set.

    An empty key set verifies only against the G2 point at infinity; otherwise this
    aggregates the keys and verifies as usual.
    """
    if len(public_keys) == 0:
        return signature == G2_POINT_AT_INFINITY
    return FastAggregateVerify(public_keys, message, signature)


def AggregateVerify(  # noqa: N802
    public_keys: Sequence[BLSPubkey], messages: Sequence[bytes], signature: BLSSignature
) -> bool:
    """
    Verify one aggregate signature over a list of public-key and message pairs.

    A malformed input verifies as false rather than raising.
    """
    if not bls_active:
        return True
    try:
        return milagro.AggregateVerify(
            [bytes(public_key) for public_key in public_keys],
            [bytes(message) for message in messages],
            bytes(signature),
        )
    except Exception:
        return False


def KeyValidate(public_key: BLSPubkey) -> bool:  # noqa: N802
    """
    Check a public key is a valid, non-identity point in the correct subgroup.

    The check follows the IETF BLS signature scheme: the key must decode to a
    point on the curve, must not be the identity, and must lie in the prime-order
    subgroup. The identity passes a subgroup test on its own, so it is rejected
    explicitly before that test.
    """
    if not bls_active:
        return True
    try:
        point = G1Point.from_compressed_bytes(bytes(public_key))
    except Exception:
        return False
    if point == G1Point.identity():
        return False
    return point.is_in_subgroup()


def SkToPk(secret_key: int) -> BLSPubkey:  # noqa: N802
    """Derive the public key for a secret-key scalar."""
    if not bls_active:
        return STUB_PUBKEY
    secret_key_bytes = secret_key.to_bytes(SECRET_KEY_BYTE_LENGTH, "big")
    return BLSPubkey(milagro.SkToPk(secret_key_bytes))
