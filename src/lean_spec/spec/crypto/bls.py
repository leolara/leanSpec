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

# Pairings and subgroup checks dominate the cost of replaying vectors, and the
# same inputs recur constantly: an attestation is verified inside the state
# transition and again when fork choice re-imports it, and the same validator
# keys are validated on every call. These memo tables key results on the raw
# bytes of the inputs, which is sound because the operations are pure.
#
# Only the active backend populates them. The disabled path returns at once and
# never reads them, so a case that toggles verification off can never observe a
# hit cached by a verifying case.
_verify_cache: dict[tuple[bytes, bytes, bytes], bool] = {}
_fast_aggregate_verify_cache: dict[tuple[tuple[bytes, ...], bytes, bytes], bool] = {}
_aggregate_verify_cache: dict[tuple[tuple[bytes, ...], tuple[bytes, ...], bytes], bool] = {}
_key_validate_cache: dict[bytes, bool] = {}
_aggregate_pubkeys_cache: dict[tuple[bytes, ...], BLSPubkey] = {}


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
    cache_key = (bytes(public_key), bytes(message), bytes(signature))
    if cache_key in _verify_cache:
        return _verify_cache[cache_key]
    try:
        result = milagro.Verify(*cache_key)
    except Exception:
        result = False
    _verify_cache[cache_key] = result
    return result


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
    cache_key = (
        tuple(bytes(public_key) for public_key in public_keys),
        bytes(message),
        bytes(signature),
    )
    if cache_key in _fast_aggregate_verify_cache:
        return _fast_aggregate_verify_cache[cache_key]
    try:
        result = milagro.FastAggregateVerify(list(cache_key[0]), cache_key[1], cache_key[2])
    except Exception:
        result = False
    _fast_aggregate_verify_cache[cache_key] = result
    return result


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


def eth_aggregate_pubkeys(public_keys: Sequence[BLSPubkey]) -> BLSPubkey:  # noqa: N802
    """
    Return the aggregate public key for a non-empty key set.

    Aggregation is elliptic-curve point addition over the decoded keys. It runs
    even when the backend is inactive, since the aggregate is a deterministic part
    of the state and must stay byte-exact regardless of signature verification.
    """
    assert len(public_keys) > 0
    if bls_active:
        assert all(KeyValidate(public_key) for public_key in public_keys)
    cache_key = tuple(bytes(public_key) for public_key in public_keys)
    if cache_key in _aggregate_pubkeys_cache:
        return _aggregate_pubkeys_cache[cache_key]
    aggregate_point = G1Point.from_compressed_bytes(cache_key[0])
    for public_key_bytes in cache_key[1:]:
        aggregate_point = aggregate_point + G1Point.from_compressed_bytes(public_key_bytes)
    aggregate = BLSPubkey(aggregate_point.to_compressed_bytes())
    _aggregate_pubkeys_cache[cache_key] = aggregate
    return aggregate


def AggregateVerify(  # noqa: N802
    public_keys: Sequence[BLSPubkey], messages: Sequence[bytes], signature: BLSSignature
) -> bool:
    """
    Verify one aggregate signature over a list of public-key and message pairs.

    A malformed input verifies as false rather than raising.
    """
    if not bls_active:
        return True
    cache_key = (
        tuple(bytes(public_key) for public_key in public_keys),
        tuple(bytes(message) for message in messages),
        bytes(signature),
    )
    if cache_key in _aggregate_verify_cache:
        return _aggregate_verify_cache[cache_key]
    try:
        result = milagro.AggregateVerify(list(cache_key[0]), list(cache_key[1]), cache_key[2])
    except Exception:
        result = False
    _aggregate_verify_cache[cache_key] = result
    return result


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
    cache_key = bytes(public_key)
    if cache_key in _key_validate_cache:
        return _key_validate_cache[cache_key]
    try:
        point = G1Point.from_compressed_bytes(cache_key)
    except Exception:
        _key_validate_cache[cache_key] = False
        return False
    result = point != G1Point.identity() and point.is_in_subgroup()
    _key_validate_cache[cache_key] = result
    return result


def SkToPk(secret_key: int) -> BLSPubkey:  # noqa: N802
    """Derive the public key for a secret-key scalar."""
    if not bls_active:
        return STUB_PUBKEY
    secret_key_bytes = secret_key.to_bytes(SECRET_KEY_BYTE_LENGTH, "big")
    return BLSPubkey(milagro.SkToPk(secret_key_bytes))
