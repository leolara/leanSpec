"""Small integer and byte helpers used across the Gloas state transition."""

from lean_spec.spec.forks.gloas.constants import UINT64_MAX, UINT64_MAX_SQRT
from lean_spec.spec.ssz import Bytes32, Uint64


def integer_squareroot(n: Uint64) -> Uint64:
    """
    Return the largest integer whose square does not exceed the input.

    The maximum input is special-cased: its true square root is precomputed,
    because the Newton iteration would otherwise overflow on the first step.
    """
    if n == UINT64_MAX:
        return UINT64_MAX_SQRT
    # The Newton iteration runs on plain integers to avoid the typed arithmetic's
    # same-type operand rule; the result is wrapped back at the boundary.
    value = int(n)
    current = value
    candidate = (current + 1) // 2
    while candidate < current:
        current = candidate
        candidate = (current + value // current) // 2
    return Uint64(current)


def xor(first: Bytes32, second: Bytes32) -> Bytes32:
    """Return the byte-wise exclusive-or of two 32-byte values."""
    return Bytes32(left ^ right for left, right in zip(first, second, strict=True))


def bytes_to_uint64(data: bytes) -> Uint64:
    """Read a little-endian unsigned 64-bit integer from raw bytes."""
    return Uint64(int.from_bytes(data, "little"))
