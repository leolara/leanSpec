"""
The swap-or-not validator shuffle used by committee and proposer selection.

Overview
--------
Committees and the proposer are chosen by shuffling validator indices with a
seed. The shuffle is the swap-or-not construction (Hoang-Morris-Rogaway), a
format-preserving permutation: it maps the set of indices onto itself, so every
index lands at exactly one position and no two collide.

Algorithm
---------
Each round picks a pivot from the seed, then for every index decides, from one
hash bit, whether to swap it with its mirror position across the pivot. Indices
are bucketed by 256 so one hash supplies the swap bits for a whole bucket.

The index arithmetic is plain modular arithmetic on Python integers; the typed
results are wrapped only at the boundary.
"""

from collections.abc import Sequence
from hashlib import sha256

from lean_spec.spec.forks.beacon.gloas.preset import SHUFFLE_ROUND_COUNT
from lean_spec.spec.ssz import Bytes32, Uint64

# A single hash output covers swap bits for this many positions at once.
_POSITIONS_PER_BUCKET = 256


def compute_shuffled_permutation(index_count: Uint64, seed: Bytes32) -> list[Uint64]:
    """Return the full shuffled permutation of the indices below the count."""
    count = int(index_count)
    # An empty set has only the empty permutation, and the pivot step below would
    # divide by the count, so handle it before the rounds.
    if count == 0:
        return []
    indices = list(range(count))
    rounds = int(SHUFFLE_ROUND_COUNT)
    seed_bytes = bytes(seed)
    for current_round in range(rounds):
        round_bytes = current_round.to_bytes(1, "little")
        # The pivot is the first 8 bytes of the round hash, reduced mod the count.
        pivot = int.from_bytes(sha256(seed_bytes + round_bytes).digest()[0:8], "little") % count
        source_by_bucket: dict[int, bytes] = {}
        for position_index in range(count):
            current = indices[position_index]
            # The mirror of the current index across the pivot.
            flip = (pivot + count - current) % count
            # Decide the swap from the bit at the higher of the two positions.
            position = max(current, flip)
            bucket = position // _POSITIONS_PER_BUCKET
            if bucket not in source_by_bucket:
                source_by_bucket[bucket] = sha256(
                    seed_bytes + round_bytes + bucket.to_bytes(4, "little")
                ).digest()
            source = source_by_bucket[bucket]
            swap_byte = source[(position % _POSITIONS_PER_BUCKET) // 8]
            swap_bit = (swap_byte >> (position % 8)) % 2
            if swap_bit:
                indices[position_index] = flip
    return [Uint64(value) for value in indices]


def compute_shuffled_index(index: Uint64, index_count: Uint64, seed: Bytes32) -> Uint64:
    """
    Return the position an index is shuffled to under a seed.

    Raises:
        AssertionError: If the index is not below the count.
    """
    assert index < index_count
    return compute_shuffled_permutation(index_count, seed)[int(index)]


def compute_committee(
    indices: Sequence[Uint64], seed: Bytes32, index: Uint64, count: Uint64
) -> list[Uint64]:
    """Return the slice of shuffled indices that forms one committee."""
    total = len(indices)
    start = (total * int(index)) // int(count)
    end = (total * (int(index) + 1)) // int(count)
    return [
        indices[int(compute_shuffled_index(Uint64(position), Uint64(total), seed))]
        for position in range(start, end)
    ]
