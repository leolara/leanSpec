"""
Runner for the rewards format.

A rewards case ships a pre-state and the expected reward and penalty deltas for
each timeliness flag and for the inactivity penalty. Each delta function is a pure
function of the pre-state, so the handler recomputes them and checks every set.
"""

from __future__ import annotations

from pathlib import Path

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.constants import (
    TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import BeaconState
from lean_spec.spec.forks.gloas.containers.primitives import Gwei
from lean_spec.spec.forks.gloas.preset import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.gloas.spec import GloasSpec
from lean_spec.spec.ssz import Container, SSZList
from pyspec_vectors_testing.decode import decompress_ssz


class _DeltaList(SSZList[Gwei]):
    """Per-validator reward or penalty amounts, one entry per registry slot."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class Deltas(Container):
    """The rewards and penalties one delta function assigns to every validator."""

    rewards: _DeltaList
    penalties: _DeltaList


# Each timeliness flag has its own delta file, all driven by one flag-delta function.
FLAG_DELTA_FILES: dict[str, int] = {
    "source_deltas": TIMELY_SOURCE_FLAG_INDEX,
    "target_deltas": TIMELY_TARGET_FLAG_INDEX,
    "head_deltas": TIMELY_HEAD_FLAG_INDEX,
}


def _assert_deltas(case_dir: Path, file_stem: str, rewards: list, penalties: list) -> None:
    """Compare a computed delta set to the expected delta file's contents."""
    expected = Deltas.decode_bytes(decompress_ssz(case_dir / f"{file_stem}.ssz_snappy"))
    actual = Deltas(rewards=_DeltaList(data=rewards), penalties=_DeltaList(data=penalties))
    actual_root = hash_tree_root(actual)
    expected_root = hash_tree_root(expected)
    assert actual_root == expected_root, (
        f"{file_stem} mismatch:\n  expected {expected_root.hex()}\n  actual   {actual_root.hex()}"
    )


def run_rewards_case(case_dir: Path) -> None:
    """
    Recompute every delta set from the pre-state and compare to the expected files.

    Raises:
        AssertionError: If any computed reward or penalty set differs from the vector.
    """
    spec = GloasSpec()
    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))

    for file_stem, flag_index in FLAG_DELTA_FILES.items():
        rewards, penalties = spec.get_flag_index_deltas(pre_state, flag_index)
        _assert_deltas(case_dir, file_stem, rewards, penalties)

    inactivity_rewards, inactivity_penalties = spec.get_inactivity_penalty_deltas(pre_state)
    _assert_deltas(case_dir, "inactivity_penalty_deltas", inactivity_rewards, inactivity_penalties)
