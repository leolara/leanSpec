"""
Runner for the block and slot state-transition formats.

The slots handler advances a pre-state by a fixed number of empty slots. The
blocks handler imports a sequence of signed blocks through the full state
transition. The same blocks driver backs the sanity, finality, and random
runners, which differ only in how their block sequences are constructed.

A case that ships a post-state expects the transition to succeed and the
resulting state root to match; a case with no post-state expects it to be
rejected somewhere in the sequence.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import lean_spec.spec.crypto.bls as bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import BeaconState, SignedBeaconBlock
from lean_spec.spec.forks.beacon.gloas.containers.primitives import Slot
from lean_spec.spec.forks.beacon.gloas.spec import GloasSpec
from pyspec_vectors_testing.decode import bls_is_active, decompress_ssz, load_meta


def _assert_post_state(case_dir: Path, actual_state: BeaconState) -> None:
    """Compare the produced state root to the expected post-state's root."""
    expected_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "post.ssz_snappy"))
    actual_root = hash_tree_root(actual_state)
    expected_root = hash_tree_root(expected_state)
    assert actual_root == expected_root, (
        f"post-state root mismatch:\n"
        f"  expected {expected_root.hex()}\n"
        f"  actual   {actual_root.hex()}"
    )


def run_slots_case(case_dir: Path) -> None:
    """Advance the pre-state by the slot count in slots.yaml and compare the post-state."""
    spec = GloasSpec()
    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))
    slot_count = int(yaml.safe_load((case_dir / "slots.yaml").read_text()))
    actual_state = spec.process_slots(pre_state, Slot(int(pre_state.slot) + slot_count))
    _assert_post_state(case_dir, actual_state)


def run_blocks_case(case_dir: Path) -> None:
    """
    Import each signed block through the state transition and compare the post-state.

    Raises:
        AssertionError: If the post-state root differs, or a rejection case does not reject.
    """
    spec = GloasSpec()
    meta = load_meta(case_dir)
    bls.bls_active = bls_is_active(meta)

    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))
    blocks_count = int(meta.get("blocks_count", 0))
    signed_blocks = [
        SignedBeaconBlock.decode_bytes(decompress_ssz(case_dir / f"blocks_{index}.ssz_snappy"))
        for index in range(blocks_count)
    ]

    if (case_dir / "post.ssz_snappy").exists():
        state = pre_state
        for signed_block in signed_blocks:
            state = spec.state_transition(state, signed_block)
        _assert_post_state(case_dir, state)
    else:
        # A case that ships no post-state expects one of the blocks to be rejected.
        with pytest.raises(Exception):  # noqa: B017, PT011
            state = pre_state
            for signed_block in signed_blocks:
                state = spec.state_transition(state, signed_block)


def run_sanity_case(case_dir: Path, handler: str) -> None:
    """Dispatch a sanity case to the slots or blocks driver by its handler name."""
    if handler == "slots":
        run_slots_case(case_dir)
    elif handler == "blocks":
        run_blocks_case(case_dir)
    else:
        pytest.skip(f"sanity handler not yet supported: {handler}")
