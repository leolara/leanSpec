"""
Runner for the operations format.

An operations case applies one block operation to a pre-state. A case that ships
a post-state expects the operation to succeed and the resulting state root to
match; a case with no post-state expects the operation to be rejected.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import lean_spec.spec.crypto.bls as bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    BeaconState,
    SignedBLSToExecutionChange,
)
from lean_spec.spec.forks.gloas.state_transition.operations import process_bls_to_execution_change
from lean_spec.spec.ssz.ssz_base import SSZType
from pyspec_vectors_testing.decode import bls_is_active, decompress_ssz, load_meta


@dataclass(frozen=True)
class OperationSpec:
    """How one operations handler maps to a process function and its object file."""

    process: Callable[[BeaconState, Any], BeaconState]
    container: type[SSZType]
    file_stem: str


# One entry per supported operations handler; unsupported handlers are skipped.
OPERATION_SPECS: dict[str, OperationSpec] = {
    "bls_to_execution_change": OperationSpec(
        process=process_bls_to_execution_change,
        container=SignedBLSToExecutionChange,
        file_stem="address_change",
    ),
}


def run_operations_case(case_dir: Path, handler: str) -> None:
    """
    Run one operations case, comparing the post-state or expecting a rejection.

    Raises:
        AssertionError: If the post-state root differs, or a rejection case does not reject.
    """
    if handler not in OPERATION_SPECS:
        pytest.skip(f"operations handler not yet supported: {handler}")
    spec = OPERATION_SPECS[handler]

    bls.bls_active = bls_is_active(load_meta(case_dir))

    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))
    operation = spec.container.decode_bytes(
        decompress_ssz(case_dir / f"{spec.file_stem}.ssz_snappy")
    )

    post_path = case_dir / "post.ssz_snappy"
    if post_path.exists():
        expected_state = BeaconState.decode_bytes(decompress_ssz(post_path))
        actual_state = spec.process(pre_state, operation)
        actual_root = hash_tree_root(actual_state)
        expected_root = hash_tree_root(expected_state)
        assert actual_root == expected_root, (
            f"post-state root mismatch:\n"
            f"  expected {expected_root.hex()}\n"
            f"  actual   {actual_root.hex()}"
        )
    else:
        with pytest.raises(AssertionError):
            spec.process(pre_state, operation)
