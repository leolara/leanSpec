"""
Runner for the epoch_processing format.

An epoch_processing case applies one epoch sub-transition to a pre-state that has
already been advanced to just before that sub-transition. A case that ships a
post-state expects the sub-transition to succeed and the resulting state root to
match; a case with no post-state expects it to be aborted.

Each handler name maps to the spec method of the same name, prefixed with
"process_". Handlers whose method is not yet implemented are skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import lean_spec.spec.crypto.bls as bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.containers.beacon_chain import BeaconState
from lean_spec.spec.forks.gloas.spec import GloasSpec
from pyspec_vectors_testing.decode import bls_is_active, decompress_ssz, load_meta

# A few handler suites exercise one sub-transition under a name that is not its
# method name; map those to the method they drive.
HANDLER_METHOD_OVERRIDES: dict[str, str] = {
    "pending_deposits_churn": "process_pending_deposits",
}


def run_epoch_processing_case(case_dir: Path, handler: str) -> None:
    """
    Run one epoch sub-transition case, comparing the post-state or expecting an abort.

    Raises:
        AssertionError: If the post-state root differs, or an aborted case does not raise.
    """
    spec = GloasSpec()
    method_name = HANDLER_METHOD_OVERRIDES.get(handler, f"process_{handler}")
    if not hasattr(spec, method_name):
        pytest.skip(f"epoch_processing handler not yet supported: {handler}")
    process = getattr(spec, method_name)

    bls.bls_active = bls_is_active(load_meta(case_dir))

    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))

    post_path = case_dir / "post.ssz_snappy"
    if post_path.exists():
        expected_state = BeaconState.decode_bytes(decompress_ssz(post_path))
        actual_state = process(pre_state)
        actual_root = hash_tree_root(actual_state)
        expected_root = hash_tree_root(expected_state)
        assert actual_root == expected_root, (
            f"post-state root mismatch:\n"
            f"  expected {expected_root.hex()}\n"
            f"  actual   {actual_root.hex()}"
        )
    else:
        # A case that ships no post-state expects the sub-transition to be aborted.
        with pytest.raises(Exception):  # noqa: B017, PT011
            process(pre_state)
