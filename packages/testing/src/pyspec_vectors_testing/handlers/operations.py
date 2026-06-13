"""
Runner for the operations format.

An operations case applies one block operation to a pre-state. A case that ships
a post-state expects the operation to succeed and the resulting state root to
match; a case with no post-state expects the operation to be rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

import lean_spec.spec.crypto.bls as bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Attestation,
    AttesterSlashing,
    BeaconBlock,
    BeaconState,
    ConsolidationRequest,
    DepositRequest,
    PayloadAttestation,
    ProposerSlashing,
    SignedBLSToExecutionChange,
    SignedVoluntaryExit,
    WithdrawalRequest,
)
from lean_spec.spec.forks.gloas.spec import GloasSpec
from lean_spec.spec.ssz.ssz_base import SSZType
from pyspec_vectors_testing.decode import bls_is_active, decompress_ssz, load_meta


@dataclass(frozen=True)
class OperationSpec:
    """How one operations handler maps to a spec method and its object file."""

    method: str
    container: type[SSZType]
    file_stem: str


# One entry per supported operations handler; unsupported handlers are skipped.
OPERATION_SPECS: dict[str, OperationSpec] = {
    "bls_to_execution_change": OperationSpec(
        method="process_bls_to_execution_change",
        container=SignedBLSToExecutionChange,
        file_stem="address_change",
    ),
    "proposer_slashing": OperationSpec(
        method="process_proposer_slashing",
        container=ProposerSlashing,
        file_stem="proposer_slashing",
    ),
    "attester_slashing": OperationSpec(
        method="process_attester_slashing",
        container=AttesterSlashing,
        file_stem="attester_slashing",
    ),
    "block_header": OperationSpec(
        method="process_block_header",
        container=BeaconBlock,
        file_stem="block",
    ),
    "attestation": OperationSpec(
        method="process_attestation",
        container=Attestation,
        file_stem="attestation",
    ),
    "withdrawal_request": OperationSpec(
        method="process_withdrawal_request",
        container=WithdrawalRequest,
        file_stem="withdrawal_request",
    ),
    "voluntary_exit": OperationSpec(
        method="process_voluntary_exit",
        container=SignedVoluntaryExit,
        file_stem="voluntary_exit",
    ),
    "voluntary_exit_churn": OperationSpec(
        method="process_voluntary_exit",
        container=SignedVoluntaryExit,
        file_stem="voluntary_exit",
    ),
    "consolidation_request": OperationSpec(
        method="process_consolidation_request",
        container=ConsolidationRequest,
        file_stem="consolidation_request",
    ),
    "deposit_request": OperationSpec(
        method="process_deposit_request",
        container=DepositRequest,
        file_stem="deposit_request",
    ),
    "payload_attestation": OperationSpec(
        method="process_payload_attestation",
        container=PayloadAttestation,
        file_stem="payload_attestation",
    ),
    "execution_payload_bid": OperationSpec(
        method="process_execution_payload_bid",
        container=BeaconBlock,
        file_stem="block",
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
    operation_spec = OPERATION_SPECS[handler]
    spec = GloasSpec()
    process = getattr(spec, operation_spec.method)

    bls.bls_active = bls_is_active(load_meta(case_dir))

    pre_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "pre.ssz_snappy"))
    operation = operation_spec.container.decode_bytes(
        decompress_ssz(case_dir / f"{operation_spec.file_stem}.ssz_snappy")
    )

    post_path = case_dir / "post.ssz_snappy"
    if post_path.exists():
        expected_state = BeaconState.decode_bytes(decompress_ssz(post_path))
        actual_state = process(pre_state, operation)
        actual_root = hash_tree_root(actual_state)
        expected_root = hash_tree_root(expected_state)
        assert actual_root == expected_root, (
            f"post-state root mismatch:\n"
            f"  expected {expected_root.hex()}\n"
            f"  actual   {actual_root.hex()}"
        )
    else:
        # A case that ships no post-state expects the operation to be rejected.
        # The upstream runner treats any raised exception as a rejection, since a
        # bad operation can fail an assert or fault on an out-of-range lookup.
        with pytest.raises(Exception):  # noqa: B017, PT011
            process(pre_state, operation)
