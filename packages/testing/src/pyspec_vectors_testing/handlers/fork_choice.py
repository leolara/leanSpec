"""
Runner for the fork_choice format.

A fork-choice case builds a store from an anchor state and block, then replays a
sequence of steps: clock ticks, block and attestation and payload arrivals, and
check steps that assert the store's head, checkpoints, boost, and payload votes.
A step marked invalid is expected to be rejected.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

import lean_spec.spec.crypto.bls as bls
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import (
    Attestation,
    AttesterSlashing,
    BeaconBlock,
    BeaconState,
    PayloadAttestationMessage,
    SignedBeaconBlock,
    SignedExecutionPayloadEnvelope,
)
from lean_spec.spec.forks.beacon.gloas.containers.fork_choice import Store
from lean_spec.spec.forks.beacon.gloas.containers.primitives import Root
from lean_spec.spec.forks.beacon.gloas.spec import GloasSpec
from lean_spec.spec.ssz import Boolean, Uint64
from pyspec_vectors_testing.decode import bls_is_active, decompress_ssz, load_meta


def _root_hex(root: Root) -> str:
    """Render a root as the 0x-prefixed hex string the step files use."""
    return f"0x{bytes(root).hex()}"


def _vote_matches(actual: Boolean | None, expected: bool | None) -> bool:
    """Compare one stored ternary payload vote against its expected yaml value."""
    if expected is None:
        return actual is None
    return actual is not None and bool(actual) == expected


def _run_checks(spec: GloasSpec, store: Store, checks: dict[str, Any]) -> None:
    """Assert the store matches every field a check step names."""
    if "time" in checks:
        assert int(store.time) == checks["time"]
    if "genesis_time" in checks:
        assert int(store.genesis_time) == checks["genesis_time"]
    if "proposer_boost_root" in checks:
        assert _root_hex(store.proposer_boost_root) == checks["proposer_boost_root"]
    if "head" in checks:
        head = spec.get_head(store)
        assert _root_hex(head.root) == checks["head"]["root"]
        assert int(store.blocks[head.root].slot) == checks["head"]["slot"]
        assert int(head.payload_status) == checks["head"]["payload_status"]
    for checkpoint_key in ("justified_checkpoint", "finalized_checkpoint"):
        if checkpoint_key in checks:
            checkpoint = getattr(store, checkpoint_key)
            assert int(checkpoint.epoch) == checks[checkpoint_key]["epoch"]
            assert _root_hex(checkpoint.root) == checks[checkpoint_key]["root"]
    if "payload_timeliness_vote" in checks:
        expected = checks["payload_timeliness_vote"]
        stored = store.payload_timeliness_vote[Root(bytes.fromhex(expected["block_root"][2:]))]
        assert all(_vote_matches(stored[i], vote) for i, vote in enumerate(expected["votes"]))
    if "payload_data_availability_vote" in checks:
        expected = checks["payload_data_availability_vote"]
        stored = store.payload_data_availability_vote[
            Root(bytes.fromhex(expected["block_root"][2:]))
        ]
        assert all(_vote_matches(stored[i], vote) for i, vote in enumerate(expected["votes"]))


def _run_block_step(spec: GloasSpec, store: Store, case_dir: Path, step: dict[str, Any]) -> None:
    """Apply a block, then feed its attestations and attester slashings to the store."""
    signed_block = SignedBeaconBlock.decode_bytes(
        decompress_ssz(case_dir / f"{step['block']}.ssz_snappy")
    )
    if not step.get("valid", True):
        with pytest.raises(Exception):  # noqa: B017, PT011
            spec.on_block(store, signed_block)
        return
    spec.on_block(store, signed_block)
    for attestation in signed_block.message.body.attestations:
        spec.on_attestation(store, attestation, is_from_block=True)
    for attester_slashing in signed_block.message.body.attester_slashings:
        spec.on_attester_slashing(store, attester_slashing)


def _run_step(spec: GloasSpec, store: Store, case_dir: Path, step: dict[str, Any]) -> None:
    """Dispatch one step in the scenario to its store operation or check."""
    if "tick" in step:
        spec.on_tick(store, Uint64(step["tick"]))
    elif "block" in step:
        _run_block_step(spec, store, case_dir, step)
    elif "attestation" in step:
        attestation = Attestation.decode_bytes(
            decompress_ssz(case_dir / f"{step['attestation']}.ssz_snappy")
        )
        if not step.get("valid", True):
            with pytest.raises(Exception):  # noqa: B017, PT011
                spec.on_attestation(store, attestation, is_from_block=False)
        else:
            spec.on_attestation(store, attestation, is_from_block=False)
    elif "execution_payload" in step:
        signed_envelope = SignedExecutionPayloadEnvelope.decode_bytes(
            decompress_ssz(case_dir / f"{step['execution_payload']}.ssz_snappy")
        )
        if not step.get("valid", True):
            with pytest.raises(Exception):  # noqa: B017, PT011
                spec.on_execution_payload_envelope(store, signed_envelope)
        else:
            spec.on_execution_payload_envelope(store, signed_envelope)
    elif "payload_attestation_message" in step:
        ptc_message = PayloadAttestationMessage.decode_bytes(
            decompress_ssz(case_dir / f"{step['payload_attestation_message']}.ssz_snappy")
        )
        if not step.get("valid", True):
            with pytest.raises(Exception):  # noqa: B017, PT011
                spec.on_payload_attestation_message(store, ptc_message, is_from_block=False)
        else:
            spec.on_payload_attestation_message(store, ptc_message, is_from_block=False)
    elif "attester_slashing" in step:
        attester_slashing = AttesterSlashing.decode_bytes(
            decompress_ssz(case_dir / f"{step['attester_slashing']}.ssz_snappy")
        )
        spec.on_attester_slashing(store, attester_slashing)
    elif "checks" in step:
        _run_checks(spec, store, step["checks"])
    else:
        pytest.skip(f"fork_choice step not yet supported: {sorted(step)}")


def run_fork_choice_case(case_dir: Path) -> None:
    """
    Build the store from the anchor and replay every step in the scenario.

    Raises:
        AssertionError: If a check fails, or a step expected to be rejected is accepted.
    """
    spec = GloasSpec()
    bls.bls_active = bls_is_active(load_meta(case_dir))

    anchor_state = BeaconState.decode_bytes(decompress_ssz(case_dir / "anchor_state.ssz_snappy"))
    anchor_block = BeaconBlock.decode_bytes(decompress_ssz(case_dir / "anchor_block.ssz_snappy"))
    store = spec.get_forkchoice_store(anchor_state, anchor_block)

    for step in yaml.safe_load((case_dir / "steps.yaml").read_text()):
        _run_step(spec, store, case_dir, step)
