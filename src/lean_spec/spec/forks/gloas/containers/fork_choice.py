"""
Fork-choice store and node types.

The store is a node's local, mutable view of the chain used to run fork choice.
Unlike the consensus state, it is updated in place as blocks, attestations, and
payloads arrive, so it is a plain mutable structure rather than a frozen SSZ
container. A fork-choice node names a block together with the payload-presence
decision for that block, the unit the Gloas LMD-GHOST search ranks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    BeaconBlock,
    BeaconState,
    Checkpoint,
    ExecutionPayloadEnvelope,
)
from lean_spec.spec.forks.gloas.containers.primitives import Root, Slot, ValidatorIndex
from lean_spec.spec.ssz import Boolean, Uint8, Uint64


class PayloadStatus(Uint8):
    """Payload-presence decision attached to a fork-choice node."""


PAYLOAD_STATUS_EMPTY = PayloadStatus(0)
"""The slot's block was applied with no execution payload."""

PAYLOAD_STATUS_FULL = PayloadStatus(1)
"""The slot's block was applied with its execution payload present."""

PAYLOAD_STATUS_PENDING = PayloadStatus(2)
"""The payload decision for the slot is not yet settled."""


@dataclass(eq=True, frozen=True)
class ForkChoiceNode:
    """A block root paired with the payload-presence decision fork choice ranks."""

    root: Root
    payload_status: PayloadStatus


@dataclass(eq=True, frozen=True)
class LatestMessage:
    """The most recent fork-choice vote observed from one validator."""

    slot: Slot
    root: Root
    payload_present: Boolean


@dataclass
class Store:
    """A node's local, mutable view of the chain for running fork choice."""

    time: Uint64
    genesis_time: Uint64
    justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    unrealized_justified_checkpoint: Checkpoint
    unrealized_finalized_checkpoint: Checkpoint
    proposer_boost_root: Root
    equivocating_indices: set[ValidatorIndex] = field(default_factory=set)
    blocks: dict[Root, BeaconBlock] = field(default_factory=dict)
    block_states: dict[Root, BeaconState] = field(default_factory=dict)
    block_timeliness: dict[Root, list[Boolean]] = field(default_factory=dict)
    checkpoint_states: dict[Checkpoint, BeaconState] = field(default_factory=dict)
    latest_messages: dict[ValidatorIndex, LatestMessage] = field(default_factory=dict)
    unrealized_justifications: dict[Root, Checkpoint] = field(default_factory=dict)
    payloads: dict[Root, ExecutionPayloadEnvelope] = field(default_factory=dict)
    payload_timeliness_vote: dict[Root, list[Boolean | None]] = field(default_factory=dict)
    payload_data_availability_vote: dict[Root, list[Boolean | None]] = field(default_factory=dict)
