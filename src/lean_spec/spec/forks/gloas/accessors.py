"""
Read-only accessors over the beacon state.

These derive epochs, historical roots, randomness seeds, committees, and balance
totals from the state. They never mutate it.

The shared SSZ integers are strict about operand types: an arithmetic operation
needs both sides of the same width type. Where the upstream mixes a domain newtype
with a preset constant, the arithmetic runs on plain integers and the result is
wrapped back into its domain type.
"""

from hashlib import sha256

from lean_spec.spec.forks.gloas.constants import DOMAIN_BEACON_ATTESTER, GENESIS_EPOCH
from lean_spec.spec.forks.gloas.containers.beacon_chain import BeaconState
from lean_spec.spec.forks.gloas.containers.primitives import (
    CommitteeIndex,
    DomainType,
    Epoch,
    Gwei,
    Root,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.gloas.helpers.math import uint64_to_bytes
from lean_spec.spec.forks.gloas.helpers.shuffle import compute_committee
from lean_spec.spec.forks.gloas.predicates import is_active_validator
from lean_spec.spec.forks.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    MAX_COMMITTEES_PER_SLOT,
    MAX_SEED_LOOKAHEAD,
    MIN_SEED_LOOKAHEAD,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
    TARGET_COMMITTEE_SIZE,
)
from lean_spec.spec.ssz import Bytes32, Uint64

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)
_EPOCHS_PER_HISTORICAL_VECTOR = int(EPOCHS_PER_HISTORICAL_VECTOR)
_MIN_SEED_LOOKAHEAD = int(MIN_SEED_LOOKAHEAD)


def compute_epoch_at_slot(slot: Slot) -> Epoch:
    """Return the epoch a slot falls in."""
    return Epoch(int(slot) // _SLOTS_PER_EPOCH)


def compute_start_slot_at_epoch(epoch: Epoch) -> Slot:
    """Return the first slot of an epoch."""
    return Slot(int(epoch) * _SLOTS_PER_EPOCH)


def compute_activation_exit_epoch(epoch: Epoch) -> Epoch:
    """Return the epoch an activation or exit initiated this epoch takes effect."""
    return Epoch(int(epoch) + 1 + int(MAX_SEED_LOOKAHEAD))


def get_current_epoch(state: BeaconState) -> Epoch:
    """Return the epoch the state is currently in."""
    return compute_epoch_at_slot(state.slot)


def get_previous_epoch(state: BeaconState) -> Epoch:
    """Return the epoch before the current one, clamped at genesis."""
    current_epoch = get_current_epoch(state)
    if current_epoch == GENESIS_EPOCH:
        return GENESIS_EPOCH
    return Epoch(int(current_epoch) - 1)


def get_active_validator_indices(state: BeaconState, epoch: Epoch) -> list[ValidatorIndex]:
    """Return the indices of validators active in the given epoch."""
    return [
        ValidatorIndex(index)
        for index, validator in enumerate(state.validators)
        if is_active_validator(validator, epoch)
    ]


def get_block_root_at_slot(state: BeaconState, slot: Slot) -> Root:
    """
    Return a recent block root by slot.

    Raises:
        AssertionError: If the slot is not within the retained history window.
    """
    assert int(slot) < int(state.slot) <= int(slot) + _SLOTS_PER_HISTORICAL_ROOT
    return state.block_roots[int(slot) % _SLOTS_PER_HISTORICAL_ROOT]


def get_block_root(state: BeaconState, epoch: Epoch) -> Root:
    """Return the block root at the start of a recent epoch."""
    return get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))


def get_randao_mix(state: BeaconState, epoch: Epoch) -> Bytes32:
    """Return the randao mix recorded for a recent epoch."""
    return state.randao_mixes[int(epoch) % _EPOCHS_PER_HISTORICAL_VECTOR]


def get_seed(state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
    """
    Return the seed mixing randomness, the epoch, and a domain into one hash.

    The mix is taken a full history window minus the seed lookahead back, which
    keeps the index non-negative without an explicit underflow guard.
    """
    lookahead_epoch = Epoch(int(epoch) + _EPOCHS_PER_HISTORICAL_VECTOR - _MIN_SEED_LOOKAHEAD - 1)
    mix = get_randao_mix(state, lookahead_epoch)
    return Bytes32(sha256(bytes(domain_type) + uint64_to_bytes(epoch) + bytes(mix)).digest())


def get_committee_count_per_slot(state: BeaconState, epoch: Epoch) -> Uint64:
    """Return how many committees each slot is split into for the epoch."""
    active_validator_count = Uint64(len(get_active_validator_indices(state, epoch)))
    return max(
        Uint64(1),
        min(
            MAX_COMMITTEES_PER_SLOT,
            active_validator_count // SLOTS_PER_EPOCH // TARGET_COMMITTEE_SIZE,
        ),
    )


def get_beacon_committee(
    state: BeaconState, slot: Slot, index: CommitteeIndex
) -> list[ValidatorIndex]:
    """Return the validator indices of one committee at a slot."""
    epoch = compute_epoch_at_slot(slot)
    committees_per_slot = int(get_committee_count_per_slot(state, epoch))
    committee_index = (int(slot) % _SLOTS_PER_EPOCH) * committees_per_slot + int(index)
    committee = compute_committee(
        indices=get_active_validator_indices(state, epoch),
        seed=get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
        index=Uint64(committee_index),
        count=Uint64(committees_per_slot * _SLOTS_PER_EPOCH),
    )
    return [ValidatorIndex(int(member)) for member in committee]


def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:
    """Return the proposer for the current slot from the precomputed lookahead."""
    return state.proposer_lookahead[int(state.slot) % _SLOTS_PER_EPOCH]


def get_total_balance(state: BeaconState, indices: set[ValidatorIndex]) -> Gwei:
    """
    Return the summed effective balance of the indices, floored at one increment.

    The floor avoids a later division by zero when the set is empty.
    """
    total = sum(int(state.validators[index].effective_balance) for index in indices)
    return Gwei(max(int(EFFECTIVE_BALANCE_INCREMENT), total))


def get_total_active_balance(state: BeaconState) -> Gwei:
    """Return the summed effective balance of the currently active validators."""
    active_indices = get_active_validator_indices(state, get_current_epoch(state))
    return get_total_balance(state, set(active_indices))
