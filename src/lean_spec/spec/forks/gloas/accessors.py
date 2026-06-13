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

from lean_spec.spec.forks.gloas.constants import (
    DOMAIN_BEACON_ATTESTER,
    FAR_FUTURE_EPOCH,
    GENESIS_EPOCH,
    TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Attestation,
    AttestationData,
    AttestingIndices,
    BeaconState,
    ConsolidationRequest,
    IndexedAttestation,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BuilderIndex,
    CommitteeIndex,
    DomainType,
    Epoch,
    Gwei,
    ParticipationFlags,
    Root,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.gloas.helpers.math import integer_squareroot, uint64_to_bytes
from lean_spec.spec.forks.gloas.helpers.shuffle import compute_committee
from lean_spec.spec.forks.gloas.preset import (
    BASE_REWARD_FACTOR,
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    MAX_COMMITTEES_PER_SLOT,
    MAX_SEED_LOOKAHEAD,
    MIN_ATTESTATION_INCLUSION_DELAY,
    MIN_SEED_LOOKAHEAD,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
    TARGET_COMMITTEE_SIZE,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Bytes32, Uint64
from lean_spec.spec.ssz.bitfields import BaseBitvector

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)
_EPOCHS_PER_HISTORICAL_VECTOR = int(EPOCHS_PER_HISTORICAL_VECTOR)
_MIN_SEED_LOOKAHEAD = int(MIN_SEED_LOOKAHEAD)


class AccessorMixin(GloasSpecBase):
    """Accessor behavior for the Gloas spec."""

    def compute_epoch_at_slot(self, slot: Slot) -> Epoch:
        """Return the epoch a slot falls in."""
        return Epoch(int(slot) // _SLOTS_PER_EPOCH)

    def compute_start_slot_at_epoch(self, epoch: Epoch) -> Slot:
        """Return the first slot of an epoch."""
        return Slot(int(epoch) * _SLOTS_PER_EPOCH)

    def compute_activation_exit_epoch(self, epoch: Epoch) -> Epoch:
        """Return the epoch an activation or exit initiated this epoch takes effect."""
        return Epoch(int(epoch) + 1 + int(MAX_SEED_LOOKAHEAD))

    def get_current_epoch(self, state: BeaconState) -> Epoch:
        """Return the epoch the state is currently in."""
        return self.compute_epoch_at_slot(state.slot)

    def get_previous_epoch(self, state: BeaconState) -> Epoch:
        """Return the epoch before the current one, clamped at genesis."""
        current_epoch = self.get_current_epoch(state)
        if current_epoch == GENESIS_EPOCH:
            return GENESIS_EPOCH
        return Epoch(int(current_epoch) - 1)

    def get_active_validator_indices(
        self, state: BeaconState, epoch: Epoch
    ) -> list[ValidatorIndex]:
        """Return the indices of validators active in the given epoch."""
        return [
            ValidatorIndex(index)
            for index, validator in enumerate(state.validators)
            if self.is_active_validator(validator, epoch)
        ]

    def get_block_root_at_slot(self, state: BeaconState, slot: Slot) -> Root:
        """
        Return a recent block root by slot.

        Raises:
            AssertionError: If the slot is not within the retained history window.
        """
        assert int(slot) < int(state.slot) <= int(slot) + _SLOTS_PER_HISTORICAL_ROOT
        return state.block_roots[int(slot) % _SLOTS_PER_HISTORICAL_ROOT]

    def get_block_root(self, state: BeaconState, epoch: Epoch) -> Root:
        """Return the block root at the start of a recent epoch."""
        return self.get_block_root_at_slot(state, self.compute_start_slot_at_epoch(epoch))

    def get_randao_mix(self, state: BeaconState, epoch: Epoch) -> Bytes32:
        """Return the randao mix recorded for a recent epoch."""
        return state.randao_mixes[int(epoch) % _EPOCHS_PER_HISTORICAL_VECTOR]

    def get_seed(self, state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
        """
        Return the seed mixing randomness, the epoch, and a domain into one hash.

        The mix is taken a full history window minus the seed lookahead back, which
        keeps the index non-negative without an explicit underflow guard.
        """
        lookahead_epoch = Epoch(
            int(epoch) + _EPOCHS_PER_HISTORICAL_VECTOR - _MIN_SEED_LOOKAHEAD - 1
        )
        mix = self.get_randao_mix(state, lookahead_epoch)
        return Bytes32(sha256(bytes(domain_type) + uint64_to_bytes(epoch) + bytes(mix)).digest())

    def get_committee_count_per_slot(self, state: BeaconState, epoch: Epoch) -> Uint64:
        """Return how many committees each slot is split into for the epoch."""
        active_validator_count = Uint64(len(self.get_active_validator_indices(state, epoch)))
        return max(
            Uint64(1),
            min(
                MAX_COMMITTEES_PER_SLOT,
                active_validator_count // SLOTS_PER_EPOCH // TARGET_COMMITTEE_SIZE,
            ),
        )

    def get_beacon_committee(
        self, state: BeaconState, slot: Slot, index: CommitteeIndex
    ) -> list[ValidatorIndex]:
        """Return the validator indices of one committee at a slot."""
        epoch = self.compute_epoch_at_slot(slot)
        committees_per_slot = int(self.get_committee_count_per_slot(state, epoch))
        committee_index = (int(slot) % _SLOTS_PER_EPOCH) * committees_per_slot + int(index)
        committee = compute_committee(
            indices=self.get_active_validator_indices(state, epoch),
            seed=self.get_seed(state, epoch, DOMAIN_BEACON_ATTESTER),
            index=Uint64(committee_index),
            count=Uint64(committees_per_slot * _SLOTS_PER_EPOCH),
        )
        return [ValidatorIndex(int(member)) for member in committee]

    def get_beacon_proposer_index(self, state: BeaconState) -> ValidatorIndex:
        """Return the proposer for the current slot from the precomputed lookahead."""
        return state.proposer_lookahead[int(state.slot) % _SLOTS_PER_EPOCH]

    def get_total_balance(self, state: BeaconState, indices: set[ValidatorIndex]) -> Gwei:
        """
        Return the summed effective balance of the indices, floored at one increment.

        The floor avoids a later division by zero when the set is empty.
        """
        total = sum(int(state.validators[index].effective_balance) for index in indices)
        return Gwei(max(int(EFFECTIVE_BALANCE_INCREMENT), total))

    def get_total_active_balance(self, state: BeaconState) -> Gwei:
        """Return the summed effective balance of the currently active validators."""
        active_indices = self.get_active_validator_indices(state, self.get_current_epoch(state))
        return self.get_total_balance(state, set(active_indices))

    def get_pending_balance_to_withdraw(
        self, state: BeaconState, validator_index: ValidatorIndex
    ) -> Gwei:
        """Return the gwei a validator already has queued for partial withdrawal."""
        return Gwei(
            sum(
                int(withdrawal.amount)
                for withdrawal in state.pending_partial_withdrawals
                if withdrawal.validator_index == validator_index
            )
        )

    def is_valid_switch_to_compounding_request(
        self, state: BeaconState, consolidation_request: ConsolidationRequest
    ) -> bool:
        """Check whether a self-targeting consolidation requests a compounding switch."""
        if consolidation_request.source_public_key != consolidation_request.target_public_key:
            return False
        public_keys = [validator.public_key for validator in state.validators]
        if consolidation_request.source_public_key not in public_keys:
            return False
        source = state.validators[public_keys.index(consolidation_request.source_public_key)]
        if bytes(source.withdrawal_credentials)[12:] != bytes(consolidation_request.source_address):
            return False
        if not self.has_eth1_withdrawal_credential(source):
            return False
        if not self.is_active_validator(source, self.get_current_epoch(state)):
            return False
        return source.exit_epoch == FAR_FUTURE_EPOCH

    def is_active_builder(self, state: BeaconState, builder_index: BuilderIndex) -> bool:
        """Check whether a builder is finalized into the registry and not exiting."""
        builder = state.builders[int(builder_index)]
        return (
            builder.deposit_epoch < state.finalized_checkpoint.epoch
            and builder.withdrawable_epoch == FAR_FUTURE_EPOCH
        )

    def get_pending_balance_to_withdraw_for_builder(
        self, state: BeaconState, builder_index: BuilderIndex
    ) -> Gwei:
        """Return the gwei a builder has queued across pending withdrawals and payments."""
        from_withdrawals = sum(
            int(withdrawal.amount)
            for withdrawal in state.builder_pending_withdrawals
            if withdrawal.builder_index == builder_index
        )
        from_payments = sum(
            int(payment.withdrawal.amount)
            for payment in state.builder_pending_payments
            if payment.withdrawal.builder_index == builder_index
        )
        return Gwei(from_withdrawals + from_payments)

    def get_committee_indices(self, committee_bits: BaseBitvector) -> list[CommitteeIndex]:
        """Return the committee indices whose bit is set in an attestation."""
        return [CommitteeIndex(index) for index, bit in enumerate(committee_bits.data) if bit]

    def get_attesting_indices(
        self, state: BeaconState, attestation: Attestation
    ) -> set[ValidatorIndex]:
        """Return the validator indices that an attestation's bits mark as attesting."""
        attesting: set[ValidatorIndex] = set()
        committee_offset = 0
        for committee_index in self.get_committee_indices(attestation.committee_bits):
            committee = self.get_beacon_committee(state, attestation.data.slot, committee_index)
            for position, attester_index in enumerate(committee):
                if attestation.aggregation_bits[committee_offset + position]:
                    attesting.add(attester_index)
            committee_offset += len(committee)
        return attesting

    def get_indexed_attestation(
        self, state: BeaconState, attestation: Attestation
    ) -> IndexedAttestation:
        """Return the indexed form of an attestation, with sorted attesting indices."""
        attesting_indices = sorted(self.get_attesting_indices(state, attestation))
        return IndexedAttestation(
            attesting_indices=AttestingIndices(data=attesting_indices),
            data=attestation.data,
            signature=attestation.signature,
        )

    def is_attestation_same_slot(self, state: BeaconState, data: AttestationData) -> bool:
        """Check whether an attestation votes for the block proposed at its own slot."""
        if data.slot == Slot(0):
            return True
        block_root = data.beacon_block_root
        same_slot_root = self.get_block_root_at_slot(state, data.slot)
        previous_slot_root = self.get_block_root_at_slot(state, Slot(int(data.slot) - 1))
        return block_root == same_slot_root and block_root != previous_slot_root

    def get_attestation_participation_flag_indices(
        self, state: BeaconState, data: AttestationData, inclusion_delay: Uint64
    ) -> list[int]:
        """
        Return which timeliness flags an attestation earns.

        The flags reward a vote whose source, target, head, and execution-payload
        presence match the canonical chain, each within its own timeliness window.

        Raises:
            AssertionError: If the source checkpoint does not match the justified one.
        """
        if data.target.epoch == self.get_current_epoch(state):
            justified_checkpoint = state.current_justified_checkpoint
        else:
            justified_checkpoint = state.previous_justified_checkpoint
        is_matching_source = data.source == justified_checkpoint

        target_root = self.get_block_root(state, data.target.epoch)
        is_matching_target = is_matching_source and data.target.root == target_root

        if self.is_attestation_same_slot(state, data):
            assert data.index == CommitteeIndex(0)
            payload_matches = True
        else:
            slot_index = int(data.slot) % int(SLOTS_PER_HISTORICAL_ROOT)
            payload_present = state.execution_payload_availability.data[slot_index]
            payload_matches = int(data.index) == int(payload_present)

        head_root = self.get_block_root_at_slot(state, data.slot)
        is_matching_head = (
            is_matching_target and data.beacon_block_root == head_root and payload_matches
        )

        assert is_matching_source

        flag_indices: list[int] = []
        timely_source_window = integer_squareroot(SLOTS_PER_EPOCH)
        if is_matching_source and inclusion_delay <= timely_source_window:
            flag_indices.append(TIMELY_SOURCE_FLAG_INDEX)
        if is_matching_target:
            flag_indices.append(TIMELY_TARGET_FLAG_INDEX)
        if is_matching_head and inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY:
            flag_indices.append(TIMELY_HEAD_FLAG_INDEX)
        return flag_indices

    def get_base_reward_per_increment(self, state: BeaconState) -> Gwei:
        """Return the base reward earned per effective-balance increment this epoch."""
        total_active = Uint64(int(self.get_total_active_balance(state)))
        return Gwei(
            int(EFFECTIVE_BALANCE_INCREMENT)
            * int(BASE_REWARD_FACTOR)
            // int(integer_squareroot(total_active))
        )

    def get_base_reward(self, state: BeaconState, index: ValidatorIndex) -> Gwei:
        """Return one validator's base reward, scaled by its effective balance."""
        increments = int(state.validators[int(index)].effective_balance) // int(
            EFFECTIVE_BALANCE_INCREMENT
        )
        return Gwei(increments * int(self.get_base_reward_per_increment(state)))

    def add_flag(self, flags: ParticipationFlags, flag_index: int) -> ParticipationFlags:
        """Return the participation flags with one timeliness flag added."""
        return flags | ParticipationFlags(2**flag_index)

    def has_flag(self, flags: ParticipationFlags, flag_index: int) -> bool:
        """Check whether the participation flags already carry one timeliness flag."""
        flag = ParticipationFlags(2**flag_index)
        return (flags & flag) == flag
