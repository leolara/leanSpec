"""
Read-only accessors over the beacon state.

These derive epochs, historical roots, randomness seeds, committees, and balance
totals from the state. They never mutate it.

The shared SSZ integers are strict about operand types: an arithmetic operation
needs both sides of the same width type. Where the upstream mixes a domain newtype
with a preset constant, the arithmetic runs on plain integers and the result is
wrapped back into its domain type.
"""

from collections.abc import Sequence
from hashlib import sha256

from lean_spec.spec.crypto import bls
from lean_spec.spec.forks.beacon.gloas.config import (
    BLOB_SCHEDULE,
    CHURN_LIMIT_QUOTIENT_GLOAS,
    ELECTRA_FORK_EPOCH,
    MAX_BLOBS_PER_BLOCK_ELECTRA,
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS,
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
    BlobParameters,
)
from lean_spec.spec.forks.beacon.gloas.constants import (
    BUILDER_PAYMENT_THRESHOLD_DENOMINATOR,
    BUILDER_PAYMENT_THRESHOLD_NUMERATOR,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_PTC_ATTESTER,
    DOMAIN_SYNC_COMMITTEE,
    FAR_FUTURE_EPOCH,
    GENESIS_EPOCH,
    TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX,
)
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import (
    Attestation,
    AttestationData,
    AttestingIndices,
    BeaconState,
    ConsolidationRequest,
    IndexedAttestation,
    IndexedPayloadAttestation,
    IndexedpayloadattestationAttestingIndices,
    PayloadAttestation,
    PtcWindowElement,
    PublicKeys,
    SyncCommittee,
    Withdrawal,
)
from lean_spec.spec.forks.beacon.gloas.containers.primitives import (
    BLSPubkey,
    BuilderIndex,
    CommitteeIndex,
    DomainType,
    Epoch,
    ExecutionAddress,
    Gwei,
    ParticipationFlags,
    Root,
    Slot,
    ValidatorIndex,
    WithdrawalIndex,
)
from lean_spec.spec.forks.beacon.gloas.containers.withdrawals import ExpectedWithdrawals
from lean_spec.spec.forks.beacon.gloas.helpers.math import (
    bytes_to_uint64,
    integer_squareroot,
    uint64_to_bytes,
)
from lean_spec.spec.forks.beacon.gloas.helpers.shuffle import (
    compute_committee,
    compute_shuffled_index,
)
from lean_spec.spec.forks.beacon.gloas.preset import (
    BASE_REWARD_FACTOR,
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    MAX_BUILDERS_PER_WITHDRAWALS_SWEEP,
    MAX_COMMITTEES_PER_SLOT,
    MAX_EFFECTIVE_BALANCE_ELECTRA,
    MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
    MAX_SEED_LOOKAHEAD,
    MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
    MAX_WITHDRAWALS_PER_PAYLOAD,
    MIN_ACTIVATION_BALANCE,
    MIN_ATTESTATION_INCLUSION_DELAY,
    MIN_EPOCHS_TO_INACTIVITY_PENALTY,
    MIN_SEED_LOOKAHEAD,
    PTC_SIZE,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
    SYNC_COMMITTEE_SIZE,
    TARGET_COMMITTEE_SIZE,
)
from lean_spec.spec.forks.beacon.gloas.spec_base import GloasSpecBase
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

    def get_blob_parameters(self, epoch: Epoch) -> BlobParameters:
        """Return the blob ceiling active at an epoch from the configured schedule."""
        # Walk the schedule newest-first and take the first bump already activated.
        for scheduled in sorted(BLOB_SCHEDULE, key=lambda entry: int(entry.epoch), reverse=True):
            if int(epoch) >= int(scheduled.epoch):
                return scheduled
        return BlobParameters(
            epoch=ELECTRA_FORK_EPOCH, max_blobs_per_block=MAX_BLOBS_PER_BLOCK_ELECTRA
        )

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

    def get_index_for_new_validator(self, state: BeaconState) -> ValidatorIndex:
        """Return the registry index a newly deposited validator will occupy."""
        return ValidatorIndex(len(state.validators))

    def get_activation_churn_limit(self, state: BeaconState) -> Gwei:
        """Return the per-epoch activation churn, floored, rounded, and capped."""
        churn = max(
            int(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA),
            int(self.get_total_active_balance(state)) // int(CHURN_LIMIT_QUOTIENT_GLOAS),
        )
        rounded_churn = churn - churn % int(EFFECTIVE_BALANCE_INCREMENT)
        return Gwei(min(int(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS), rounded_churn))

    def compute_balance_weighted_selection(
        self,
        state: BeaconState,
        indices: Sequence[ValidatorIndex],
        seed: Bytes32,
        size: Uint64,
        shuffle_indices: bool,
    ) -> list[ValidatorIndex]:
        """Sample candidate indices by effective balance, possibly with duplicates."""
        max_random_value = 2**16 - 1
        total = len(indices)
        assert total > 0
        effective_balances = [
            int(state.validators[int(index)].effective_balance) for index in indices
        ]
        selected: list[ValidatorIndex] = []
        sample = 0
        random_bytes = b""
        while len(selected) < int(size):
            offset = sample % 16 * 2
            if offset == 0:
                random_bytes = sha256(bytes(seed) + uint64_to_bytes(Uint64(sample // 16))).digest()
            candidate_position = sample % total
            if shuffle_indices:
                candidate_position = int(
                    compute_shuffled_index(Uint64(candidate_position), Uint64(total), seed)
                )
            weight = effective_balances[candidate_position] * max_random_value
            random_value = int(bytes_to_uint64(random_bytes[offset : offset + 2]))
            threshold = int(MAX_EFFECTIVE_BALANCE_ELECTRA) * random_value
            if weight >= threshold:
                selected.append(indices[candidate_position])
            sample += 1
        return selected

    def compute_ptc(self, state: BeaconState, slot: Slot) -> PtcWindowElement:
        """Sample the payload timeliness committee for a slot, balance-weighted with duplicates."""
        epoch = self.compute_epoch_at_slot(slot)
        seed = Bytes32(
            sha256(
                bytes(self.get_seed(state, epoch, DOMAIN_PTC_ATTESTER)) + uint64_to_bytes(slot)
            ).digest()
        )
        committee_indices: list[ValidatorIndex] = []
        for committee_index in range(int(self.get_committee_count_per_slot(state, epoch))):
            committee_indices.extend(
                self.get_beacon_committee(state, slot, CommitteeIndex(committee_index))
            )
        return PtcWindowElement(
            data=self.compute_balance_weighted_selection(
                state, committee_indices, seed, PTC_SIZE, shuffle_indices=False
            )
        )

    def get_builder_payment_quorum_threshold(self, state: BeaconState) -> Uint64:
        """Return the per-slot weight a builder payment must reach to be honored."""
        per_slot_balance = int(self.get_total_active_balance(state)) // _SLOTS_PER_EPOCH
        quorum = per_slot_balance * int(BUILDER_PAYMENT_THRESHOLD_NUMERATOR)
        return Uint64(quorum // int(BUILDER_PAYMENT_THRESHOLD_DENOMINATOR))

    def compute_proposer_indices(
        self,
        state: BeaconState,
        epoch: Epoch,
        seed: Bytes32,
        indices: Sequence[ValidatorIndex],
    ) -> list[ValidatorIndex]:
        """Sample one balance-weighted proposer per slot of an epoch from the candidates."""
        start_slot = int(self.compute_start_slot_at_epoch(epoch))
        per_slot_seeds = [
            sha256(bytes(seed) + uint64_to_bytes(Slot(start_slot + slot_offset))).digest()
            for slot_offset in range(_SLOTS_PER_EPOCH)
        ]
        return [
            self.compute_balance_weighted_selection(
                state, indices, Bytes32(per_slot_seed), Uint64(1), shuffle_indices=True
            )[0]
            for per_slot_seed in per_slot_seeds
        ]

    def get_beacon_proposer_indices(self, state: BeaconState, epoch: Epoch) -> list[ValidatorIndex]:
        """Return the proposer for each slot of an epoch, drawn from unslashed active validators."""
        candidate_indices = [
            validator_index
            for validator_index in self.get_active_validator_indices(state, epoch)
            if not state.validators[int(validator_index)].slashed
        ]
        seed = self.get_seed(state, epoch, DOMAIN_BEACON_PROPOSER)
        return self.compute_proposer_indices(state, epoch, seed, candidate_indices)

    def get_next_sync_committee_indices(self, state: BeaconState) -> list[ValidatorIndex]:
        """Sample the next sync committee's members, balance-weighted with duplicates."""
        epoch = Epoch(int(self.get_current_epoch(state)) + 1)
        seed = self.get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)
        active_indices = self.get_active_validator_indices(state, epoch)
        return self.compute_balance_weighted_selection(
            state, active_indices, seed, SYNC_COMMITTEE_SIZE, shuffle_indices=True
        )

    def get_next_sync_committee(self, state: BeaconState) -> SyncCommittee:
        """Build the next sync committee from its sampled members and their aggregate key."""
        member_indices = self.get_next_sync_committee_indices(state)
        public_keys = [state.validators[int(index)].public_key for index in member_indices]
        return SyncCommittee(
            public_keys=PublicKeys(data=public_keys),
            aggregate_public_key=BLSPubkey(bls.eth_aggregate_pubkeys(public_keys)),
        )

    def get_unslashed_participating_indices(
        self, state: BeaconState, flag_index: int, epoch: Epoch
    ) -> set[ValidatorIndex]:
        """Return the active, unslashed validators that earned a timeliness flag in an epoch."""
        assert epoch in (self.get_previous_epoch(state), self.get_current_epoch(state))
        epoch_participation = (
            state.current_epoch_participation
            if epoch == self.get_current_epoch(state)
            else state.previous_epoch_participation
        )
        return {
            validator_index
            for validator_index in self.get_active_validator_indices(state, epoch)
            if self.has_flag(epoch_participation[int(validator_index)], flag_index)
            and not state.validators[int(validator_index)].slashed
        }

    def get_eligible_validator_indices(self, state: BeaconState) -> list[ValidatorIndex]:
        """Return the validators eligible for rewards and penalties this epoch."""
        previous_epoch = self.get_previous_epoch(state)
        return [
            ValidatorIndex(validator_index)
            for validator_index, validator in enumerate(state.validators)
            if self.is_active_validator(validator, previous_epoch)
            or (validator.slashed and int(previous_epoch) + 1 < int(validator.withdrawable_epoch))
        ]

    def get_finality_delay(self, state: BeaconState) -> Uint64:
        """Return how many epochs the previous epoch trails the last finalized one."""
        return Uint64(int(self.get_previous_epoch(state)) - int(state.finalized_checkpoint.epoch))

    def is_in_inactivity_leak(self, state: BeaconState) -> bool:
        """Check whether finality has stalled long enough to trigger the inactivity leak."""
        return int(self.get_finality_delay(state)) > int(MIN_EPOCHS_TO_INACTIVITY_PENALTY)

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

    def get_index_for_new_builder(self, state: BeaconState) -> BuilderIndex:
        """Return a reusable exited-builder slot, or the next free index past the registry."""
        current_epoch = self.get_current_epoch(state)
        for builder_index, builder in enumerate(state.builders):
            # An exited builder whose balance has fully withdrawn frees its slot.
            if builder.withdrawable_epoch <= current_epoch and builder.balance == Gwei(0):
                return BuilderIndex(builder_index)
        return BuilderIndex(len(state.builders))

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

    def get_balance_after_withdrawals(
        self,
        state: BeaconState,
        validator_index: ValidatorIndex,
        withdrawals: Sequence[Withdrawal],
    ) -> Gwei:
        """Return a validator's balance with the already-planned withdrawals subtracted."""
        withdrawn = sum(
            int(withdrawal.amount)
            for withdrawal in withdrawals
            if withdrawal.validator_index == validator_index
        )
        return Gwei(int(state.balances[int(validator_index)]) - withdrawn)

    def get_builder_withdrawals(
        self,
        state: BeaconState,
        withdrawal_index: WithdrawalIndex,
        prior_withdrawals: Sequence[Withdrawal],
    ) -> tuple[list[Withdrawal], WithdrawalIndex, Uint64]:
        """Drain queued builder withdrawals, reserving one payload slot for the validator sweep."""
        withdrawals_limit = int(MAX_WITHDRAWALS_PER_PAYLOAD) - 1
        assert len(prior_withdrawals) <= withdrawals_limit

        processed_count = 0
        withdrawals: list[Withdrawal] = []
        for pending_withdrawal in state.builder_pending_withdrawals:
            if len(prior_withdrawals) + len(withdrawals) >= withdrawals_limit:
                break
            withdrawals.append(
                Withdrawal(
                    index=withdrawal_index,
                    validator_index=self.convert_builder_index_to_validator_index(
                        pending_withdrawal.builder_index
                    ),
                    address=pending_withdrawal.fee_recipient,
                    amount=pending_withdrawal.amount,
                )
            )
            withdrawal_index = WithdrawalIndex(int(withdrawal_index) + 1)
            processed_count += 1
        return withdrawals, withdrawal_index, Uint64(processed_count)

    def get_builders_sweep_withdrawals(
        self,
        state: BeaconState,
        withdrawal_index: WithdrawalIndex,
        prior_withdrawals: Sequence[Withdrawal],
    ) -> tuple[list[Withdrawal], WithdrawalIndex, Uint64]:
        """Sweep the builder registry for exited, funded builders past the saved cursor."""
        epoch = self.get_current_epoch(state)
        builders_limit = min(len(state.builders), int(MAX_BUILDERS_PER_WITHDRAWALS_SWEEP))
        withdrawals_limit = int(MAX_WITHDRAWALS_PER_PAYLOAD) - 1
        assert len(prior_withdrawals) <= withdrawals_limit

        processed_count = 0
        withdrawals: list[Withdrawal] = []
        builder_index = int(state.next_withdrawal_builder_index)
        for _ in range(builders_limit):
            if len(prior_withdrawals) + len(withdrawals) >= withdrawals_limit:
                break
            builder = state.builders[builder_index]
            if builder.withdrawable_epoch <= epoch and builder.balance > Gwei(0):
                withdrawals.append(
                    Withdrawal(
                        index=withdrawal_index,
                        validator_index=self.convert_builder_index_to_validator_index(
                            BuilderIndex(builder_index)
                        ),
                        address=builder.execution_address,
                        amount=builder.balance,
                    )
                )
                withdrawal_index = WithdrawalIndex(int(withdrawal_index) + 1)
            builder_index = (builder_index + 1) % len(state.builders)
            processed_count += 1
        return withdrawals, withdrawal_index, Uint64(processed_count)

    def get_pending_partial_withdrawals(
        self,
        state: BeaconState,
        withdrawal_index: WithdrawalIndex,
        prior_withdrawals: Sequence[Withdrawal],
    ) -> tuple[list[Withdrawal], WithdrawalIndex, Uint64]:
        """Drain matured pending partial withdrawals up to this sweep's bounded budget."""
        epoch = self.get_current_epoch(state)
        withdrawals_limit = min(
            len(prior_withdrawals) + int(MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP),
            int(MAX_WITHDRAWALS_PER_PAYLOAD) - 1,
        )
        assert len(prior_withdrawals) <= withdrawals_limit

        processed_count = 0
        withdrawals: list[Withdrawal] = []
        for pending_withdrawal in state.pending_partial_withdrawals:
            running_withdrawals = [*list(prior_withdrawals), *withdrawals]
            is_withdrawable = pending_withdrawal.withdrawable_epoch <= epoch
            has_reached_limit = len(running_withdrawals) >= withdrawals_limit
            if not is_withdrawable or has_reached_limit:
                break
            validator_index = pending_withdrawal.validator_index
            validator = state.validators[int(validator_index)]
            balance = self.get_balance_after_withdrawals(
                state, validator_index, running_withdrawals
            )
            if self.is_eligible_for_partial_withdrawals(validator, balance):
                withdrawal_amount = min(
                    int(balance) - int(MIN_ACTIVATION_BALANCE), int(pending_withdrawal.amount)
                )
                withdrawals.append(
                    Withdrawal(
                        index=withdrawal_index,
                        validator_index=validator_index,
                        address=ExecutionAddress(bytes(validator.withdrawal_credentials)[12:]),
                        amount=Gwei(withdrawal_amount),
                    )
                )
                withdrawal_index = WithdrawalIndex(int(withdrawal_index) + 1)
            processed_count += 1
        return withdrawals, withdrawal_index, Uint64(processed_count)

    def get_validators_sweep_withdrawals(
        self,
        state: BeaconState,
        withdrawal_index: WithdrawalIndex,
        prior_withdrawals: Sequence[Withdrawal],
    ) -> tuple[list[Withdrawal], WithdrawalIndex, Uint64]:
        """Sweep validators past the saved cursor for full and excess-balance withdrawals."""
        epoch = self.get_current_epoch(state)
        validators_limit = min(len(state.validators), int(MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP))
        withdrawals_limit = int(MAX_WITHDRAWALS_PER_PAYLOAD)
        # At least one payload slot must remain free for the validator sweep.
        assert len(prior_withdrawals) < withdrawals_limit

        processed_count = 0
        withdrawals: list[Withdrawal] = []
        validator_index = int(state.next_withdrawal_validator_index)
        for _ in range(validators_limit):
            if len(prior_withdrawals) + len(withdrawals) >= withdrawals_limit:
                break
            validator = state.validators[validator_index]
            balance = self.get_balance_after_withdrawals(
                state, ValidatorIndex(validator_index), [*list(prior_withdrawals), *withdrawals]
            )
            withdrawal_address = ExecutionAddress(bytes(validator.withdrawal_credentials)[12:])
            if self.is_fully_withdrawable_validator(validator, balance, epoch):
                withdrawals.append(
                    Withdrawal(
                        index=withdrawal_index,
                        validator_index=ValidatorIndex(validator_index),
                        address=withdrawal_address,
                        amount=balance,
                    )
                )
                withdrawal_index = WithdrawalIndex(int(withdrawal_index) + 1)
            elif self.is_partially_withdrawable_validator(validator, balance):
                withdrawals.append(
                    Withdrawal(
                        index=withdrawal_index,
                        validator_index=ValidatorIndex(validator_index),
                        address=withdrawal_address,
                        amount=Gwei(int(balance) - int(self.get_max_effective_balance(validator))),
                    )
                )
                withdrawal_index = WithdrawalIndex(int(withdrawal_index) + 1)
            validator_index = (validator_index + 1) % len(state.validators)
            processed_count += 1
        return withdrawals, withdrawal_index, Uint64(processed_count)

    def get_expected_withdrawals(self, state: BeaconState) -> ExpectedWithdrawals:
        """Build the full ordered withdrawal sweep and each stage's processed count."""
        withdrawal_index = state.next_withdrawal_index
        withdrawals: list[Withdrawal] = []

        builder_withdrawals, withdrawal_index, processed_builder_withdrawals_count = (
            self.get_builder_withdrawals(state, withdrawal_index, withdrawals)
        )
        withdrawals.extend(builder_withdrawals)

        partial_withdrawals, withdrawal_index, processed_partial_withdrawals_count = (
            self.get_pending_partial_withdrawals(state, withdrawal_index, withdrawals)
        )
        withdrawals.extend(partial_withdrawals)

        builders_sweep_withdrawals, withdrawal_index, processed_builders_sweep_count = (
            self.get_builders_sweep_withdrawals(state, withdrawal_index, withdrawals)
        )
        withdrawals.extend(builders_sweep_withdrawals)

        validators_sweep_withdrawals, withdrawal_index, processed_sweep_withdrawals_count = (
            self.get_validators_sweep_withdrawals(state, withdrawal_index, withdrawals)
        )
        withdrawals.extend(validators_sweep_withdrawals)

        return ExpectedWithdrawals(
            withdrawals=withdrawals,
            processed_builder_withdrawals_count=processed_builder_withdrawals_count,
            processed_partial_withdrawals_count=processed_partial_withdrawals_count,
            processed_builders_sweep_count=processed_builders_sweep_count,
            processed_sweep_withdrawals_count=processed_sweep_withdrawals_count,
        )

    def get_ptc(self, state: BeaconState, slot: Slot) -> PtcWindowElement:
        """Return the payload timeliness committee cached for a slot in the window."""
        epoch = self.compute_epoch_at_slot(slot)
        state_epoch = self.get_current_epoch(state)
        slot_offset_in_epoch = int(slot) % _SLOTS_PER_EPOCH
        # The window stores one epoch behind, the current epoch, and the lookahead epochs.
        if int(epoch) < int(state_epoch):
            assert int(epoch) + 1 == int(state_epoch)
            return state.ptc_window[slot_offset_in_epoch]
        assert int(epoch) <= int(state_epoch) + _MIN_SEED_LOOKAHEAD
        window_offset = (int(epoch) - int(state_epoch) + 1) * _SLOTS_PER_EPOCH
        return state.ptc_window[window_offset + slot_offset_in_epoch]

    def get_indexed_payload_attestation(
        self, state: BeaconState, payload_attestation: PayloadAttestation
    ) -> IndexedPayloadAttestation:
        """Return the indexed form of a payload attestation, resolved against its committee."""
        payload_timeliness_committee = self.get_ptc(state, payload_attestation.data.slot)
        aggregation_bits = payload_attestation.aggregation_bits
        attesting_indices = [
            validator_index
            for committee_position, validator_index in enumerate(payload_timeliness_committee)
            if aggregation_bits.data[committee_position]
        ]
        return IndexedPayloadAttestation(
            attesting_indices=IndexedpayloadattestationAttestingIndices(
                data=sorted(attesting_indices)
            ),
            data=payload_attestation.data,
            signature=payload_attestation.signature,
        )

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
