"""
State mutators in the immutable lstar style.

Each function returns a new state through functional copies rather than mutating
in place. Balance and validator edits rebuild the affected collection; the
exit-churn helpers also return the queue epoch they computed.
"""

from collections.abc import Sequence

from lean_spec.spec.forks.gloas.config import (
    CHURN_LIMIT_QUOTIENT_GLOAS,
    CONSOLIDATION_CHURN_LIMIT_QUOTIENT,
    MIN_BUILDER_WITHDRAWABILITY_DELAY,
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
)
from lean_spec.spec.forks.gloas.constants import (
    COMPOUNDING_WITHDRAWAL_PREFIX,
    FAR_FUTURE_EPOCH,
    G2_POINT_AT_INFINITY,
    GENESIS_SLOT,
    PROPOSER_WEIGHT,
    WEIGHT_DENOMINATOR,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Balances,
    BeaconState,
    Builder,
    BuilderPendingPayment,
    BuilderPendingPayments,
    BuilderPendingWithdrawal,
    BuilderPendingWithdrawals,
    Builders,
    ExecutionPayloadAvailability,
    ExecutionRequests,
    PayloadExpectedWithdrawals,
    PendingDeposit,
    PendingDeposits,
    PendingPartialWithdrawals,
    Slashings,
    Validator,
    Validators,
    Withdrawal,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BLSPubkey,
    BLSSignature,
    BuilderIndex,
    Epoch,
    ExecutionAddress,
    Gwei,
    Slot,
    ValidatorIndex,
    WithdrawalIndex,
)
from lean_spec.spec.forks.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
    MAX_WITHDRAWALS_PER_PAYLOAD,
    MIN_ACTIVATION_BALANCE,
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Boolean, Bytes32, Uint8, Uint64

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)


class MutatorMixin(GloasSpecBase):
    """Mutator behavior for the Gloas spec."""

    def replace_validator(
        self, state: BeaconState, index: int, validator: Validator
    ) -> BeaconState:
        """Return a state whose validator at the index is replaced."""
        updated = list(state.validators)
        updated[index] = validator
        return state.model_copy(update={"validators": Validators(data=updated)})

    def increase_balance(
        self, state: BeaconState, index: ValidatorIndex, delta: Gwei
    ) -> BeaconState:
        """Return a state with the balance at the index increased by the delta."""
        balances = list(state.balances)
        position = int(index)
        balances[position] = Gwei(int(balances[position]) + int(delta))
        return state.model_copy(update={"balances": Balances(data=balances)})

    def decrease_balance(
        self, state: BeaconState, index: ValidatorIndex, delta: Gwei
    ) -> BeaconState:
        """Return a state with the balance at the index decreased, floored at zero."""
        balances = list(state.balances)
        position = int(index)
        current = int(balances[position])
        balances[position] = Gwei(0 if int(delta) > current else current - int(delta))
        return state.model_copy(update={"balances": Balances(data=balances)})

    def get_exit_churn_limit(self, state: BeaconState) -> Gwei:
        """Return the per-epoch exit churn, rounded down to a balance increment."""
        churn = max(
            int(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA),
            int(self.get_total_active_balance(state)) // int(CHURN_LIMIT_QUOTIENT_GLOAS),
        )
        return Gwei(churn - churn % int(EFFECTIVE_BALANCE_INCREMENT))

    def compute_exit_epoch_and_update_churn(
        self, state: BeaconState, exit_balance: Gwei
    ) -> tuple[BeaconState, Epoch]:
        """
        Reserve exit churn for a balance and return the updated state and exit epoch.

        Exits are spread across epochs so that no epoch sheds more than the churn
        limit. The reserved balance and the earliest exit epoch are carried in state.
        """
        earliest_exit_epoch = max(
            int(state.earliest_exit_epoch),
            int(self.compute_activation_exit_epoch(self.get_current_epoch(state))),
        )
        per_epoch_churn = int(self.get_exit_churn_limit(state))
        if int(state.earliest_exit_epoch) < earliest_exit_epoch:
            exit_balance_to_consume = per_epoch_churn
        else:
            exit_balance_to_consume = int(state.exit_balance_to_consume)

        requested = int(exit_balance)
        if requested > exit_balance_to_consume:
            balance_to_process = requested - exit_balance_to_consume
            additional_epochs = (balance_to_process - 1) // per_epoch_churn + 1
            earliest_exit_epoch += additional_epochs
            exit_balance_to_consume += additional_epochs * per_epoch_churn

        new_state = state.model_copy(
            update={
                "exit_balance_to_consume": Gwei(exit_balance_to_consume - requested),
                "earliest_exit_epoch": Epoch(earliest_exit_epoch),
            }
        )
        return new_state, Epoch(earliest_exit_epoch)

    def initiate_validator_exit(self, state: BeaconState, index: ValidatorIndex) -> BeaconState:
        """Return a state with the validator's exit queued, or unchanged if already exiting."""
        validator = state.validators[int(index)]
        if validator.exit_epoch != FAR_FUTURE_EPOCH:
            return state
        state, exit_queue_epoch = self.compute_exit_epoch_and_update_churn(
            state, validator.effective_balance
        )
        exited_validator = validator.model_copy(
            update={
                "exit_epoch": exit_queue_epoch,
                "withdrawable_epoch": Epoch(
                    int(exit_queue_epoch) + int(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
                ),
            }
        )
        return self.replace_validator(state, int(index), exited_validator)

    def get_consolidation_churn_limit(self, state: BeaconState) -> Gwei:
        """Return the per-epoch consolidation churn, rounded down to a balance increment."""
        churn = int(self.get_total_active_balance(state)) // int(CONSOLIDATION_CHURN_LIMIT_QUOTIENT)
        return Gwei(churn - churn % int(EFFECTIVE_BALANCE_INCREMENT))

    def compute_consolidation_epoch_and_update_churn(
        self, state: BeaconState, consolidation_balance: Gwei
    ) -> tuple[BeaconState, Epoch]:
        """Reserve consolidation churn for a balance and return the state and exit epoch."""
        earliest_consolidation_epoch = max(
            int(state.earliest_consolidation_epoch),
            int(self.compute_activation_exit_epoch(self.get_current_epoch(state))),
        )
        per_epoch_churn = int(self.get_consolidation_churn_limit(state))
        if int(state.earliest_consolidation_epoch) < earliest_consolidation_epoch:
            balance_to_consume = per_epoch_churn
        else:
            balance_to_consume = int(state.consolidation_balance_to_consume)

        requested = int(consolidation_balance)
        if requested > balance_to_consume:
            balance_to_process = requested - balance_to_consume
            additional_epochs = (balance_to_process - 1) // per_epoch_churn + 1
            earliest_consolidation_epoch += additional_epochs
            balance_to_consume += additional_epochs * per_epoch_churn

        new_state = state.model_copy(
            update={
                "consolidation_balance_to_consume": Gwei(balance_to_consume - requested),
                "earliest_consolidation_epoch": Epoch(earliest_consolidation_epoch),
            }
        )
        return new_state, Epoch(earliest_consolidation_epoch)

    def queue_excess_active_balance(self, state: BeaconState, index: ValidatorIndex) -> BeaconState:
        """
        Return a state with a validator's balance above the activation floor queued.

        The excess becomes a pending deposit so a switch to compounding does not lose
        the over-staked balance.
        """
        balance = int(state.balances[int(index)])
        if balance <= int(MIN_ACTIVATION_BALANCE):
            return state
        excess_balance = balance - int(MIN_ACTIVATION_BALANCE)
        balances = list(state.balances)
        balances[int(index)] = Gwei(int(MIN_ACTIVATION_BALANCE))
        state = state.model_copy(update={"balances": Balances(data=balances)})
        validator = state.validators[int(index)]
        pending_deposit = PendingDeposit(
            public_key=validator.public_key,
            withdrawal_credentials=validator.withdrawal_credentials,
            amount=Gwei(excess_balance),
            signature=G2_POINT_AT_INFINITY,
            slot=GENESIS_SLOT,
        )
        queued = [*list(state.pending_deposits), pending_deposit]
        return state.model_copy(update={"pending_deposits": PendingDeposits(data=queued)})

    def switch_to_compounding_validator(
        self, state: BeaconState, index: ValidatorIndex
    ) -> BeaconState:
        """Return a state with a validator switched to compounding credentials."""
        validator = state.validators[int(index)]
        new_credentials = Bytes32(
            bytes(COMPOUNDING_WITHDRAWAL_PREFIX) + bytes(validator.withdrawal_credentials)[1:]
        )
        updated_validator = validator.model_copy(update={"withdrawal_credentials": new_credentials})
        state = self.replace_validator(state, int(index), updated_validator)
        return self.queue_excess_active_balance(state, index)

    def initiate_builder_exit(self, state: BeaconState, builder_index: BuilderIndex) -> BeaconState:
        """Return a state with the builder's withdrawable epoch scheduled."""
        builder = state.builders[int(builder_index)]
        withdrawable_epoch = Epoch(
            int(self.get_current_epoch(state)) + int(MIN_BUILDER_WITHDRAWABILITY_DELAY)
        )
        updated_builder = builder.model_copy(update={"withdrawable_epoch": withdrawable_epoch})
        builders = list(state.builders)
        builders[int(builder_index)] = updated_builder
        return state.model_copy(update={"builders": Builders(data=builders)})

    def slash_validator(
        self,
        state: BeaconState,
        slashed_index: ValidatorIndex,
        whistleblower_index: ValidatorIndex | None = None,
    ) -> BeaconState:
        """Return a state with the validator slashed, penalized, and the reward paid out."""
        epoch = self.get_current_epoch(state)
        state = self.initiate_validator_exit(state, slashed_index)

        validator = state.validators[int(slashed_index)]
        slashed_validator = validator.model_copy(
            update={
                "slashed": Boolean(True),
                "withdrawable_epoch": Epoch(
                    max(
                        int(validator.withdrawable_epoch),
                        int(epoch) + int(EPOCHS_PER_SLASHINGS_VECTOR),
                    )
                ),
            }
        )
        state = self.replace_validator(state, int(slashed_index), slashed_validator)

        slashings = list(state.slashings)
        slashing_slot = int(epoch) % int(EPOCHS_PER_SLASHINGS_VECTOR)
        slashings[slashing_slot] = Gwei(
            int(slashings[slashing_slot]) + int(slashed_validator.effective_balance)
        )
        state = state.model_copy(update={"slashings": Slashings(data=slashings)})

        slashing_penalty = Gwei(
            int(slashed_validator.effective_balance) // int(MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA)
        )
        state = self.decrease_balance(state, slashed_index, slashing_penalty)

        proposer_index = self.get_beacon_proposer_index(state)
        rewarded_whistleblower = (
            proposer_index if whistleblower_index is None else whistleblower_index
        )
        whistleblower_reward = Gwei(
            int(slashed_validator.effective_balance) // int(WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA)
        )
        proposer_reward = Gwei(
            int(whistleblower_reward) * int(PROPOSER_WEIGHT) // int(WEIGHT_DENOMINATOR)
        )
        state = self.increase_balance(state, proposer_index, proposer_reward)
        return self.increase_balance(
            state, rewarded_whistleblower, Gwei(int(whistleblower_reward) - int(proposer_reward))
        )

    def add_builder_to_registry(
        self,
        state: BeaconState,
        public_key: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        slot: Slot,
    ) -> BeaconState:
        """Return a state with a new builder placed in a reusable or freshly appended slot."""
        credentials = bytes(withdrawal_credentials)
        new_builder = Builder(
            public_key=public_key,
            version=Uint8(credentials[0]),
            execution_address=ExecutionAddress(credentials[12:]),
            balance=amount,
            deposit_epoch=self.compute_epoch_at_slot(slot),
            withdrawable_epoch=FAR_FUTURE_EPOCH,
        )
        builders = list(state.builders)
        # Builder indices are reusable: an exited, fully-withdrawn slot is overwritten,
        # otherwise the registry grows by one.
        new_builder_index = int(self.get_index_for_new_builder(state))
        if new_builder_index < len(builders):
            builders[new_builder_index] = new_builder
        else:
            builders.append(new_builder)
        return state.model_copy(update={"builders": Builders(data=builders)})

    def apply_deposit_for_builder(
        self,
        state: BeaconState,
        public_key: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
        slot: Slot,
    ) -> BeaconState:
        """Register a new builder from a valid deposit, or top up an existing one."""
        builder_public_keys = [builder.public_key for builder in state.builders]
        if public_key not in builder_public_keys:
            if self.is_valid_deposit_signature(
                public_key, withdrawal_credentials, amount, signature
            ):
                return self.add_builder_to_registry(
                    state, public_key, withdrawal_credentials, amount, slot
                )
            return state
        builder_index = builder_public_keys.index(public_key)
        builders = list(state.builders)
        topped_up = builders[builder_index].model_copy(
            update={"balance": Gwei(int(builders[builder_index].balance) + int(amount))}
        )
        builders[builder_index] = topped_up
        return state.model_copy(update={"builders": Builders(data=builders)})

    def apply_withdrawals(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Deduct each withdrawal from its builder or validator balance."""
        for withdrawal in withdrawals:
            if self.is_builder_index(withdrawal.validator_index):
                builder_index = int(
                    self.convert_validator_index_to_builder_index(withdrawal.validator_index)
                )
                builders = list(state.builders)
                builder = builders[builder_index]
                # A builder balance cannot go negative, so clamp the deduction to it.
                deduction = min(int(withdrawal.amount), int(builder.balance))
                builders[builder_index] = builder.model_copy(
                    update={"balance": Gwei(int(builder.balance) - deduction)}
                )
                state = state.model_copy(update={"builders": Builders(data=builders)})
            else:
                state = self.decrease_balance(state, withdrawal.validator_index, withdrawal.amount)
        return state

    def update_next_withdrawal_index(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Advance the next withdrawal index past the last withdrawal in the block."""
        if len(withdrawals) == 0:
            return state
        latest_withdrawal = withdrawals[-1]
        return state.model_copy(
            update={"next_withdrawal_index": WithdrawalIndex(int(latest_withdrawal.index) + 1)}
        )

    def update_payload_expected_withdrawals(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Record the withdrawals the next execution payload must honor."""
        return state.model_copy(
            update={
                "payload_expected_withdrawals": PayloadExpectedWithdrawals(data=list(withdrawals))
            }
        )

    def update_builder_pending_withdrawals(
        self, state: BeaconState, processed_builder_withdrawals_count: Uint64
    ) -> BeaconState:
        """Drop the builder pending withdrawals consumed by this block from the front."""
        remaining = list(state.builder_pending_withdrawals)[
            int(processed_builder_withdrawals_count) :
        ]
        return state.model_copy(
            update={"builder_pending_withdrawals": BuilderPendingWithdrawals(data=remaining)}
        )

    def update_pending_partial_withdrawals(
        self, state: BeaconState, processed_partial_withdrawals_count: Uint64
    ) -> BeaconState:
        """Drop the pending partial withdrawals consumed by this block from the front."""
        remaining = list(state.pending_partial_withdrawals)[
            int(processed_partial_withdrawals_count) :
        ]
        return state.model_copy(
            update={"pending_partial_withdrawals": PendingPartialWithdrawals(data=remaining)}
        )

    def update_next_withdrawal_builder_index(
        self, state: BeaconState, processed_builders_sweep_count: Uint64
    ) -> BeaconState:
        """Advance the builder sweep cursor past the builders this block swept."""
        if len(state.builders) == 0:
            return state
        next_index = int(state.next_withdrawal_builder_index) + int(processed_builders_sweep_count)
        return state.model_copy(
            update={"next_withdrawal_builder_index": BuilderIndex(next_index % len(state.builders))}
        )

    def update_next_withdrawal_validator_index(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Advance the validator sweep cursor for the next block."""
        # A full payload resumes right after the last swept validator;
        # a partial sweep advances by the fixed sweep span instead.
        if len(withdrawals) == int(MAX_WITHDRAWALS_PER_PAYLOAD):
            next_validator_index = ValidatorIndex(
                (int(withdrawals[-1].validator_index) + 1) % len(state.validators)
            )
        else:
            next_index = int(state.next_withdrawal_validator_index) + int(
                MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP
            )
            next_validator_index = ValidatorIndex(next_index % len(state.validators))
        return state.model_copy(update={"next_withdrawal_validator_index": next_validator_index})

    def settle_builder_payment(self, state: BeaconState, payment_index: int) -> BeaconState:
        """Convert a slot's pending builder payment into a queued withdrawal and clear it."""
        assert payment_index < len(state.builder_pending_payments)
        payment = state.builder_pending_payments[payment_index]
        if int(payment.withdrawal.amount) > 0:
            withdrawals = [*list(state.builder_pending_withdrawals), payment.withdrawal]
            state = state.model_copy(
                update={"builder_pending_withdrawals": BuilderPendingWithdrawals(data=withdrawals)}
            )
        payments = list(state.builder_pending_payments)
        payments[payment_index] = BuilderPendingPayment.decode_bytes(
            b"\x00" * BuilderPendingPayment.get_byte_length()
        )
        return state.model_copy(
            update={"builder_pending_payments": BuilderPendingPayments(data=payments)}
        )

    def apply_parent_execution_payload(
        self, state: BeaconState, requests: ExecutionRequests
    ) -> BeaconState:
        """Process the parent payload's requests, settle its payment, and mark it available."""
        parent_bid = state.latest_execution_payload_bid
        parent_slot = parent_bid.slot
        parent_epoch = self.compute_epoch_at_slot(parent_slot)

        # The parent's execution requests are processed at the child's slot.
        for deposit_request in requests.deposits:
            state = self.process_deposit_request(state, deposit_request)
        for withdrawal_request in requests.withdrawals:
            state = self.process_withdrawal_request(state, withdrawal_request)
        for consolidation_request in requests.consolidations:
            state = self.process_consolidation_request(state, consolidation_request)

        # Settle the parent's builder payment from its slot's window entry while it is
        # still in the two-epoch window, else queue the withdrawal directly.
        if parent_epoch == self.get_current_epoch(state):
            state = self.settle_builder_payment(
                state, _SLOTS_PER_EPOCH + int(parent_slot) % _SLOTS_PER_EPOCH
            )
        elif parent_epoch == self.get_previous_epoch(state):
            state = self.settle_builder_payment(state, int(parent_slot) % _SLOTS_PER_EPOCH)
        elif int(parent_bid.value) > 0:
            withdrawals = [
                *list(state.builder_pending_withdrawals),
                BuilderPendingWithdrawal(
                    fee_recipient=parent_bid.fee_recipient,
                    amount=parent_bid.value,
                    builder_index=parent_bid.builder_index,
                ),
            ]
            state = state.model_copy(
                update={"builder_pending_withdrawals": BuilderPendingWithdrawals(data=withdrawals)}
            )

        availability = list(state.execution_payload_availability.data)
        availability[int(parent_slot) % _SLOTS_PER_HISTORICAL_ROOT] = Boolean(True)
        return state.model_copy(
            update={
                "execution_payload_availability": ExecutionPayloadAvailability(data=availability),
                "latest_block_hash": parent_bid.block_hash,
            }
        )
