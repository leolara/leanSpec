"""
State mutators in the immutable lstar style.

Each function returns a new state through functional copies rather than mutating
in place. Balance and validator edits rebuild the affected collection; the
exit-churn helpers also return the queue epoch they computed.
"""

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
    Builders,
    PendingDeposit,
    PendingDeposits,
    Slashings,
    Validator,
    Validators,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BuilderIndex,
    Epoch,
    Gwei,
    ValidatorIndex,
)
from lean_spec.spec.forks.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MIN_ACTIVATION_BALANCE,
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Boolean, Bytes32


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
