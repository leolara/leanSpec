"""
State mutators in the immutable lstar style.

Each function returns a new state through functional copies rather than mutating
in place. Balance and validator edits rebuild the affected collection; the
exit-churn helpers also return the queue epoch they computed.
"""

from lean_spec.spec.forks.gloas.accessors import (
    compute_activation_exit_epoch,
    get_beacon_proposer_index,
    get_current_epoch,
    get_total_active_balance,
)
from lean_spec.spec.forks.gloas.config import (
    CHURN_LIMIT_QUOTIENT_GLOAS,
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
)
from lean_spec.spec.forks.gloas.constants import (
    FAR_FUTURE_EPOCH,
    PROPOSER_WEIGHT,
    WEIGHT_DENOMINATOR,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Balances,
    BeaconState,
    Slashings,
    Validator,
    Validators,
)
from lean_spec.spec.forks.gloas.containers.primitives import Epoch, Gwei, ValidatorIndex
from lean_spec.spec.forks.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
)
from lean_spec.spec.ssz import Boolean


def replace_validator(state: BeaconState, index: int, validator: Validator) -> BeaconState:
    """Return a state whose validator at the index is replaced."""
    updated = list(state.validators)
    updated[index] = validator
    return state.model_copy(update={"validators": Validators(data=updated)})


def increase_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> BeaconState:
    """Return a state with the balance at the index increased by the delta."""
    balances = list(state.balances)
    position = int(index)
    balances[position] = Gwei(int(balances[position]) + int(delta))
    return state.model_copy(update={"balances": Balances(data=balances)})


def decrease_balance(state: BeaconState, index: ValidatorIndex, delta: Gwei) -> BeaconState:
    """Return a state with the balance at the index decreased, floored at zero."""
    balances = list(state.balances)
    position = int(index)
    current = int(balances[position])
    balances[position] = Gwei(0 if int(delta) > current else current - int(delta))
    return state.model_copy(update={"balances": Balances(data=balances)})


def get_exit_churn_limit(state: BeaconState) -> Gwei:
    """Return the per-epoch exit churn, rounded down to a balance increment."""
    churn = max(
        int(MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA),
        int(get_total_active_balance(state)) // int(CHURN_LIMIT_QUOTIENT_GLOAS),
    )
    return Gwei(churn - churn % int(EFFECTIVE_BALANCE_INCREMENT))


def compute_exit_epoch_and_update_churn(
    state: BeaconState, exit_balance: Gwei
) -> tuple[BeaconState, Epoch]:
    """
    Reserve exit churn for a balance and return the updated state and exit epoch.

    Exits are spread across epochs so that no epoch sheds more than the churn
    limit. The reserved balance and the earliest exit epoch are carried in state.
    """
    earliest_exit_epoch = max(
        int(state.earliest_exit_epoch),
        int(compute_activation_exit_epoch(get_current_epoch(state))),
    )
    per_epoch_churn = int(get_exit_churn_limit(state))
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


def initiate_validator_exit(state: BeaconState, index: ValidatorIndex) -> BeaconState:
    """Return a state with the validator's exit queued, or unchanged if already exiting."""
    validator = state.validators[int(index)]
    if validator.exit_epoch != FAR_FUTURE_EPOCH:
        return state
    state, exit_queue_epoch = compute_exit_epoch_and_update_churn(
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
    return replace_validator(state, int(index), exited_validator)


def slash_validator(
    state: BeaconState,
    slashed_index: ValidatorIndex,
    whistleblower_index: ValidatorIndex | None = None,
) -> BeaconState:
    """Return a state with the validator slashed, penalized, and the reward paid out."""
    epoch = get_current_epoch(state)
    state = initiate_validator_exit(state, slashed_index)

    validator = state.validators[int(slashed_index)]
    slashed_validator = validator.model_copy(
        update={
            "slashed": Boolean(True),
            "withdrawable_epoch": Epoch(
                max(
                    int(validator.withdrawable_epoch), int(epoch) + int(EPOCHS_PER_SLASHINGS_VECTOR)
                )
            ),
        }
    )
    state = replace_validator(state, int(slashed_index), slashed_validator)

    slashings = list(state.slashings)
    slashing_slot = int(epoch) % int(EPOCHS_PER_SLASHINGS_VECTOR)
    slashings[slashing_slot] = Gwei(
        int(slashings[slashing_slot]) + int(slashed_validator.effective_balance)
    )
    state = state.model_copy(update={"slashings": Slashings(data=slashings)})

    slashing_penalty = Gwei(
        int(slashed_validator.effective_balance) // int(MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA)
    )
    state = decrease_balance(state, slashed_index, slashing_penalty)

    proposer_index = get_beacon_proposer_index(state)
    rewarded_whistleblower = proposer_index if whistleblower_index is None else whistleblower_index
    whistleblower_reward = Gwei(
        int(slashed_validator.effective_balance) // int(WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA)
    )
    proposer_reward = Gwei(
        int(whistleblower_reward) * int(PROPOSER_WEIGHT) // int(WEIGHT_DENOMINATOR)
    )
    state = increase_balance(state, proposer_index, proposer_reward)
    return increase_balance(
        state, rewarded_whistleblower, Gwei(int(whistleblower_reward) - int(proposer_reward))
    )
