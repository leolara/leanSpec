"""
Per-epoch state transitions in the immutable lstar style.

Each function applies one epoch sub-transition and returns a new state through
functional copies rather than mutating in place. The sub-transitions run in a
fixed order at the epoch boundary; here each is a standalone method so the
consensus vectors can exercise it in isolation.
"""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    BeaconState,
    CurrentEpochParticipation,
    Eth1DataVotes,
    HistoricalSummaries,
    HistoricalSummary,
    PreviousEpochParticipation,
    RandaoMixes,
    Slashings,
    Validators,
)
from lean_spec.spec.forks.gloas.containers.primitives import Gwei, ParticipationFlags, Root
from lean_spec.spec.forks.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_ETH1_VOTING_PERIOD,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    HYSTERESIS_DOWNWARD_MULTIPLIER,
    HYSTERESIS_QUOTIENT,
    HYSTERESIS_UPWARD_MULTIPLIER,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase

_EPOCHS_PER_SLASHINGS_VECTOR = int(EPOCHS_PER_SLASHINGS_VECTOR)
_EPOCHS_PER_HISTORICAL_VECTOR = int(EPOCHS_PER_HISTORICAL_VECTOR)
_EPOCHS_PER_ETH1_VOTING_PERIOD = int(EPOCHS_PER_ETH1_VOTING_PERIOD)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)
_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)


class EpochMixin(GloasSpecBase):
    """Per-epoch transition behavior for the Gloas spec."""

    def process_eth1_data_reset(self, state: BeaconState) -> BeaconState:
        """Clear the eth1 data vote tally at the end of each voting period."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        if next_epoch % _EPOCHS_PER_ETH1_VOTING_PERIOD == 0:
            return state.model_copy(update={"eth1_data_votes": Eth1DataVotes(data=[])})
        return state

    def process_slashings_reset(self, state: BeaconState) -> BeaconState:
        """Clear the slashing total for the epoch slot about to be reused."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        slashings = list(state.slashings)
        slashings[next_epoch % _EPOCHS_PER_SLASHINGS_VECTOR] = Gwei(0)
        return state.model_copy(update={"slashings": Slashings(data=slashings)})

    def process_randao_mixes_reset(self, state: BeaconState) -> BeaconState:
        """Carry the current epoch's randao mix into the slot the next epoch will reuse."""
        current_epoch = self.get_current_epoch(state)
        next_epoch = int(current_epoch) + 1
        randao_mixes = list(state.randao_mixes)
        randao_mixes[next_epoch % _EPOCHS_PER_HISTORICAL_VECTOR] = self.get_randao_mix(
            state, current_epoch
        )
        return state.model_copy(update={"randao_mixes": RandaoMixes(data=randao_mixes)})

    def process_participation_flag_updates(self, state: BeaconState) -> BeaconState:
        """Rotate current-epoch participation into previous and zero the new current epoch."""
        fresh_participation = [ParticipationFlags(0) for _ in range(len(state.validators))]
        return state.model_copy(
            update={
                "previous_epoch_participation": PreviousEpochParticipation(
                    data=list(state.current_epoch_participation)
                ),
                "current_epoch_participation": CurrentEpochParticipation(data=fresh_participation),
            }
        )

    def process_historical_summaries_update(self, state: BeaconState) -> BeaconState:
        """Accumulate a historical summary of block and state roots once per accumulation period."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        accumulation_period = _SLOTS_PER_HISTORICAL_ROOT // _SLOTS_PER_EPOCH
        if next_epoch % accumulation_period == 0:
            historical_summary = HistoricalSummary(
                block_summary_root=Root(hash_tree_root(state.block_roots)),
                state_summary_root=Root(hash_tree_root(state.state_roots)),
            )
            summaries = [*list(state.historical_summaries), historical_summary]
            return state.model_copy(
                update={"historical_summaries": HistoricalSummaries(data=summaries)}
            )
        return state

    def process_effective_balance_updates(self, state: BeaconState) -> BeaconState:
        """Recompute effective balances with hysteresis to damp churn around the boundary."""
        hysteresis_increment = int(EFFECTIVE_BALANCE_INCREMENT) // int(HYSTERESIS_QUOTIENT)
        downward_threshold = hysteresis_increment * int(HYSTERESIS_DOWNWARD_MULTIPLIER)
        upward_threshold = hysteresis_increment * int(HYSTERESIS_UPWARD_MULTIPLIER)
        increment = int(EFFECTIVE_BALANCE_INCREMENT)

        validators = list(state.validators)
        changed = False
        for validator_index, validator in enumerate(validators):
            balance = int(state.balances[validator_index])
            effective_balance = int(validator.effective_balance)
            max_effective_balance = int(self.get_max_effective_balance(validator))
            # Only restep the effective balance when the live balance drifts past the band.
            if (
                balance + downward_threshold < effective_balance
                or effective_balance + upward_threshold < balance
            ):
                new_effective_balance = min(balance - balance % increment, max_effective_balance)
                validators[validator_index] = validator.model_copy(
                    update={"effective_balance": Gwei(new_effective_balance)}
                )
                changed = True
        if not changed:
            return state
        return state.model_copy(update={"validators": Validators(data=validators)})
