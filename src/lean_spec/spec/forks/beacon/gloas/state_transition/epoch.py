"""
Per-epoch state transitions in the immutable lstar style.

Each function applies one epoch sub-transition and returns a new state through
functional copies rather than mutating in place. The sub-transitions run in a
fixed order at the epoch boundary; here each is a standalone method so the
consensus vectors can exercise it in isolation.
"""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.beacon.gloas.config import (
    EJECTION_BALANCE,
    INACTIVITY_SCORE_BIAS,
    INACTIVITY_SCORE_RECOVERY_RATE,
)
from lean_spec.spec.forks.beacon.gloas.constants import (
    FAR_FUTURE_EPOCH,
    GENESIS_EPOCH,
    JUSTIFICATION_BITS_LENGTH,
    PARTICIPATION_FLAG_WEIGHTS,
    TIMELY_HEAD_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX,
    WEIGHT_DENOMINATOR,
)
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import (
    Balances,
    BeaconState,
    BuilderPendingPayment,
    BuilderPendingPayments,
    BuilderPendingWithdrawals,
    Checkpoint,
    CurrentEpochParticipation,
    Eth1DataVotes,
    HistoricalSummaries,
    HistoricalSummary,
    InactivityScores,
    JustificationBits,
    PendingConsolidations,
    PendingDeposits,
    PreviousEpochParticipation,
    ProposerLookahead,
    PtcWindow,
    RandaoMixes,
    Slashings,
    Validators,
)
from lean_spec.spec.forks.beacon.gloas.containers.primitives import (
    Epoch,
    Gwei,
    ParticipationFlags,
    Root,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.beacon.gloas.preset import (
    EFFECTIVE_BALANCE_INCREMENT,
    EPOCHS_PER_ETH1_VOTING_PERIOD,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
    HYSTERESIS_DOWNWARD_MULTIPLIER,
    HYSTERESIS_QUOTIENT,
    HYSTERESIS_UPWARD_MULTIPLIER,
    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
    MAX_PENDING_DEPOSITS_PER_EPOCH,
    MIN_SEED_LOOKAHEAD,
    PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
)
from lean_spec.spec.forks.beacon.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Boolean, Uint64

_EPOCHS_PER_SLASHINGS_VECTOR = int(EPOCHS_PER_SLASHINGS_VECTOR)
_EPOCHS_PER_HISTORICAL_VECTOR = int(EPOCHS_PER_HISTORICAL_VECTOR)
_EPOCHS_PER_ETH1_VOTING_PERIOD = int(EPOCHS_PER_ETH1_VOTING_PERIOD)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)
_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_JUSTIFICATION_BITS_LENGTH = int(JUSTIFICATION_BITS_LENGTH)
_MIN_SEED_LOOKAHEAD = int(MIN_SEED_LOOKAHEAD)


class EpochMixin(GloasSpecBase):
    """Per-epoch transition behavior for the Gloas spec."""

    def process_epoch(self, state: BeaconState) -> BeaconState:
        """Run every per-epoch sub-transition in its fixed order at an epoch boundary."""
        state = self.process_justification_and_finalization(state)
        state = self.process_inactivity_updates(state)
        state = self.process_rewards_and_penalties(state)
        state = self.process_registry_updates(state)
        state = self.process_slashings(state)
        state = self.process_eth1_data_reset(state)
        state = self.process_pending_deposits(state)
        state = self.process_pending_consolidations(state)
        state = self.process_builder_pending_payments(state)
        state = self.process_effective_balance_updates(state)
        state = self.process_slashings_reset(state)
        state = self.process_randao_mixes_reset(state)
        state = self.process_historical_summaries_update(state)
        state = self.process_participation_flag_updates(state)
        state = self.process_sync_committee_updates(state)
        state = self.process_proposer_lookahead(state)
        return self.process_ptc_window(state)

    def weigh_justification_and_finalization(
        self,
        state: BeaconState,
        total_active_balance: Gwei,
        previous_epoch_target_balance: Gwei,
        current_epoch_target_balance: Gwei,
    ) -> BeaconState:
        """Justify epochs that reached the 2/3 target vote and finalize older justified chains."""
        previous_epoch = self.get_previous_epoch(state)
        current_epoch = self.get_current_epoch(state)
        old_previous_justified_checkpoint = state.previous_justified_checkpoint
        old_current_justified_checkpoint = state.current_justified_checkpoint

        # Shift the justification record one epoch older and clear the newest bit.
        current_justified_checkpoint = state.current_justified_checkpoint
        previous_bits = list(state.justification_bits.data)
        justification_bits = [Boolean(False), *previous_bits[: _JUSTIFICATION_BITS_LENGTH - 1]]

        # Threshold: a target balance of at least two-thirds of the active balance justifies.
        if int(previous_epoch_target_balance) * 3 >= int(total_active_balance) * 2:
            current_justified_checkpoint = Checkpoint(
                epoch=previous_epoch, root=self.get_block_root(state, previous_epoch)
            )
            justification_bits[1] = Boolean(True)
        if int(current_epoch_target_balance) * 3 >= int(total_active_balance) * 2:
            current_justified_checkpoint = Checkpoint(
                epoch=current_epoch, root=self.get_block_root(state, current_epoch)
            )
            justification_bits[0] = Boolean(True)

        # Finalize on the four classic source-to-target justification spans.
        finalized_checkpoint = state.finalized_checkpoint
        if all(justification_bits[1:4]) and (
            int(old_previous_justified_checkpoint.epoch) + 3 == int(current_epoch)
        ):
            finalized_checkpoint = old_previous_justified_checkpoint
        if all(justification_bits[1:3]) and (
            int(old_previous_justified_checkpoint.epoch) + 2 == int(current_epoch)
        ):
            finalized_checkpoint = old_previous_justified_checkpoint
        if all(justification_bits[0:3]) and (
            int(old_current_justified_checkpoint.epoch) + 2 == int(current_epoch)
        ):
            finalized_checkpoint = old_current_justified_checkpoint
        if all(justification_bits[0:2]) and (
            int(old_current_justified_checkpoint.epoch) + 1 == int(current_epoch)
        ):
            finalized_checkpoint = old_current_justified_checkpoint

        return state.model_copy(
            update={
                "previous_justified_checkpoint": old_current_justified_checkpoint,
                "current_justified_checkpoint": current_justified_checkpoint,
                "justification_bits": JustificationBits(data=justification_bits),
                "finalized_checkpoint": finalized_checkpoint,
            }
        )

    def process_justification_and_finalization(self, state: BeaconState) -> BeaconState:
        """Tally the target votes of the last two epochs and update justification and finality."""
        # The genesis checkpoint root is a stub, so skip the first two epochs.
        if int(self.get_current_epoch(state)) <= int(GENESIS_EPOCH) + 1:
            return state
        previous_indices = self.get_unslashed_participating_indices(
            state, TIMELY_TARGET_FLAG_INDEX, self.get_previous_epoch(state)
        )
        current_indices = self.get_unslashed_participating_indices(
            state, TIMELY_TARGET_FLAG_INDEX, self.get_current_epoch(state)
        )
        total_active_balance = self.get_total_active_balance(state)
        previous_target_balance = self.get_total_balance(state, previous_indices)
        current_target_balance = self.get_total_balance(state, current_indices)
        return self.weigh_justification_and_finalization(
            state, total_active_balance, previous_target_balance, current_target_balance
        )

    def process_inactivity_updates(self, state: BeaconState) -> BeaconState:
        """Raise inactivity scores for absent validators and recover them when not leaking."""
        # Scores reflect the previous epoch's participation, which is undefined at genesis.
        if self.get_current_epoch(state) == GENESIS_EPOCH:
            return state

        previous_target_indices = self.get_unslashed_participating_indices(
            state, TIMELY_TARGET_FLAG_INDEX, self.get_previous_epoch(state)
        )
        in_inactivity_leak = self.is_in_inactivity_leak(state)
        inactivity_scores = list(state.inactivity_scores)
        for validator_index in self.get_eligible_validator_indices(state):
            position = int(validator_index)
            score = int(inactivity_scores[position])
            if validator_index in previous_target_indices:
                score -= min(1, score)
            else:
                score += int(INACTIVITY_SCORE_BIAS)
            # A leak-free epoch recovers every eligible validator's score, not just attesters.
            if not in_inactivity_leak:
                score -= min(int(INACTIVITY_SCORE_RECOVERY_RATE), score)
            inactivity_scores[position] = Uint64(score)
        return state.model_copy(
            update={"inactivity_scores": InactivityScores(data=inactivity_scores)}
        )

    def get_flag_index_deltas(
        self, state: BeaconState, flag_index: int
    ) -> tuple[list[Gwei], list[Gwei]]:
        """Return the per-validator rewards and penalties for one timeliness flag."""
        rewards = [Gwei(0)] * len(state.validators)
        penalties = [Gwei(0)] * len(state.validators)
        previous_epoch = self.get_previous_epoch(state)
        unslashed_participating_indices = self.get_unslashed_participating_indices(
            state, flag_index, previous_epoch
        )
        weight = int(PARTICIPATION_FLAG_WEIGHTS[flag_index])
        unslashed_participating_increments = int(
            self.get_total_balance(state, unslashed_participating_indices)
        ) // int(EFFECTIVE_BALANCE_INCREMENT)
        active_increments = int(self.get_total_active_balance(state)) // int(
            EFFECTIVE_BALANCE_INCREMENT
        )
        in_inactivity_leak = self.is_in_inactivity_leak(state)
        for validator_index in self.get_eligible_validator_indices(state):
            position = int(validator_index)
            base_reward = int(self.get_base_reward(state, validator_index))
            if validator_index in unslashed_participating_indices:
                # During a leak no positive rewards are paid, only penalties accrue.
                if not in_inactivity_leak:
                    reward_numerator = base_reward * weight * unslashed_participating_increments
                    rewards[position] = Gwei(
                        int(rewards[position])
                        + reward_numerator // (active_increments * int(WEIGHT_DENOMINATOR))
                    )
            elif flag_index != TIMELY_HEAD_FLAG_INDEX:
                # A missed head is never penalized, since heads can be legitimately reorged.
                penalties[position] = Gwei(
                    int(penalties[position]) + base_reward * weight // int(WEIGHT_DENOMINATOR)
                )
        return rewards, penalties

    def get_inactivity_penalty_deltas(self, state: BeaconState) -> tuple[list[Gwei], list[Gwei]]:
        """Return the per-validator inactivity penalties scaled by each validator's score."""
        rewards = [Gwei(0)] * len(state.validators)
        penalties = [Gwei(0)] * len(state.validators)
        matching_target_indices = self.get_unslashed_participating_indices(
            state, TIMELY_TARGET_FLAG_INDEX, self.get_previous_epoch(state)
        )
        penalty_denominator = int(INACTIVITY_SCORE_BIAS) * int(
            INACTIVITY_PENALTY_QUOTIENT_BELLATRIX
        )
        for validator_index in self.get_eligible_validator_indices(state):
            position = int(validator_index)
            if validator_index not in matching_target_indices:
                penalty_numerator = int(state.validators[position].effective_balance) * int(
                    state.inactivity_scores[position]
                )
                penalties[position] = Gwei(
                    int(penalties[position]) + penalty_numerator // penalty_denominator
                )
        return rewards, penalties

    def process_rewards_and_penalties(self, state: BeaconState) -> BeaconState:
        """Apply the timeliness-flag and inactivity deltas to every validator's balance."""
        # Rewards are paid for the previous epoch's work, of which genesis has none.
        if self.get_current_epoch(state) == GENESIS_EPOCH:
            return state

        flag_deltas = [
            self.get_flag_index_deltas(state, flag_index)
            for flag_index in range(len(PARTICIPATION_FLAG_WEIGHTS))
        ]
        deltas = [*flag_deltas, self.get_inactivity_penalty_deltas(state)]

        # Fold every delta into a working balance list in order; a decrease floors at zero.
        balances = [int(balance) for balance in state.balances]
        for rewards, penalties in deltas:
            for validator_index in range(len(state.validators)):
                balances[validator_index] += int(rewards[validator_index])
                balances[validator_index] = max(
                    0, balances[validator_index] - int(penalties[validator_index])
                )
        return state.model_copy(
            update={"balances": Balances(data=[Gwei(balance) for balance in balances])}
        )

    def process_registry_updates(self, state: BeaconState) -> BeaconState:
        """Queue eligible validators, eject the underfunded, and activate the ready ones."""
        current_epoch = self.get_current_epoch(state)
        activation_epoch = self.compute_activation_exit_epoch(current_epoch)
        for validator_index in range(len(state.validators)):
            validator = state.validators[validator_index]
            if self.is_eligible_for_activation_queue(validator):
                state = self.replace_validator(
                    state,
                    validator_index,
                    validator.model_copy(
                        update={"activation_eligibility_epoch": Epoch(int(current_epoch) + 1)}
                    ),
                )
            elif (
                self.is_active_validator(validator, current_epoch)
                and validator.effective_balance <= EJECTION_BALANCE
            ):
                state = self.initiate_validator_exit(state, ValidatorIndex(validator_index))
            elif self.is_eligible_for_activation(state, validator):
                state = self.replace_validator(
                    state,
                    validator_index,
                    validator.model_copy(update={"activation_epoch": activation_epoch}),
                )
        return state

    def process_slashings(self, state: BeaconState) -> BeaconState:
        """Charge the correlated-slashing penalty to validators reaching their midpoint epoch."""
        epoch = self.get_current_epoch(state)
        total_balance = int(self.get_total_active_balance(state))
        # The aggregate slashed balance is scaled, then capped at the total active balance.
        adjusted_total_slashing_balance = min(
            sum(int(slashing) for slashing in state.slashings)
            * int(PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX),
            total_balance,
        )
        increment = int(EFFECTIVE_BALANCE_INCREMENT)
        penalty_per_effective_balance_increment = adjusted_total_slashing_balance // (
            total_balance // increment
        )
        midpoint_offset = _EPOCHS_PER_SLASHINGS_VECTOR // 2
        for validator_index in range(len(state.validators)):
            validator = state.validators[validator_index]
            if validator.slashed and (
                int(epoch) + midpoint_offset == int(validator.withdrawable_epoch)
            ):
                effective_balance_increments = int(validator.effective_balance) // increment
                penalty = penalty_per_effective_balance_increment * effective_balance_increments
                state = self.decrease_balance(state, ValidatorIndex(validator_index), Gwei(penalty))
        return state

    def process_pending_deposits(self, state: BeaconState) -> BeaconState:
        """Drain finalized pending deposits up to the activation churn and per-epoch cap."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        available_for_processing = int(state.deposit_balance_to_consume) + int(
            self.get_activation_churn_limit(state)
        )
        processed_amount = 0
        next_deposit_index = 0
        deposits_to_postpone = []
        is_churn_limit_reached = False
        finalized_slot = int(self.compute_start_slot_at_epoch(state.finalized_checkpoint.epoch))

        for deposit in state.pending_deposits:
            # Stop at the first unfinalized deposit, or once the per-epoch cap is hit.
            if int(deposit.slot) > finalized_slot:
                break
            if next_deposit_index >= int(MAX_PENDING_DEPOSITS_PER_EPOCH):
                break

            is_validator_exited = False
            is_validator_withdrawn = False
            validator_public_keys = [validator.public_key for validator in state.validators]
            if deposit.public_key in validator_public_keys:
                validator = state.validators[validator_public_keys.index(deposit.public_key)]
                is_validator_exited = int(validator.exit_epoch) < int(FAR_FUTURE_EPOCH)
                is_validator_withdrawn = int(validator.withdrawable_epoch) < next_epoch

            if is_validator_withdrawn:
                # A withdrawn validator can never reactivate, so credit without consuming churn.
                state = self.apply_pending_deposit(state, deposit)
            elif is_validator_exited:
                # An exiting validator's deposit waits until after it becomes withdrawable.
                deposits_to_postpone.append(deposit)
            else:
                is_churn_limit_reached = (
                    processed_amount + int(deposit.amount) > available_for_processing
                )
                if is_churn_limit_reached:
                    break
                processed_amount += int(deposit.amount)
                state = self.apply_pending_deposit(state, deposit)

            next_deposit_index += 1

        remaining = [*list(state.pending_deposits)[next_deposit_index:], *deposits_to_postpone]
        # Carry leftover churn budget only when the limit stopped processing.
        deposit_balance_to_consume = (
            available_for_processing - processed_amount if is_churn_limit_reached else 0
        )
        return state.model_copy(
            update={
                "pending_deposits": PendingDeposits(data=remaining),
                "deposit_balance_to_consume": Gwei(deposit_balance_to_consume),
            }
        )

    def process_pending_consolidations(self, state: BeaconState) -> BeaconState:
        """Settle matured consolidations, moving each source's active balance to its target."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        processed_count = 0
        for pending_consolidation in state.pending_consolidations:
            source_index = pending_consolidation.source_index
            source_validator = state.validators[int(source_index)]
            # A slashed source is dropped without moving any balance.
            if source_validator.slashed:
                processed_count += 1
                continue
            # Stop at the first source that has not yet become withdrawable.
            if int(source_validator.withdrawable_epoch) > next_epoch:
                break

            source_effective_balance = min(
                int(state.balances[int(source_index)]), int(source_validator.effective_balance)
            )
            state = self.decrease_balance(state, source_index, Gwei(source_effective_balance))
            state = self.increase_balance(
                state, pending_consolidation.target_index, Gwei(source_effective_balance)
            )
            processed_count += 1

        remaining = list(state.pending_consolidations)[processed_count:]
        return state.model_copy(
            update={"pending_consolidations": PendingConsolidations(data=remaining)}
        )

    def process_builder_pending_payments(self, state: BeaconState) -> BeaconState:
        """Settle last epoch's builder payments that reached quorum, then roll the window."""
        quorum = self.get_builder_payment_quorum_threshold(state)
        payments = list(state.builder_pending_payments)
        withdrawals = list(state.builder_pending_withdrawals)
        for payment in payments[:_SLOTS_PER_EPOCH]:
            if int(payment.weight) >= int(quorum):
                withdrawals.append(payment.withdrawal)

        # Drop the oldest epoch of payments and open a fresh empty epoch at the end.
        zero_payment = BuilderPendingPayment.decode_bytes(
            b"\x00" * BuilderPendingPayment.get_byte_length()
        )
        rolled_payments = [
            *payments[_SLOTS_PER_EPOCH:],
            *[zero_payment for _ in range(_SLOTS_PER_EPOCH)],
        ]
        return state.model_copy(
            update={
                "builder_pending_withdrawals": BuilderPendingWithdrawals(data=withdrawals),
                "builder_pending_payments": BuilderPendingPayments(data=rolled_payments),
            }
        )

    def process_ptc_window(self, state: BeaconState) -> BeaconState:
        """Shift the payload timeliness committee window forward and fill the lookahead epoch."""
        window = list(state.ptc_window)
        next_epoch = Epoch(int(self.get_current_epoch(state)) + _MIN_SEED_LOOKAHEAD + 1)
        start_slot = int(self.compute_start_slot_at_epoch(next_epoch))
        lookahead_committees = [
            self.compute_ptc(state, Slot(start_slot + slot_offset))
            for slot_offset in range(_SLOTS_PER_EPOCH)
        ]
        rolled_window = [*window[_SLOTS_PER_EPOCH:], *lookahead_committees]
        return state.model_copy(update={"ptc_window": PtcWindow(data=rolled_window)})

    def process_sync_committee_updates(self, state: BeaconState) -> BeaconState:
        """Rotate the next sync committee into current and sample a new next at period bounds."""
        next_epoch = int(self.get_current_epoch(state)) + 1
        if next_epoch % int(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) == 0:
            return state.model_copy(
                update={
                    "current_sync_committee": state.next_sync_committee,
                    "next_sync_committee": self.get_next_sync_committee(state),
                }
            )
        return state

    def process_proposer_lookahead(self, state: BeaconState) -> BeaconState:
        """Shift the proposer lookahead forward and fill the newly exposed epoch."""
        lookahead = list(state.proposer_lookahead)
        last_epoch_proposers = self.get_beacon_proposer_indices(
            state, Epoch(int(self.get_current_epoch(state)) + _MIN_SEED_LOOKAHEAD + 1)
        )
        rolled_lookahead = [*lookahead[_SLOTS_PER_EPOCH:], *last_epoch_proposers]
        return state.model_copy(
            update={"proposer_lookahead": ProposerLookahead(data=rolled_lookahead)}
        )

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
