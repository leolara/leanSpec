"""
Block-operation processing.

Each function validates one operation against the pre-state and returns the
post-state. A failed validation raises, which the upstream vectors signal by
shipping no post-state for that case.
"""

from hashlib import sha256

from lean_spec.spec.crypto import bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.config import (
    CAPELLA_FORK_VERSION,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
    SHARD_COMMITTEE_PERIOD,
)
from lean_spec.spec.forks.gloas.constants import (
    BLS_WITHDRAWAL_PREFIX,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BLS_TO_EXECUTION_CHANGE,
    DOMAIN_VOLUNTARY_EXIT,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    FAR_FUTURE_EPOCH,
    FULL_EXIT_REQUEST_AMOUNT,
    PARTICIPATION_FLAG_WEIGHTS,
    PROPOSER_WEIGHT,
    WEIGHT_DENOMINATOR,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Attestation,
    AttesterSlashing,
    BeaconBlock,
    BeaconBlockHeader,
    BeaconState,
    BuilderPendingPayment,
    BuilderPendingPayments,
    ConsolidationRequest,
    DepositRequest,
    PayloadAttestation,
    PendingConsolidation,
    PendingConsolidations,
    PendingDeposit,
    PendingDeposits,
    PendingPartialWithdrawal,
    PendingPartialWithdrawals,
    ProposerSlashing,
    SignedBLSToExecutionChange,
    SignedVoluntaryExit,
    Validators,
    WithdrawalRequest,
)
from lean_spec.spec.forks.gloas.containers.primitives import Epoch, Gwei, Root, ValidatorIndex
from lean_spec.spec.forks.gloas.preset import (
    MIN_ACTIVATION_BALANCE,
    MIN_ATTESTATION_INCLUSION_DELAY,
    PENDING_CONSOLIDATIONS_LIMIT,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT,
    SLOTS_PER_EPOCH,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Bytes32, Uint64

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_EXECUTION_CREDENTIAL_PADDING = b"\x00" * 11


class OperationMixin(GloasSpecBase):
    """Operation behavior for the Gloas spec."""

    def _zero_builder_payment(self) -> BuilderPendingPayment:
        """Return an all-zero builder pending payment, the empty-slot placeholder."""
        return BuilderPendingPayment.decode_bytes(b"\x00" * BuilderPendingPayment.get_byte_length())

    def process_bls_to_execution_change(
        self, state: BeaconState, signed_address_change: SignedBLSToExecutionChange
    ) -> BeaconState:
        """
        Switch a validator from BLS to execution-address withdrawal credentials.

        The change is self-signed by the original BLS key, whose hash must match the
        validator's current credentials. The signature uses the genesis fork version,
        so a change stays valid across forks.

        Raises:
            AssertionError: If the index, the credential binding, or the signature is invalid.
        """
        address_change = signed_address_change.message
        validator_index = int(address_change.validator_index)

        assert validator_index < len(state.validators)
        validator = state.validators[validator_index]

        current_credentials = bytes(validator.withdrawal_credentials)
        assert current_credentials[:1] == BLS_WITHDRAWAL_PREFIX
        assert (
            current_credentials[1:]
            == sha256(bytes(address_change.from_bls_public_key)).digest()[1:]
        )

        domain = self.compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE, genesis_validators_root=state.genesis_validators_root
        )
        signing_root = self.compute_signing_root(address_change, domain)
        assert bls.Verify(
            address_change.from_bls_public_key, signing_root, signed_address_change.signature
        )

        new_credentials = Bytes32(
            bytes(ETH1_ADDRESS_WITHDRAWAL_PREFIX)
            + _EXECUTION_CREDENTIAL_PADDING
            + bytes(address_change.to_execution_address)
        )
        updated_validator = validator.model_copy(update={"withdrawal_credentials": new_credentials})
        updated_validators = Validators(
            data=[
                *list(state.validators)[:validator_index],
                updated_validator,
                *list(state.validators)[validator_index + 1 :],
            ]
        )
        return state.model_copy(update={"validators": updated_validators})

    def _reset_builder_payment(self, state: BeaconState, payment_index: int) -> BeaconState:
        """Return a state with one builder pending payment slot cleared to zero."""
        payments = list(state.builder_pending_payments)
        payments[payment_index] = self._zero_builder_payment()
        return state.model_copy(
            update={"builder_pending_payments": BuilderPendingPayments(data=payments)}
        )

    def process_proposer_slashing(
        self, state: BeaconState, proposer_slashing: ProposerSlashing
    ) -> BeaconState:
        """
        Slash a proposer that signed two distinct headers for one slot.

        The two headers must share a slot and proposer yet differ, and both signatures
        must verify. A still-pending builder payment for the equivocating slot is
        cleared before the proposer is slashed.

        Raises:
            AssertionError: If the evidence or either signature is invalid.
        """
        header_1 = proposer_slashing.signed_header_1.message
        header_2 = proposer_slashing.signed_header_2.message

        assert header_1.slot == header_2.slot
        assert header_1.proposer_index == header_2.proposer_index
        assert header_1 != header_2
        proposer = state.validators[int(header_1.proposer_index)]
        assert self.is_slashable_validator(proposer, self.get_current_epoch(state))
        for signed_header in (proposer_slashing.signed_header_1, proposer_slashing.signed_header_2):
            domain = self.get_domain(
                state,
                DOMAIN_BEACON_PROPOSER,
                self.compute_epoch_at_slot(signed_header.message.slot),
            )
            signing_root = self.compute_signing_root(signed_header.message, domain)
            assert bls.Verify(proposer.public_key, signing_root, signed_header.signature)

        slot = header_1.slot
        proposal_epoch = self.compute_epoch_at_slot(slot)
        if proposal_epoch == self.get_current_epoch(state):
            state = self._reset_builder_payment(
                state, _SLOTS_PER_EPOCH + int(slot) % _SLOTS_PER_EPOCH
            )
        elif proposal_epoch == self.get_previous_epoch(state):
            state = self._reset_builder_payment(state, int(slot) % _SLOTS_PER_EPOCH)

        return self.slash_validator(state, header_1.proposer_index)

    def process_attester_slashing(
        self, state: BeaconState, attester_slashing: AttesterSlashing
    ) -> BeaconState:
        """
        Slash every validator that signed both of two conflicting attestations.

        The two attestations must form a slashable pair and each must be a valid
        indexed attestation; at least one common signer must end up slashed.

        Raises:
            AssertionError: If the evidence is not slashable or no validator is slashed.
        """
        attestation_1 = attester_slashing.attestation_1
        attestation_2 = attester_slashing.attestation_2
        assert self.is_slashable_attestation_data(attestation_1.data, attestation_2.data)
        assert self.is_valid_indexed_attestation(state, attestation_1)
        assert self.is_valid_indexed_attestation(state, attestation_2)

        common_indices = set(attestation_1.attesting_indices) & set(attestation_2.attesting_indices)
        current_epoch = self.get_current_epoch(state)
        slashed_any = False
        for index in sorted(common_indices):
            if self.is_slashable_validator(state.validators[index], current_epoch):
                state = self.slash_validator(state, index)
                slashed_any = True
        assert slashed_any
        return state

    def process_withdrawal_request(
        self, state: BeaconState, withdrawal_request: WithdrawalRequest
    ) -> BeaconState:
        """
        Queue an execution-triggered exit or partial withdrawal for a validator.

        Every validation failure is a silent no-op rather than a rejection, so the
        post-state equals the pre-state when the request does not apply.
        """
        amount = int(withdrawal_request.amount)
        is_full_exit_request = amount == int(FULL_EXIT_REQUEST_AMOUNT)

        if len(state.pending_partial_withdrawals) == int(PENDING_PARTIAL_WITHDRAWALS_LIMIT) and (
            not is_full_exit_request
        ):
            return state

        validator_public_keys = [validator.public_key for validator in state.validators]
        if withdrawal_request.validator_public_key not in validator_public_keys:
            return state
        index = ValidatorIndex(validator_public_keys.index(withdrawal_request.validator_public_key))
        validator = state.validators[int(index)]

        has_correct_credential = self.has_execution_withdrawal_credential(validator)
        is_correct_source_address = bytes(validator.withdrawal_credentials)[12:] == bytes(
            withdrawal_request.source_address
        )
        if not (has_correct_credential and is_correct_source_address):
            return state
        if not self.is_active_validator(validator, self.get_current_epoch(state)):
            return state
        if validator.exit_epoch != FAR_FUTURE_EPOCH:
            return state
        activation_floor = int(validator.activation_epoch) + int(SHARD_COMMITTEE_PERIOD)
        if int(self.get_current_epoch(state)) < activation_floor:
            return state

        pending_balance_to_withdraw = int(self.get_pending_balance_to_withdraw(state, index))

        if is_full_exit_request:
            if pending_balance_to_withdraw == 0:
                return self.initiate_validator_exit(state, index)
            return state

        minimum_balance = int(MIN_ACTIVATION_BALANCE)
        has_sufficient_effective_balance = int(validator.effective_balance) >= minimum_balance
        balance = int(state.balances[int(index)])
        has_excess_balance = balance > minimum_balance + pending_balance_to_withdraw

        if not (
            self.has_compounding_withdrawal_credential(validator)
            and has_sufficient_effective_balance
            and has_excess_balance
        ):
            return state

        to_withdraw = min(
            balance - int(MIN_ACTIVATION_BALANCE) - pending_balance_to_withdraw, amount
        )
        state, exit_queue_epoch = self.compute_exit_epoch_and_update_churn(state, Gwei(to_withdraw))
        withdrawable_epoch = Epoch(int(exit_queue_epoch) + int(MIN_VALIDATOR_WITHDRAWABILITY_DELAY))
        queued = [
            *list(state.pending_partial_withdrawals),
            PendingPartialWithdrawal(
                validator_index=index,
                amount=Gwei(to_withdraw),
                withdrawable_epoch=withdrawable_epoch,
            ),
        ]
        return state.model_copy(
            update={"pending_partial_withdrawals": PendingPartialWithdrawals(data=queued)}
        )

    def process_consolidation_request(
        self, state: BeaconState, consolidation_request: ConsolidationRequest
    ) -> BeaconState:
        """
        Switch a validator to compounding, or queue a source-to-target consolidation.

        Every validation failure is a silent no-op rather than a rejection, so the
        post-state equals the pre-state when the request does not apply.
        """
        if self.is_valid_switch_to_compounding_request(state, consolidation_request):
            public_keys = [validator.public_key for validator in state.validators]
            source_index = ValidatorIndex(
                public_keys.index(consolidation_request.source_public_key)
            )
            return self.switch_to_compounding_validator(state, source_index)

        if consolidation_request.source_public_key == consolidation_request.target_public_key:
            return state
        if len(state.pending_consolidations) == int(PENDING_CONSOLIDATIONS_LIMIT):
            return state
        if int(self.get_consolidation_churn_limit(state)) <= int(MIN_ACTIVATION_BALANCE):
            return state

        public_keys = [validator.public_key for validator in state.validators]
        if consolidation_request.source_public_key not in public_keys:
            return state
        if consolidation_request.target_public_key not in public_keys:
            return state
        source_index = ValidatorIndex(public_keys.index(consolidation_request.source_public_key))
        target_index = ValidatorIndex(public_keys.index(consolidation_request.target_public_key))
        source = state.validators[int(source_index)]
        target = state.validators[int(target_index)]

        is_correct_source_address = bytes(source.withdrawal_credentials)[12:] == bytes(
            consolidation_request.source_address
        )
        if not (self.has_execution_withdrawal_credential(source) and is_correct_source_address):
            return state
        if not self.has_compounding_withdrawal_credential(target):
            return state

        current_epoch = self.get_current_epoch(state)
        if not self.is_active_validator(source, current_epoch):
            return state
        if not self.is_active_validator(target, current_epoch):
            return state
        if source.exit_epoch != FAR_FUTURE_EPOCH:
            return state
        if target.exit_epoch != FAR_FUTURE_EPOCH:
            return state
        if int(current_epoch) < int(source.activation_epoch) + int(SHARD_COMMITTEE_PERIOD):
            return state
        if int(self.get_pending_balance_to_withdraw(state, source_index)) > 0:
            return state

        state, exit_epoch = self.compute_consolidation_epoch_and_update_churn(
            state, source.effective_balance
        )
        consolidated_source = source.model_copy(
            update={
                "exit_epoch": exit_epoch,
                "withdrawable_epoch": Epoch(
                    int(exit_epoch) + int(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
                ),
            }
        )
        state = self.replace_validator(state, int(source_index), consolidated_source)
        queued = [
            *list(state.pending_consolidations),
            PendingConsolidation(source_index=source_index, target_index=target_index),
        ]
        return state.model_copy(
            update={"pending_consolidations": PendingConsolidations(data=queued)}
        )

    def process_voluntary_exit(
        self, state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit
    ) -> BeaconState:
        """
        Initiate the exit of a validator or builder that signed a voluntary exit.

        The exit uses the Capella fork version so it stays valid across forks. A
        builder index routes to the builder exit; otherwise the validator must be
        active, not already exiting, and seasoned past the shard-committee period.

        Raises:
            AssertionError: If the exit is premature, the subject ineligible, or the signature bad.
        """
        voluntary_exit = signed_voluntary_exit.message
        domain = self.compute_domain(
            DOMAIN_VOLUNTARY_EXIT, CAPELLA_FORK_VERSION, state.genesis_validators_root
        )
        signing_root = self.compute_signing_root(voluntary_exit, domain)

        assert int(self.get_current_epoch(state)) >= int(voluntary_exit.epoch)

        if self.is_builder_index(voluntary_exit.validator_index):
            builder_index = self.convert_validator_index_to_builder_index(
                voluntary_exit.validator_index
            )
            assert self.is_active_builder(state, builder_index)
            assert int(self.get_pending_balance_to_withdraw_for_builder(state, builder_index)) == 0
            public_key = state.builders[int(builder_index)].public_key
            assert bls.Verify(public_key, signing_root, signed_voluntary_exit.signature)
            return self.initiate_builder_exit(state, builder_index)

        validator = state.validators[int(voluntary_exit.validator_index)]
        assert self.is_active_validator(validator, self.get_current_epoch(state))
        assert validator.exit_epoch == FAR_FUTURE_EPOCH
        activation_floor = int(validator.activation_epoch) + int(SHARD_COMMITTEE_PERIOD)
        assert int(self.get_current_epoch(state)) >= activation_floor
        assert int(self.get_pending_balance_to_withdraw(state, voluntary_exit.validator_index)) == 0
        assert bls.Verify(validator.public_key, signing_root, signed_voluntary_exit.signature)
        return self.initiate_validator_exit(state, voluntary_exit.validator_index)

    def process_block_header(self, state: BeaconState, block: BeaconBlock) -> BeaconState:
        """
        Validate a block's header against the state and record it as the latest.

        Raises:
            AssertionError: If the slot, proposer, or parent root is wrong, or the proposer slashed.
        """
        assert block.slot == state.slot
        assert int(block.slot) > int(state.latest_block_header.slot)
        assert block.proposer_index == self.get_beacon_proposer_index(state)
        assert block.parent_root == hash_tree_root(state.latest_block_header)

        proposer = state.validators[int(block.proposer_index)]
        assert not proposer.slashed

        new_header = BeaconBlockHeader(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            state_root=Root.zero(),
            body_root=Root(hash_tree_root(block.body)),
        )
        return state.model_copy(update={"latest_block_header": new_header})

    def process_attestation(self, state: BeaconState, attestation: Attestation) -> BeaconState:
        """
        Record an attestation's participation flags and reward the proposer.

        Each newly set timeliness flag earns the proposer a share; for a same-slot
        attestation, the attester's balance also adds to the slot's builder payment
        weight, so each validator contributes to the slot quorum exactly once.

        Raises:
            AssertionError: If the attestation is malformed, mistimed, or has an invalid signature.
        """
        data = attestation.data
        assert data.target.epoch in (self.get_previous_epoch(state), self.get_current_epoch(state))
        assert data.target.epoch == self.compute_epoch_at_slot(data.slot)
        assert int(data.slot) + int(MIN_ATTESTATION_INCLUSION_DELAY) <= int(state.slot)
        assert int(data.index) < 2

        committee_offset = 0
        for committee_index in self.get_committee_indices(attestation.committee_bits):
            assert int(committee_index) < int(
                self.get_committee_count_per_slot(state, data.target.epoch)
            )
            committee = self.get_beacon_committee(state, data.slot, committee_index)
            attesters = {
                attester
                for position, attester in enumerate(committee)
                if attestation.aggregation_bits[committee_offset + position]
            }
            assert len(attesters) > 0
            committee_offset += len(committee)
        assert len(attestation.aggregation_bits) == committee_offset

        inclusion_delay = Uint64(int(state.slot) - int(data.slot))
        participation_flag_indices = self.get_attestation_participation_flag_indices(
            state, data, inclusion_delay
        )
        assert self.is_valid_indexed_attestation(
            state, self.get_indexed_attestation(state, attestation)
        )

        current_epoch_target = data.target.epoch == self.get_current_epoch(state)
        if current_epoch_target:
            epoch_participation = list(state.current_epoch_participation)
            payment_index = _SLOTS_PER_EPOCH + int(data.slot) % _SLOTS_PER_EPOCH
        else:
            epoch_participation = list(state.previous_epoch_participation)
            payment_index = int(data.slot) % _SLOTS_PER_EPOCH
        payment = state.builder_pending_payments[payment_index]
        payment_weight = int(payment.weight)
        same_slot = self.is_attestation_same_slot(state, data)
        payment_has_amount = int(payment.withdrawal.amount) > 0

        proposer_reward_numerator = 0
        for index in self.get_attesting_indices(state, attestation):
            position = int(index)
            set_new_flag = False
            for flag_index, weight in enumerate(PARTICIPATION_FLAG_WEIGHTS):
                if flag_index in participation_flag_indices and not self.has_flag(
                    epoch_participation[position], flag_index
                ):
                    epoch_participation[position] = self.add_flag(
                        epoch_participation[position], flag_index
                    )
                    proposer_reward_numerator += int(self.get_base_reward(state, index)) * int(
                        weight
                    )
                    set_new_flag = True
            if set_new_flag and same_slot and payment_has_amount:
                payment_weight += int(state.validators[position].effective_balance)

        participation_field = (
            "current_epoch_participation"
            if current_epoch_target
            else "previous_epoch_participation"
        )
        participation_type = type(getattr(state, participation_field))
        state = state.model_copy(
            update={participation_field: participation_type(data=epoch_participation)}
        )

        weight_denominator = int(WEIGHT_DENOMINATOR)
        proposer_weight = int(PROPOSER_WEIGHT)
        proposer_reward_denominator = (
            (weight_denominator - proposer_weight) * weight_denominator // proposer_weight
        )
        proposer_reward = Gwei(proposer_reward_numerator // proposer_reward_denominator)
        state = self.increase_balance(state, self.get_beacon_proposer_index(state), proposer_reward)

        updated_payment = payment.model_copy(update={"weight": Uint64(payment_weight)})
        payments = list(state.builder_pending_payments)
        payments[payment_index] = updated_payment
        return state.model_copy(
            update={"builder_pending_payments": BuilderPendingPayments(data=payments)}
        )

    def process_deposit_request(
        self, state: BeaconState, deposit_request: DepositRequest
    ) -> BeaconState:
        """
        Apply an execution-layer deposit request to a builder or the deposit queue.

        A deposit for an existing builder, or a builder-credential deposit for a key
        that is neither a validator nor already queued, settles into the builder
        registry at once. Every other deposit joins the pending-deposit queue.
        """
        builder_public_keys = [builder.public_key for builder in state.builders]
        validator_public_keys = [validator.public_key for validator in state.validators]
        is_builder = deposit_request.public_key in builder_public_keys
        is_validator = deposit_request.public_key in validator_public_keys

        if is_builder or (
            self.is_builder_withdrawal_credential(deposit_request.withdrawal_credentials)
            and not is_validator
            and not self.is_pending_validator(state.pending_deposits, deposit_request.public_key)
        ):
            return self.apply_deposit_for_builder(
                state,
                deposit_request.public_key,
                deposit_request.withdrawal_credentials,
                deposit_request.amount,
                deposit_request.signature,
                state.slot,
            )

        queued = [
            *list(state.pending_deposits),
            PendingDeposit(
                public_key=deposit_request.public_key,
                withdrawal_credentials=deposit_request.withdrawal_credentials,
                amount=deposit_request.amount,
                signature=deposit_request.signature,
                slot=state.slot,
            ),
        ]
        return state.model_copy(update={"pending_deposits": PendingDeposits(data=queued)})

    def process_payload_attestation(
        self, state: BeaconState, payload_attestation: PayloadAttestation
    ) -> BeaconState:
        """
        Validate a payload timeliness attestation for the parent block.

        The attestation only confirms the parent block's payload, so it leaves the
        state unchanged. It must reference the parent block at the previous slot and
        carry a valid aggregate signature from the payload timeliness committee.

        Raises:
            AssertionError: If the attestation targets the wrong block or slot, or fails to verify.
        """
        data = payload_attestation.data
        assert data.beacon_block_root == state.latest_block_header.parent_root
        assert int(data.slot) + 1 == int(state.slot)
        indexed_payload_attestation = self.get_indexed_payload_attestation(
            state, payload_attestation
        )
        assert self.is_valid_indexed_payload_attestation(state, indexed_payload_attestation)
        return state
