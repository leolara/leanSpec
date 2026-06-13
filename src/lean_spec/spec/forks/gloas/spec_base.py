"""
Protocol and shared typed base for the Gloas spec mixins.

The Gloas fork is assembled like the lean fork: a single spec class composed
from behavior mixins. Each mixin inherits this base, which declares the full
method contract so a mixin can call any sibling method through self. The base
extends a minimal protocol carrying the fork identity.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from lean_spec.spec.forks.gloas.config import BlobParameters
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Attestation,
    AttestationData,
    AttesterSlashing,
    BeaconBlock,
    BeaconState,
    BuilderPendingPayment,
    ConsolidationRequest,
    DepositRequest,
    ExecutionRequests,
    IndexedAttestation,
    IndexedPayloadAttestation,
    PayloadAttestation,
    PendingDeposits,
    ProposerSlashing,
    SignedBLSToExecutionChange,
    SignedExecutionPayloadBid,
    SignedVoluntaryExit,
    Validator,
    Withdrawal,
    WithdrawalRequest,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BLSPubkey,
    BLSSignature,
    BuilderIndex,
    CommitteeIndex,
    Domain,
    DomainType,
    Epoch,
    Gwei,
    ParticipationFlags,
    Root,
    Slot,
    ValidatorIndex,
    Version,
)
from lean_spec.spec.forks.gloas.helpers.withdrawals import ExpectedWithdrawals
from lean_spec.spec.ssz import Bytes32, Uint64
from lean_spec.spec.ssz.bitfields import BaseBitvector
from lean_spec.spec.ssz.ssz_base import SSZType


class GloasProtocol(ABC):
    """Identity facade for the standalone Gloas reference fork."""

    NAME: ClassVar[str]
    """Fork name."""

    PRESET: ClassVar[str]
    """Active consensus preset, mainnet or minimal."""


class GloasSpecBase(GloasProtocol):
    """
    Typed base every Gloas behavior mixin inherits.

    It declares each spec method as abstract so any mixin can call any sibling
    method through self; the composed spec class provides the implementations.
    """

    @abstractmethod
    def compute_fork_data_root(
        self, current_version: Version, genesis_validators_root: Root
    ) -> Root:
        """Combine a fork version and the genesis validators root into one root."""
        ...

    @abstractmethod
    def compute_domain(
        self,
        domain_type: DomainType,
        fork_version: Version | None = None,
        genesis_validators_root: Root | None = None,
    ) -> Domain:
        """Build the 32-byte signature domain for a purpose, fork, and network."""
        ...

    @abstractmethod
    def compute_signing_root(self, ssz_object: SSZType, domain: Domain) -> Root:
        """Return the domain-separated root a validator actually signs."""
        ...

    @abstractmethod
    def get_domain(
        self, state: BeaconState, domain_type: DomainType, epoch: Epoch | None = None
    ) -> Domain:
        """Return the signature domain for a message anchored to the state's fork."""
        ...

    @abstractmethod
    def is_active_validator(self, validator: Validator, epoch: Epoch) -> bool:
        """Check whether a validator is active in the given epoch."""
        ...

    @abstractmethod
    def is_eligible_for_activation_queue(self, validator: Validator) -> bool:
        """Check whether a validator may enter the activation queue."""
        ...

    @abstractmethod
    def is_eligible_for_activation(self, state: BeaconState, validator: Validator) -> bool:
        """Check whether a queued validator may now be activated."""
        ...

    @abstractmethod
    def is_slashable_validator(self, validator: Validator, epoch: Epoch) -> bool:
        """Check whether a validator can be slashed in the given epoch."""
        ...

    @abstractmethod
    def is_slashable_attestation_data(
        self, data_1: AttestationData, data_2: AttestationData
    ) -> bool:
        """Check whether two attestation data are slashable under Casper FFG."""
        ...

    @abstractmethod
    def is_compounding_withdrawal_credential(self, withdrawal_credentials: Bytes32) -> bool:
        """Check whether withdrawal credentials carry the compounding prefix."""
        ...

    @abstractmethod
    def has_eth1_withdrawal_credential(self, validator: Validator) -> bool:
        """Check whether a validator has an execution-address withdrawal credential."""
        ...

    @abstractmethod
    def has_compounding_withdrawal_credential(self, validator: Validator) -> bool:
        """Check whether a validator has a compounding withdrawal credential."""
        ...

    @abstractmethod
    def has_execution_withdrawal_credential(self, validator: Validator) -> bool:
        """Check whether a validator can withdraw to an execution address."""
        ...

    @abstractmethod
    def get_max_effective_balance(self, validator: Validator) -> Gwei:
        """Return the ceiling on a validator's effective balance."""
        ...

    @abstractmethod
    def is_fully_withdrawable_validator(
        self, validator: Validator, balance: Gwei, epoch: Epoch
    ) -> bool:
        """Check whether a validator's whole balance is withdrawable in the epoch."""
        ...

    @abstractmethod
    def is_partially_withdrawable_validator(self, validator: Validator, balance: Gwei) -> bool:
        """Check whether a validator has withdrawable balance above its ceiling."""
        ...

    @abstractmethod
    def is_builder_index(self, validator_index: ValidatorIndex) -> bool:
        """Check whether an index encodes a builder rather than a validator."""
        ...

    @abstractmethod
    def convert_validator_index_to_builder_index(
        self, validator_index: ValidatorIndex
    ) -> BuilderIndex:
        """Strip the builder flag bit to recover a builder-registry index."""
        ...

    @abstractmethod
    def convert_builder_index_to_validator_index(
        self, builder_index: BuilderIndex
    ) -> ValidatorIndex:
        """Set the builder flag bit to project a builder index into the validator space."""
        ...

    @abstractmethod
    def is_eligible_for_partial_withdrawals(self, validator: Validator, balance: Gwei) -> bool:
        """Check a non-exiting validator at full effective balance has excess to withdraw."""
        ...

    @abstractmethod
    def is_builder_withdrawal_credential(self, withdrawal_credentials: Bytes32) -> bool:
        """Check whether withdrawal credentials carry the builder prefix."""
        ...

    @abstractmethod
    def is_valid_indexed_attestation(
        self, state: BeaconState, indexed_attestation: IndexedAttestation
    ) -> bool:
        """Check that an indexed attestation has sorted, unique indices and a valid signature."""
        ...

    @abstractmethod
    def is_valid_indexed_payload_attestation(
        self, state: BeaconState, payload_attestation: IndexedPayloadAttestation
    ) -> bool:
        """Check a payload attestation has non-empty, sorted indices and a valid signature."""
        ...

    @abstractmethod
    def get_indexed_payload_attestation(
        self, state: BeaconState, payload_attestation: PayloadAttestation
    ) -> IndexedPayloadAttestation:
        """Return the indexed form of a payload attestation, resolved against its committee."""
        ...

    @abstractmethod
    def can_builder_cover_bid(
        self, state: BeaconState, builder_index: BuilderIndex, bid_amount: Gwei
    ) -> bool:
        """Check a builder can fund a bid above its minimum-deposit and queued-withdrawal floor."""
        ...

    @abstractmethod
    def verify_execution_payload_bid_signature(
        self, state: BeaconState, signed_bid: SignedExecutionPayloadBid
    ) -> bool:
        """Check a bid is signed by the builder it names."""
        ...

    @abstractmethod
    def compute_epoch_at_slot(self, slot: Slot) -> Epoch:
        """Return the epoch a slot falls in."""
        ...

    @abstractmethod
    def compute_start_slot_at_epoch(self, epoch: Epoch) -> Slot:
        """Return the first slot of an epoch."""
        ...

    @abstractmethod
    def compute_activation_exit_epoch(self, epoch: Epoch) -> Epoch:
        """Return the epoch an activation or exit initiated this epoch takes effect."""
        ...

    @abstractmethod
    def get_current_epoch(self, state: BeaconState) -> Epoch:
        """Return the epoch the state is currently in."""
        ...

    @abstractmethod
    def get_blob_parameters(self, epoch: Epoch) -> BlobParameters:
        """Return the blob ceiling active at an epoch from the configured schedule."""
        ...

    @abstractmethod
    def get_previous_epoch(self, state: BeaconState) -> Epoch:
        """Return the epoch before the current one, clamped at genesis."""
        ...

    @abstractmethod
    def get_active_validator_indices(
        self, state: BeaconState, epoch: Epoch
    ) -> list[ValidatorIndex]:
        """Return the indices of validators active in the given epoch."""
        ...

    @abstractmethod
    def get_block_root_at_slot(self, state: BeaconState, slot: Slot) -> Root:
        """Return a recent block root by slot."""
        ...

    @abstractmethod
    def get_block_root(self, state: BeaconState, epoch: Epoch) -> Root:
        """Return the block root at the start of a recent epoch."""
        ...

    @abstractmethod
    def get_randao_mix(self, state: BeaconState, epoch: Epoch) -> Bytes32:
        """Return the randao mix recorded for a recent epoch."""
        ...

    @abstractmethod
    def get_seed(self, state: BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32:
        """Return the seed mixing randomness, the epoch, and a domain into one hash."""
        ...

    @abstractmethod
    def get_committee_count_per_slot(self, state: BeaconState, epoch: Epoch) -> Uint64:
        """Return how many committees each slot is split into for the epoch."""
        ...

    @abstractmethod
    def get_beacon_committee(
        self, state: BeaconState, slot: Slot, index: CommitteeIndex
    ) -> list[ValidatorIndex]:
        """Return the validator indices of one committee at a slot."""
        ...

    @abstractmethod
    def get_beacon_proposer_index(self, state: BeaconState) -> ValidatorIndex:
        """Return the proposer for the current slot from the precomputed lookahead."""
        ...

    @abstractmethod
    def get_total_balance(self, state: BeaconState, indices: set[ValidatorIndex]) -> Gwei:
        """Return the summed effective balance of the indices, floored at one increment."""
        ...

    @abstractmethod
    def get_total_active_balance(self, state: BeaconState) -> Gwei:
        """Return the summed effective balance of the currently active validators."""
        ...

    @abstractmethod
    def get_unslashed_participating_indices(
        self, state: BeaconState, flag_index: int, epoch: Epoch
    ) -> set[ValidatorIndex]:
        """Return the active, unslashed validators that earned a timeliness flag in an epoch."""
        ...

    @abstractmethod
    def get_eligible_validator_indices(self, state: BeaconState) -> list[ValidatorIndex]:
        """Return the validators eligible for rewards and penalties this epoch."""
        ...

    @abstractmethod
    def get_finality_delay(self, state: BeaconState) -> Uint64:
        """Return how many epochs the previous epoch trails the last finalized one."""
        ...

    @abstractmethod
    def is_in_inactivity_leak(self, state: BeaconState) -> bool:
        """Check whether finality has stalled long enough to trigger the inactivity leak."""
        ...

    @abstractmethod
    def get_pending_balance_to_withdraw(
        self, state: BeaconState, validator_index: ValidatorIndex
    ) -> Gwei:
        """Return the gwei a validator already has queued for partial withdrawal."""
        ...

    @abstractmethod
    def is_valid_switch_to_compounding_request(
        self, state: BeaconState, consolidation_request: ConsolidationRequest
    ) -> bool:
        """Check whether a self-targeting consolidation requests a compounding switch."""
        ...

    @abstractmethod
    def is_active_builder(self, state: BeaconState, builder_index: BuilderIndex) -> bool:
        """Check whether a builder is finalized into the registry and not exiting."""
        ...

    @abstractmethod
    def get_index_for_new_builder(self, state: BeaconState) -> BuilderIndex:
        """Return a reusable exited-builder slot, or the next free index past the registry."""
        ...

    @abstractmethod
    def get_pending_balance_to_withdraw_for_builder(
        self, state: BeaconState, builder_index: BuilderIndex
    ) -> Gwei:
        """Return the gwei a builder has queued across pending withdrawals and payments."""
        ...

    @abstractmethod
    def get_expected_withdrawals(self, state: BeaconState) -> ExpectedWithdrawals:
        """Build the full ordered withdrawal sweep and each stage's processed count."""
        ...

    @abstractmethod
    def get_committee_indices(self, committee_bits: BaseBitvector) -> list[CommitteeIndex]:
        """Return the committee indices whose bit is set in an attestation."""
        ...

    @abstractmethod
    def get_attesting_indices(
        self, state: BeaconState, attestation: Attestation
    ) -> set[ValidatorIndex]:
        """Return the validator indices that an attestation's bits mark as attesting."""
        ...

    @abstractmethod
    def get_indexed_attestation(
        self, state: BeaconState, attestation: Attestation
    ) -> IndexedAttestation:
        """Return the indexed form of an attestation, with sorted attesting indices."""
        ...

    @abstractmethod
    def is_attestation_same_slot(self, state: BeaconState, data: AttestationData) -> bool:
        """Check whether an attestation votes for the block proposed at its own slot."""
        ...

    @abstractmethod
    def get_attestation_participation_flag_indices(
        self, state: BeaconState, data: AttestationData, inclusion_delay: Uint64
    ) -> list[int]:
        """Return which timeliness flags an attestation earns."""
        ...

    @abstractmethod
    def get_base_reward_per_increment(self, state: BeaconState) -> Gwei:
        """Return the base reward earned per effective-balance increment this epoch."""
        ...

    @abstractmethod
    def get_base_reward(self, state: BeaconState, index: ValidatorIndex) -> Gwei:
        """Return one validator's base reward, scaled by its effective balance."""
        ...

    @abstractmethod
    def add_flag(self, flags: ParticipationFlags, flag_index: int) -> ParticipationFlags:
        """Return the participation flags with one timeliness flag added."""
        ...

    @abstractmethod
    def has_flag(self, flags: ParticipationFlags, flag_index: int) -> bool:
        """Check whether the participation flags already carry one timeliness flag."""
        ...

    @abstractmethod
    def replace_validator(
        self, state: BeaconState, index: int, validator: Validator
    ) -> BeaconState:
        """Return a state whose validator at the index is replaced."""
        ...

    @abstractmethod
    def increase_balance(
        self, state: BeaconState, index: ValidatorIndex, delta: Gwei
    ) -> BeaconState:
        """Return a state with the balance at the index increased by the delta."""
        ...

    @abstractmethod
    def decrease_balance(
        self, state: BeaconState, index: ValidatorIndex, delta: Gwei
    ) -> BeaconState:
        """Return a state with the balance at the index decreased, floored at zero."""
        ...

    @abstractmethod
    def get_exit_churn_limit(self, state: BeaconState) -> Gwei:
        """Return the per-epoch exit churn, rounded down to a balance increment."""
        ...

    @abstractmethod
    def compute_exit_epoch_and_update_churn(
        self, state: BeaconState, exit_balance: Gwei
    ) -> tuple[BeaconState, Epoch]:
        """Reserve exit churn for a balance and return the updated state and exit epoch."""
        ...

    @abstractmethod
    def initiate_validator_exit(self, state: BeaconState, index: ValidatorIndex) -> BeaconState:
        """Return a state with the validator's exit queued, or unchanged if already exiting."""
        ...

    @abstractmethod
    def get_consolidation_churn_limit(self, state: BeaconState) -> Gwei:
        """Return the per-epoch consolidation churn, rounded down to a balance increment."""
        ...

    @abstractmethod
    def compute_consolidation_epoch_and_update_churn(
        self, state: BeaconState, consolidation_balance: Gwei
    ) -> tuple[BeaconState, Epoch]:
        """Reserve consolidation churn for a balance and return the state and exit epoch."""
        ...

    @abstractmethod
    def queue_excess_active_balance(self, state: BeaconState, index: ValidatorIndex) -> BeaconState:
        """Return a state with a validator's balance above the activation floor queued."""
        ...

    @abstractmethod
    def switch_to_compounding_validator(
        self, state: BeaconState, index: ValidatorIndex
    ) -> BeaconState:
        """Return a state with a validator switched to compounding credentials."""
        ...

    @abstractmethod
    def initiate_builder_exit(self, state: BeaconState, builder_index: BuilderIndex) -> BeaconState:
        """Return a state with the builder's withdrawable epoch scheduled."""
        ...

    @abstractmethod
    def slash_validator(
        self,
        state: BeaconState,
        slashed_index: ValidatorIndex,
        whistleblower_index: ValidatorIndex | None = None,
    ) -> BeaconState:
        """Return a state with the validator slashed, penalized, and the reward paid out."""
        ...

    @abstractmethod
    def is_valid_deposit_signature(
        self,
        public_key: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
    ) -> bool:
        """Check a deposit's proof-of-possession signature."""
        ...

    @abstractmethod
    def is_pending_validator(
        self, pending_deposits: PendingDeposits, public_key: BLSPubkey
    ) -> bool:
        """Check whether a validly-signed deposit for a public key is already queued."""
        ...

    @abstractmethod
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
        ...

    @abstractmethod
    def apply_withdrawals(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Deduct each withdrawal from its builder or validator balance."""
        ...

    @abstractmethod
    def update_next_withdrawal_index(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Advance the next withdrawal index past the last withdrawal in the block."""
        ...

    @abstractmethod
    def update_payload_expected_withdrawals(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Record the withdrawals the next execution payload must honor."""
        ...

    @abstractmethod
    def update_builder_pending_withdrawals(
        self, state: BeaconState, processed_builder_withdrawals_count: Uint64
    ) -> BeaconState:
        """Drop the builder pending withdrawals consumed by this block from the front."""
        ...

    @abstractmethod
    def update_pending_partial_withdrawals(
        self, state: BeaconState, processed_partial_withdrawals_count: Uint64
    ) -> BeaconState:
        """Drop the pending partial withdrawals consumed by this block from the front."""
        ...

    @abstractmethod
    def update_next_withdrawal_builder_index(
        self, state: BeaconState, processed_builders_sweep_count: Uint64
    ) -> BeaconState:
        """Advance the builder sweep cursor past the builders this block swept."""
        ...

    @abstractmethod
    def update_next_withdrawal_validator_index(
        self, state: BeaconState, withdrawals: Sequence[Withdrawal]
    ) -> BeaconState:
        """Advance the validator sweep cursor for the next block."""
        ...

    @abstractmethod
    def settle_builder_payment(self, state: BeaconState, payment_index: int) -> BeaconState:
        """Convert a slot's pending builder payment into a queued withdrawal and clear it."""
        ...

    @abstractmethod
    def apply_parent_execution_payload(
        self, state: BeaconState, requests: ExecutionRequests
    ) -> BeaconState:
        """Process the parent payload's requests, settle its payment, and mark it available."""
        ...

    @abstractmethod
    def _zero_builder_payment(self) -> BuilderPendingPayment:
        """Return an all-zero builder pending payment, the empty-slot placeholder."""
        ...

    @abstractmethod
    def process_bls_to_execution_change(
        self, state: BeaconState, signed_address_change: SignedBLSToExecutionChange
    ) -> BeaconState:
        """Switch a validator from BLS to execution-address withdrawal credentials."""
        ...

    @abstractmethod
    def _reset_builder_payment(self, state: BeaconState, payment_index: int) -> BeaconState:
        """Return a state with one builder pending payment slot cleared to zero."""
        ...

    @abstractmethod
    def process_proposer_slashing(
        self, state: BeaconState, proposer_slashing: ProposerSlashing
    ) -> BeaconState:
        """Slash a proposer that signed two distinct headers for one slot."""
        ...

    @abstractmethod
    def process_attester_slashing(
        self, state: BeaconState, attester_slashing: AttesterSlashing
    ) -> BeaconState:
        """Slash every validator that signed both of two conflicting attestations."""
        ...

    @abstractmethod
    def process_withdrawal_request(
        self, state: BeaconState, withdrawal_request: WithdrawalRequest
    ) -> BeaconState:
        """Queue an execution-triggered exit or partial withdrawal for a validator."""
        ...

    @abstractmethod
    def process_consolidation_request(
        self, state: BeaconState, consolidation_request: ConsolidationRequest
    ) -> BeaconState:
        """Switch a validator to compounding, or queue a source-to-target consolidation."""
        ...

    @abstractmethod
    def process_deposit_request(
        self, state: BeaconState, deposit_request: DepositRequest
    ) -> BeaconState:
        """Apply an execution-layer deposit request to a builder or the deposit queue."""
        ...

    @abstractmethod
    def process_voluntary_exit(
        self, state: BeaconState, signed_voluntary_exit: SignedVoluntaryExit
    ) -> BeaconState:
        """Initiate the exit of a validator or builder that signed a voluntary exit."""
        ...

    @abstractmethod
    def process_block_header(self, state: BeaconState, block: BeaconBlock) -> BeaconState:
        """Validate a block's header against the state and record it as the latest."""
        ...

    @abstractmethod
    def process_attestation(self, state: BeaconState, attestation: Attestation) -> BeaconState:
        """Record an attestation's participation flags and reward the proposer."""
        ...
