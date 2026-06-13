"""
Flattened SSZ containers for the Gloas reference port.

Field types, order, and collection limits are a literal translation of the
upstream gloas specification, verified byte-exact against its ssz_static
vectors. Collection limits that vary by preset read from the preset module.
"""

import os

from lean_spec.spec.forks.gloas.containers.primitives import (
    BLSPubkey,
    BLSSignature,
    BuilderIndex,
    CommitteeIndex,
    Domain,
    Epoch,
    ExecutionAddress,
    Gwei,
    Hash32,
    KZGCommitment,
    ParticipationFlags,
    Root,
    Slot,
    ValidatorIndex,
    Version,
    WithdrawalIndex,
)
from lean_spec.spec.ssz import (
    BaseByteList,
    BaseBytes,
    Boolean,
    Bytes32,
    Container,
    SSZList,
    SSZVector,
    Uint8,
    Uint64,
    Uint256,
)
from lean_spec.spec.ssz.bitfields import BaseBitlist, BaseBitvector

_MINIMAL = os.environ.get("GLOAS_PRESET", "mainnet").lower() == "minimal"
"""Whether the active preset is minimal, for preset-dependent limits."""


class Checkpoint(Container):
    """Checkpoint."""

    epoch: Epoch
    """Epoch."""
    root: Root
    """Root."""


class AttestationData(Container):
    """Attestation data."""

    slot: Slot
    """Slot."""
    index: CommitteeIndex
    """Index."""
    beacon_block_root: Root
    """Beacon block root."""
    source: Checkpoint
    """Source."""
    target: Checkpoint
    """Target."""


class AggregationBits(BaseBitlist):
    """Aggregation bits as a variable-length bitfield."""

    LIMIT = 8192 if _MINIMAL else 131072


class CommitteeBits(BaseBitvector):
    """Committee bits as a fixed-length bitfield."""

    LENGTH = 4 if _MINIMAL else 64


class Attestation(Container):
    """Attestation."""

    aggregation_bits: AggregationBits
    """Aggregation bits."""
    data: AttestationData
    """Data."""
    signature: BLSSignature
    """Signature."""
    committee_bits: CommitteeBits
    """Committee bits."""


class AttestingIndices(SSZList[ValidatorIndex]):
    """Attesting indices."""

    LIMIT = 8192 if _MINIMAL else 131072


class IndexedAttestation(Container):
    """Indexed attestation."""

    attesting_indices: AttestingIndices
    """Attesting indices."""
    data: AttestationData
    """Data."""
    signature: BLSSignature
    """Signature."""


class AttesterSlashing(Container):
    """Attester slashing."""

    attestation_1: IndexedAttestation
    """Attestation 1."""
    attestation_2: IndexedAttestation
    """Attestation 2."""


class BLSToExecutionChange(Container):
    """Bls to execution change."""

    validator_index: ValidatorIndex
    """Validator index."""
    from_bls_pubkey: BLSPubkey
    """From bls pubkey."""
    to_execution_address: ExecutionAddress
    """To execution address."""


class Eth1Data(Container):
    """Eth 1 data."""

    deposit_root: Root
    """Deposit root."""
    deposit_count: Uint64
    """Deposit count."""
    block_hash: Hash32
    """Block hash."""


class BeaconBlockHeader(Container):
    """Beacon block header."""

    slot: Slot
    """Slot."""
    proposer_index: ValidatorIndex
    """Proposer index."""
    parent_root: Root
    """Parent root."""
    state_root: Root
    """State root."""
    body_root: Root
    """Body root."""


class SignedBeaconBlockHeader(Container):
    """Signed beacon block header."""

    message: BeaconBlockHeader
    """Message."""
    signature: BLSSignature
    """Signature."""


class ProposerSlashing(Container):
    """Proposer slashing."""

    signed_header_1: SignedBeaconBlockHeader
    """Signed header 1."""
    signed_header_2: SignedBeaconBlockHeader
    """Signed header 2."""


class DepositData(Container):
    """Deposit data."""

    public_key: BLSPubkey
    """Public key."""
    withdrawal_credentials: Bytes32
    """Withdrawal credentials."""
    amount: Gwei
    """Amount."""
    signature: BLSSignature
    """Signature."""


class Proof(SSZVector[Bytes32]):
    """Proof."""

    LENGTH = 33


class Deposit(Container):
    """Deposit."""

    proof: Proof
    """Proof."""
    data: DepositData
    """Data."""


class VoluntaryExit(Container):
    """Voluntary exit."""

    epoch: Epoch
    """Epoch."""
    validator_index: ValidatorIndex
    """Validator index."""


class SignedVoluntaryExit(Container):
    """Signed voluntary exit."""

    message: VoluntaryExit
    """Message."""
    signature: BLSSignature
    """Signature."""


class SyncCommitteeBits(BaseBitvector):
    """Sync committee bits as a fixed-length bitfield."""

    LENGTH = 32 if _MINIMAL else 512


class SyncAggregate(Container):
    """Sync aggregate."""

    sync_committee_bits: SyncCommitteeBits
    """Sync committee bits."""
    sync_committee_signature: BLSSignature
    """Sync committee signature."""


class SignedBLSToExecutionChange(Container):
    """Signed bls to execution change."""

    message: BLSToExecutionChange
    """Message."""
    signature: BLSSignature
    """Signature."""


class BlobKzgCommitments(SSZList[KZGCommitment]):
    """Blob kzg commitments."""

    LIMIT = 4096


class ExecutionPayloadBid(Container):
    """Execution payload bid."""

    parent_block_hash: Hash32
    """Parent block hash."""
    parent_block_root: Root
    """Parent block root."""
    block_hash: Hash32
    """Block hash."""
    prev_randao: Bytes32
    """Prev randao."""
    fee_recipient: ExecutionAddress
    """Fee recipient."""
    gas_limit: Uint64
    """Gas limit."""
    builder_index: BuilderIndex
    """Builder index."""
    slot: Slot
    """Slot."""
    value: Gwei
    """Value."""
    execution_payment: Gwei
    """Execution payment."""
    blob_kzg_commitments: BlobKzgCommitments
    """Blob kzg commitments."""
    execution_requests_root: Root
    """Execution requests root."""


class SignedExecutionPayloadBid(Container):
    """Signed execution payload bid."""

    message: ExecutionPayloadBid
    """Message."""
    signature: BLSSignature
    """Signature."""


class PayloadAttestationData(Container):
    """Payload attestation data."""

    beacon_block_root: Root
    """Beacon block root."""
    slot: Slot
    """Slot."""
    payload_present: Boolean
    """Payload present."""
    blob_data_available: Boolean
    """Blob data available."""


class PayloadattestationAggregationBits(BaseBitvector):
    """Aggregation bits as a fixed-length bitfield."""

    LENGTH = 16 if _MINIMAL else 512


class PayloadAttestation(Container):
    """Payload attestation."""

    aggregation_bits: PayloadattestationAggregationBits
    """Aggregation bits."""
    data: PayloadAttestationData
    """Data."""
    signature: BLSSignature
    """Signature."""


class DepositRequest(Container):
    """Deposit request."""

    public_key: BLSPubkey
    """Public key."""
    withdrawal_credentials: Bytes32
    """Withdrawal credentials."""
    amount: Gwei
    """Amount."""
    signature: BLSSignature
    """Signature."""
    index: Uint64
    """Index."""


class WithdrawalRequest(Container):
    """Withdrawal request."""

    source_address: ExecutionAddress
    """Source address."""
    validator_pubkey: BLSPubkey
    """Validator pubkey."""
    amount: Gwei
    """Amount."""


class ConsolidationRequest(Container):
    """Consolidation request."""

    source_address: ExecutionAddress
    """Source address."""
    source_pubkey: BLSPubkey
    """Source pubkey."""
    target_pubkey: BLSPubkey
    """Target pubkey."""


class Deposits(SSZList[DepositRequest]):
    """Deposits."""

    LIMIT = 8192


class Withdrawals(SSZList[WithdrawalRequest]):
    """Withdrawals."""

    LIMIT = 16


class Consolidations(SSZList[ConsolidationRequest]):
    """Consolidations."""

    LIMIT = 2


class ExecutionRequests(Container):
    """Execution requests."""

    deposits: Deposits
    """Deposits."""
    withdrawals: Withdrawals
    """Withdrawals."""
    consolidations: Consolidations
    """Consolidations."""


class ProposerSlashings(SSZList[ProposerSlashing]):
    """Proposer slashings."""

    LIMIT = 16


class AttesterSlashings(SSZList[AttesterSlashing]):
    """Attester slashings."""

    LIMIT = 1


class Attestations(SSZList[Attestation]):
    """Attestations."""

    LIMIT = 8


class BeaconblockbodyDeposits(SSZList[Deposit]):
    """Deposits."""

    LIMIT = 16


class VoluntaryExits(SSZList[SignedVoluntaryExit]):
    """Voluntary exits."""

    LIMIT = 16


class BlsToExecutionChanges(SSZList[SignedBLSToExecutionChange]):
    """Bls to execution changes."""

    LIMIT = 16


class PayloadAttestations(SSZList[PayloadAttestation]):
    """Payload attestations."""

    LIMIT = 4


class BeaconBlockBody(Container):
    """Beacon block body."""

    randao_reveal: BLSSignature
    """Randao reveal."""
    eth1_data: Eth1Data
    """Eth1 data."""
    graffiti: Bytes32
    """Graffiti."""
    proposer_slashings: ProposerSlashings
    """Proposer slashings."""
    attester_slashings: AttesterSlashings
    """Attester slashings."""
    attestations: Attestations
    """Attestations."""
    deposits: BeaconblockbodyDeposits
    """Deposits."""
    voluntary_exits: VoluntaryExits
    """Voluntary exits."""
    sync_aggregate: SyncAggregate
    """Sync aggregate."""
    bls_to_execution_changes: BlsToExecutionChanges
    """Bls to execution changes."""
    signed_execution_payload_bid: SignedExecutionPayloadBid
    """Signed execution payload bid."""
    payload_attestations: PayloadAttestations
    """Payload attestations."""
    parent_execution_requests: ExecutionRequests
    """Parent execution requests."""


class BeaconBlock(Container):
    """Beacon block."""

    slot: Slot
    """Slot."""
    proposer_index: ValidatorIndex
    """Proposer index."""
    parent_root: Root
    """Parent root."""
    state_root: Root
    """State root."""
    body: BeaconBlockBody
    """Body."""


class Fork(Container):
    """Fork."""

    previous_version: Version
    """Previous version."""
    current_version: Version
    """Current version."""
    epoch: Epoch
    """Epoch."""


class Validator(Container):
    """Validator."""

    public_key: BLSPubkey
    """Public key."""
    withdrawal_credentials: Bytes32
    """Withdrawal credentials."""
    effective_balance: Gwei
    """Effective balance."""
    slashed: Boolean
    """Slashed."""
    activation_eligibility_epoch: Epoch
    """Activation eligibility epoch."""
    activation_epoch: Epoch
    """Activation epoch."""
    exit_epoch: Epoch
    """Exit epoch."""
    withdrawable_epoch: Epoch
    """Withdrawable epoch."""


class Pubkeys(SSZVector[BLSPubkey]):
    """Pubkeys."""

    LENGTH = 32 if _MINIMAL else 512


class SyncCommittee(Container):
    """Sync committee."""

    pubkeys: Pubkeys
    """Pubkeys."""
    aggregate_pubkey: BLSPubkey
    """Aggregate pubkey."""


class HistoricalSummary(Container):
    """Historical summary."""

    block_summary_root: Root
    """Block summary root."""
    state_summary_root: Root
    """State summary root."""


class PendingDeposit(Container):
    """Pending deposit."""

    public_key: BLSPubkey
    """Public key."""
    withdrawal_credentials: Bytes32
    """Withdrawal credentials."""
    amount: Gwei
    """Amount."""
    signature: BLSSignature
    """Signature."""
    slot: Slot
    """Slot."""


class PendingPartialWithdrawal(Container):
    """Pending partial withdrawal."""

    validator_index: ValidatorIndex
    """Validator index."""
    amount: Gwei
    """Amount."""
    withdrawable_epoch: Epoch
    """Withdrawable epoch."""


class PendingConsolidation(Container):
    """Pending consolidation."""

    source_index: ValidatorIndex
    """Source index."""
    target_index: ValidatorIndex
    """Target index."""


class Builder(Container):
    """Builder."""

    public_key: BLSPubkey
    """Public key."""
    version: Uint8
    """Version."""
    execution_address: ExecutionAddress
    """Execution address."""
    balance: Gwei
    """Balance."""
    deposit_epoch: Epoch
    """Deposit epoch."""
    withdrawable_epoch: Epoch
    """Withdrawable epoch."""


class BuilderPendingWithdrawal(Container):
    """Builder pending withdrawal."""

    fee_recipient: ExecutionAddress
    """Fee recipient."""
    amount: Gwei
    """Amount."""
    builder_index: BuilderIndex
    """Builder index."""


class BuilderPendingPayment(Container):
    """Builder pending payment."""

    weight: Gwei
    """Weight."""
    withdrawal: BuilderPendingWithdrawal
    """Withdrawal."""


class Withdrawal(Container):
    """Withdrawal."""

    index: WithdrawalIndex
    """Index."""
    validator_index: ValidatorIndex
    """Validator index."""
    address: ExecutionAddress
    """Address."""
    amount: Gwei
    """Amount."""


class BlockRoots(SSZVector[Root]):
    """Block roots."""

    LENGTH = 64 if _MINIMAL else 8192


class StateRoots(SSZVector[Root]):
    """State roots."""

    LENGTH = 64 if _MINIMAL else 8192


class HistoricalRoots(SSZList[Root]):
    """Historical roots."""

    LIMIT = 16777216


class Eth1DataVotes(SSZList[Eth1Data]):
    """Eth1 data votes."""

    LIMIT = 32 if _MINIMAL else 2048


class Validators(SSZList[Validator]):
    """Validators."""

    LIMIT = 1099511627776


class Balances(SSZList[Gwei]):
    """Balances."""

    LIMIT = 1099511627776


class RandaoMixes(SSZVector[Bytes32]):
    """Randao mixes."""

    LENGTH = 64 if _MINIMAL else 65536


class Slashings(SSZVector[Gwei]):
    """Slashings."""

    LENGTH = 64 if _MINIMAL else 8192


class PreviousEpochParticipation(SSZList[ParticipationFlags]):
    """Previous epoch participation."""

    LIMIT = 1099511627776


class CurrentEpochParticipation(SSZList[ParticipationFlags]):
    """Current epoch participation."""

    LIMIT = 1099511627776


class JustificationBits(BaseBitvector):
    """Justification bits as a fixed-length bitfield."""

    LENGTH = 4


class InactivityScores(SSZList[Uint64]):
    """Inactivity scores."""

    LIMIT = 1099511627776


class HistoricalSummaries(SSZList[HistoricalSummary]):
    """Historical summaries."""

    LIMIT = 16777216


class PendingDeposits(SSZList[PendingDeposit]):
    """Pending deposits."""

    LIMIT = 134217728


class PendingPartialWithdrawals(SSZList[PendingPartialWithdrawal]):
    """Pending partial withdrawals."""

    LIMIT = 64 if _MINIMAL else 134217728


class PendingConsolidations(SSZList[PendingConsolidation]):
    """Pending consolidations."""

    LIMIT = 64 if _MINIMAL else 262144


class ProposerLookahead(SSZVector[ValidatorIndex]):
    """Proposer lookahead."""

    LENGTH = 16 if _MINIMAL else 64


class Builders(SSZList[Builder]):
    """Builders."""

    LIMIT = 1099511627776


class ExecutionPayloadAvailability(BaseBitvector):
    """Execution payload availability as a fixed-length bitfield."""

    LENGTH = 64 if _MINIMAL else 8192


class BuilderPendingPayments(SSZVector[BuilderPendingPayment]):
    """Builder pending payments."""

    LENGTH = 16 if _MINIMAL else 64


class BuilderPendingWithdrawals(SSZList[BuilderPendingWithdrawal]):
    """Builder pending withdrawals."""

    LIMIT = 1048576


class PayloadExpectedWithdrawals(SSZList[Withdrawal]):
    """Payload expected withdrawals."""

    LIMIT = 4 if _MINIMAL else 16


class PtcWindowElement(SSZVector[ValidatorIndex]):
    """Ptc window element."""

    LENGTH = 16 if _MINIMAL else 512


class PtcWindow(SSZVector[PtcWindowElement]):
    """Ptc window."""

    LENGTH = 24 if _MINIMAL else 96


class BeaconState(Container):
    """Beacon state."""

    genesis_time: Uint64
    """Genesis time."""
    genesis_validators_root: Root
    """Genesis validators root."""
    slot: Slot
    """Slot."""
    fork: Fork
    """Fork."""
    latest_block_header: BeaconBlockHeader
    """Latest block header."""
    block_roots: BlockRoots
    """Block roots."""
    state_roots: StateRoots
    """State roots."""
    historical_roots: HistoricalRoots
    """Historical roots."""
    eth1_data: Eth1Data
    """Eth1 data."""
    eth1_data_votes: Eth1DataVotes
    """Eth1 data votes."""
    eth1_deposit_index: Uint64
    """Eth1 deposit index."""
    validators: Validators
    """Validators."""
    balances: Balances
    """Balances."""
    randao_mixes: RandaoMixes
    """Randao mixes."""
    slashings: Slashings
    """Slashings."""
    previous_epoch_participation: PreviousEpochParticipation
    """Previous epoch participation."""
    current_epoch_participation: CurrentEpochParticipation
    """Current epoch participation."""
    justification_bits: JustificationBits
    """Justification bits."""
    previous_justified_checkpoint: Checkpoint
    """Previous justified checkpoint."""
    current_justified_checkpoint: Checkpoint
    """Current justified checkpoint."""
    finalized_checkpoint: Checkpoint
    """Finalized checkpoint."""
    inactivity_scores: InactivityScores
    """Inactivity scores."""
    current_sync_committee: SyncCommittee
    """Current sync committee."""
    next_sync_committee: SyncCommittee
    """Next sync committee."""
    latest_block_hash: Hash32
    """Latest block hash."""
    next_withdrawal_index: WithdrawalIndex
    """Next withdrawal index."""
    next_withdrawal_validator_index: ValidatorIndex
    """Next withdrawal validator index."""
    historical_summaries: HistoricalSummaries
    """Historical summaries."""
    deposit_requests_start_index: Uint64
    """Deposit requests start index."""
    deposit_balance_to_consume: Gwei
    """Deposit balance to consume."""
    exit_balance_to_consume: Gwei
    """Exit balance to consume."""
    earliest_exit_epoch: Epoch
    """Earliest exit epoch."""
    consolidation_balance_to_consume: Gwei
    """Consolidation balance to consume."""
    earliest_consolidation_epoch: Epoch
    """Earliest consolidation epoch."""
    pending_deposits: PendingDeposits
    """Pending deposits."""
    pending_partial_withdrawals: PendingPartialWithdrawals
    """Pending partial withdrawals."""
    pending_consolidations: PendingConsolidations
    """Pending consolidations."""
    proposer_lookahead: ProposerLookahead
    """Proposer lookahead."""
    builders: Builders
    """Builders."""
    next_withdrawal_builder_index: BuilderIndex
    """Next withdrawal builder index."""
    execution_payload_availability: ExecutionPayloadAvailability
    """Execution payload availability."""
    builder_pending_payments: BuilderPendingPayments
    """Builder pending payments."""
    builder_pending_withdrawals: BuilderPendingWithdrawals
    """Builder pending withdrawals."""
    latest_execution_payload_bid: ExecutionPayloadBid
    """Latest execution payload bid."""
    payload_expected_withdrawals: PayloadExpectedWithdrawals
    """Payload expected withdrawals."""
    ptc_window: PtcWindow
    """Ptc window."""


class DepositMessage(Container):
    """Deposit message."""

    public_key: BLSPubkey
    """Public key."""
    withdrawal_credentials: Bytes32
    """Withdrawal credentials."""
    amount: Gwei
    """Amount."""


class FixedBytes256(BaseBytes):
    """A fixed byte vector of 256 bytes."""

    LENGTH = 256


class ExtraData(BaseByteList):
    """Extra data as raw variable-length bytes."""

    LIMIT = 32


class Transaction(BaseByteList):
    """Transactions element as raw variable-length bytes."""

    LIMIT = 1073741824


class Transactions(SSZList[Transaction]):
    """Transactions."""

    LIMIT = 1048576


class ExecutionpayloadWithdrawals(SSZList[Withdrawal]):
    """Withdrawals."""

    LIMIT = 4 if _MINIMAL else 16


class BlockAccessList(BaseByteList):
    """Block access list as raw variable-length bytes."""

    LIMIT = 1073741824


class ExecutionPayload(Container):
    """Execution payload."""

    parent_hash: Hash32
    """Parent hash."""
    fee_recipient: ExecutionAddress
    """Fee recipient."""
    state_root: Bytes32
    """State root."""
    receipts_root: Bytes32
    """Receipts root."""
    logs_bloom: FixedBytes256
    """Logs bloom."""
    prev_randao: Bytes32
    """Prev randao."""
    block_number: Uint64
    """Block number."""
    gas_limit: Uint64
    """Gas limit."""
    gas_used: Uint64
    """Gas used."""
    timestamp: Uint64
    """Timestamp."""
    extra_data: ExtraData
    """Extra data."""
    base_fee_per_gas: Uint256
    """Base fee per gas."""
    block_hash: Hash32
    """Block hash."""
    transactions: Transactions
    """Transactions."""
    withdrawals: ExecutionpayloadWithdrawals
    """Withdrawals."""
    blob_gas_used: Uint64
    """Blob gas used."""
    excess_blob_gas: Uint64
    """Excess blob gas."""
    block_access_list: BlockAccessList
    """Block access list."""
    slot_number: Uint64
    """Slot number."""


class ExecutionPayloadEnvelope(Container):
    """Execution payload envelope."""

    payload: ExecutionPayload
    """Payload."""
    execution_requests: ExecutionRequests
    """Execution requests."""
    builder_index: BuilderIndex
    """Builder index."""
    beacon_block_root: Root
    """Beacon block root."""
    parent_beacon_block_root: Root
    """Parent beacon block root."""


class ForkData(Container):
    """Fork data."""

    current_version: Version
    """Current version."""
    genesis_validators_root: Root
    """Genesis validators root."""


class IndexedpayloadattestationAttestingIndices(SSZList[ValidatorIndex]):
    """Attesting indices."""

    LIMIT = 16 if _MINIMAL else 512


class IndexedPayloadAttestation(Container):
    """Indexed payload attestation."""

    attesting_indices: IndexedpayloadattestationAttestingIndices
    """Attesting indices."""
    data: PayloadAttestationData
    """Data."""
    signature: BLSSignature
    """Signature."""


class PayloadAttestationMessage(Container):
    """Payload attestation message."""

    validator_index: ValidatorIndex
    """Validator index."""
    data: PayloadAttestationData
    """Data."""
    signature: BLSSignature
    """Signature."""


class SignedBeaconBlock(Container):
    """Signed beacon block."""

    message: BeaconBlock
    """Message."""
    signature: BLSSignature
    """Signature."""


class SignedExecutionPayloadEnvelope(Container):
    """Signed execution payload envelope."""

    message: ExecutionPayloadEnvelope
    """Message."""
    signature: BLSSignature
    """Signature."""


class SigningData(Container):
    """Signing data."""

    object_root: Root
    """Object root."""
    domain: Domain
    """Domain."""
