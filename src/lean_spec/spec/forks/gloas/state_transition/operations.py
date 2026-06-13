"""
Block-operation processing.

Each function validates one operation against the pre-state and returns the
post-state. A failed validation raises, which the upstream vectors signal by
shipping no post-state for that case.
"""

from hashlib import sha256

from lean_spec.spec.crypto import bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.accessors import (
    add_flag,
    compute_epoch_at_slot,
    get_attestation_participation_flag_indices,
    get_attesting_indices,
    get_base_reward,
    get_beacon_committee,
    get_beacon_proposer_index,
    get_committee_count_per_slot,
    get_committee_indices,
    get_current_epoch,
    get_indexed_attestation,
    get_previous_epoch,
    has_flag,
    is_attestation_same_slot,
)
from lean_spec.spec.forks.gloas.constants import (
    BLS_WITHDRAWAL_PREFIX,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BLS_TO_EXECUTION_CHANGE,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
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
    ProposerSlashing,
    SignedBLSToExecutionChange,
    Validators,
)
from lean_spec.spec.forks.gloas.containers.primitives import Gwei, Root
from lean_spec.spec.forks.gloas.predicates import (
    is_slashable_attestation_data,
    is_slashable_validator,
    is_valid_indexed_attestation,
)
from lean_spec.spec.forks.gloas.preset import MIN_ATTESTATION_INCLUSION_DELAY, SLOTS_PER_EPOCH
from lean_spec.spec.forks.gloas.signing import compute_domain, compute_signing_root, get_domain
from lean_spec.spec.forks.gloas.state_transition.mutators import increase_balance, slash_validator
from lean_spec.spec.ssz import Bytes32, Uint64

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)


def _zero_builder_payment() -> BuilderPendingPayment:
    """Return an all-zero builder pending payment, the empty-slot placeholder."""
    return BuilderPendingPayment.decode_bytes(b"\x00" * BuilderPendingPayment.get_byte_length())


# A validator's withdrawal credentials are a one-byte prefix followed by 11 zero
# bytes and the 20-byte execution address.
_EXECUTION_CREDENTIAL_PADDING = b"\x00" * 11


def process_bls_to_execution_change(
    state: BeaconState, signed_address_change: SignedBLSToExecutionChange
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
    assert current_credentials[1:] == sha256(bytes(address_change.from_bls_public_key)).digest()[1:]

    domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE, genesis_validators_root=state.genesis_validators_root
    )
    signing_root = compute_signing_root(address_change, domain)
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


def _reset_builder_payment(state: BeaconState, payment_index: int) -> BeaconState:
    """Return a state with one builder pending payment slot cleared to zero."""
    payments = list(state.builder_pending_payments)
    payments[payment_index] = _zero_builder_payment()
    return state.model_copy(
        update={"builder_pending_payments": BuilderPendingPayments(data=payments)}
    )


def process_proposer_slashing(
    state: BeaconState, proposer_slashing: ProposerSlashing
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
    assert is_slashable_validator(proposer, get_current_epoch(state))
    for signed_header in (proposer_slashing.signed_header_1, proposer_slashing.signed_header_2):
        domain = get_domain(
            state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(signed_header.message.slot)
        )
        signing_root = compute_signing_root(signed_header.message, domain)
        assert bls.Verify(proposer.public_key, signing_root, signed_header.signature)

    slot = header_1.slot
    proposal_epoch = compute_epoch_at_slot(slot)
    if proposal_epoch == get_current_epoch(state):
        state = _reset_builder_payment(state, _SLOTS_PER_EPOCH + int(slot) % _SLOTS_PER_EPOCH)
    elif proposal_epoch == get_previous_epoch(state):
        state = _reset_builder_payment(state, int(slot) % _SLOTS_PER_EPOCH)

    return slash_validator(state, header_1.proposer_index)


def process_attester_slashing(
    state: BeaconState, attester_slashing: AttesterSlashing
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
    assert is_slashable_attestation_data(attestation_1.data, attestation_2.data)
    assert is_valid_indexed_attestation(state, attestation_1)
    assert is_valid_indexed_attestation(state, attestation_2)

    common_indices = set(attestation_1.attesting_indices) & set(attestation_2.attesting_indices)
    current_epoch = get_current_epoch(state)
    slashed_any = False
    for index in sorted(common_indices):
        if is_slashable_validator(state.validators[index], current_epoch):
            state = slash_validator(state, index)
            slashed_any = True
    assert slashed_any
    return state


def process_block_header(state: BeaconState, block: BeaconBlock) -> BeaconState:
    """
    Validate a block's header against the state and record it as the latest.

    Raises:
        AssertionError: If the slot, proposer, or parent root is wrong, or the proposer is slashed.
    """
    assert block.slot == state.slot
    assert int(block.slot) > int(state.latest_block_header.slot)
    assert block.proposer_index == get_beacon_proposer_index(state)
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


def process_attestation(state: BeaconState, attestation: Attestation) -> BeaconState:
    """
    Record an attestation's participation flags and reward the proposer.

    Each newly set timeliness flag earns the proposer a share; for a same-slot
    attestation, the attester's balance also adds to the slot's builder payment
    weight, so each validator contributes to the slot quorum exactly once.

    Raises:
        AssertionError: If the attestation is malformed, mistimed, or has an invalid signature.
    """
    data = attestation.data
    assert data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))
    assert data.target.epoch == compute_epoch_at_slot(data.slot)
    assert int(data.slot) + int(MIN_ATTESTATION_INCLUSION_DELAY) <= int(state.slot)
    assert int(data.index) < 2

    committee_offset = 0
    for committee_index in get_committee_indices(attestation.committee_bits):
        assert int(committee_index) < int(get_committee_count_per_slot(state, data.target.epoch))
        committee = get_beacon_committee(state, data.slot, committee_index)
        attesters = {
            attester
            for position, attester in enumerate(committee)
            if attestation.aggregation_bits[committee_offset + position]
        }
        assert len(attesters) > 0
        committee_offset += len(committee)
    assert len(attestation.aggregation_bits) == committee_offset

    inclusion_delay = Uint64(int(state.slot) - int(data.slot))
    participation_flag_indices = get_attestation_participation_flag_indices(
        state, data, inclusion_delay
    )
    assert is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))

    current_epoch_target = data.target.epoch == get_current_epoch(state)
    if current_epoch_target:
        epoch_participation = list(state.current_epoch_participation)
        payment_index = _SLOTS_PER_EPOCH + int(data.slot) % _SLOTS_PER_EPOCH
    else:
        epoch_participation = list(state.previous_epoch_participation)
        payment_index = int(data.slot) % _SLOTS_PER_EPOCH
    payment = state.builder_pending_payments[payment_index]
    payment_weight = int(payment.weight)
    same_slot = is_attestation_same_slot(state, data)
    payment_has_amount = int(payment.withdrawal.amount) > 0

    proposer_reward_numerator = 0
    for index in get_attesting_indices(state, attestation):
        position = int(index)
        set_new_flag = False
        for flag_index, weight in enumerate(PARTICIPATION_FLAG_WEIGHTS):
            if flag_index in participation_flag_indices and not has_flag(
                epoch_participation[position], flag_index
            ):
                epoch_participation[position] = add_flag(epoch_participation[position], flag_index)
                proposer_reward_numerator += int(get_base_reward(state, index)) * int(weight)
                set_new_flag = True
        if set_new_flag and same_slot and payment_has_amount:
            payment_weight += int(state.validators[position].effective_balance)

    participation_field = (
        "current_epoch_participation" if current_epoch_target else "previous_epoch_participation"
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
    state = increase_balance(state, get_beacon_proposer_index(state), proposer_reward)

    updated_payment = payment.model_copy(update={"weight": Uint64(payment_weight)})
    payments = list(state.builder_pending_payments)
    payments[payment_index] = updated_payment
    return state.model_copy(
        update={"builder_pending_payments": BuilderPendingPayments(data=payments)}
    )
