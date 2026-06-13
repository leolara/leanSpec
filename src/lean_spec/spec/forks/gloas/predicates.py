"""
Boolean predicates over validators and attestations.

These are pure reads of validator and attestation state: activation and exit
status, slashing eligibility, withdrawal-credential kinds, and indexed-attestation
validity. They carry no state mutation.
"""

from lean_spec.spec.crypto import bls
from lean_spec.spec.forks.gloas.constants import (
    BUILDER_INDEX_FLAG,
    BUILDER_WITHDRAWAL_PREFIX,
    COMPOUNDING_WITHDRAWAL_PREFIX,
    DOMAIN_BEACON_ATTESTER,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    FAR_FUTURE_EPOCH,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    AttestationData,
    BeaconState,
    IndexedAttestation,
    Validator,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BuilderIndex,
    Epoch,
    Gwei,
    ValidatorIndex,
)
from lean_spec.spec.forks.gloas.preset import MAX_EFFECTIVE_BALANCE_ELECTRA, MIN_ACTIVATION_BALANCE
from lean_spec.spec.forks.gloas.signing import compute_signing_root, get_domain
from lean_spec.spec.ssz import Bytes32


def is_active_validator(validator: Validator, epoch: Epoch) -> bool:
    """Check whether a validator is active in the given epoch."""
    return validator.activation_epoch <= epoch < validator.exit_epoch


def is_eligible_for_activation_queue(validator: Validator) -> bool:
    """
    Check whether a validator may enter the activation queue.

    Eligibility requires that the validator has never been queued and already
    holds at least the minimum activation balance.
    """
    return (
        validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        and validator.effective_balance >= MIN_ACTIVATION_BALANCE
    )


def is_eligible_for_activation(state: BeaconState, validator: Validator) -> bool:
    """
    Check whether a queued validator may now be activated.

    The validator's queue placement must be finalized, and it must not already
    have an activation epoch assigned.
    """
    return (
        validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
        and validator.activation_epoch == FAR_FUTURE_EPOCH
    )


def is_slashable_validator(validator: Validator, epoch: Epoch) -> bool:
    """Check whether a validator can be slashed in the given epoch."""
    return (not validator.slashed) and (
        validator.activation_epoch <= epoch < validator.withdrawable_epoch
    )


def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
    """
    Check whether two attestation data are slashable under Casper FFG.

    Two votes are slashable when they are a double vote (distinct data with the
    same target epoch) or a surround vote (one source-to-target span strictly
    contains the other).
    """
    double_vote = data_1 != data_2 and data_1.target.epoch == data_2.target.epoch
    surround_vote = (
        data_1.source.epoch < data_2.source.epoch and data_2.target.epoch < data_1.target.epoch
    )
    return double_vote or surround_vote


def is_compounding_withdrawal_credential(withdrawal_credentials: Bytes32) -> bool:
    """Check whether withdrawal credentials carry the compounding prefix."""
    return bytes(withdrawal_credentials)[:1] == COMPOUNDING_WITHDRAWAL_PREFIX


def has_eth1_withdrawal_credential(validator: Validator) -> bool:
    """Check whether a validator has an execution-address withdrawal credential."""
    return bytes(validator.withdrawal_credentials)[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX


def has_compounding_withdrawal_credential(validator: Validator) -> bool:
    """Check whether a validator has a compounding withdrawal credential."""
    return is_compounding_withdrawal_credential(validator.withdrawal_credentials)


def has_execution_withdrawal_credential(validator: Validator) -> bool:
    """Check whether a validator can withdraw to an execution address."""
    return has_eth1_withdrawal_credential(validator) or has_compounding_withdrawal_credential(
        validator
    )


def get_max_effective_balance(validator: Validator) -> Gwei:
    """
    Return the ceiling on a validator's effective balance.

    Compounding validators may stake far more than the base activation balance.
    """
    if has_compounding_withdrawal_credential(validator):
        return MAX_EFFECTIVE_BALANCE_ELECTRA
    return MIN_ACTIVATION_BALANCE


def is_fully_withdrawable_validator(validator: Validator, balance: Gwei, epoch: Epoch) -> bool:
    """Check whether a validator's whole balance is withdrawable in the epoch."""
    return (
        has_execution_withdrawal_credential(validator)
        and validator.withdrawable_epoch <= epoch
        and balance > Gwei(0)
    )


def is_partially_withdrawable_validator(validator: Validator, balance: Gwei) -> bool:
    """Check whether a validator has withdrawable balance above its ceiling."""
    max_effective_balance = get_max_effective_balance(validator)
    has_max_effective_balance = validator.effective_balance == max_effective_balance
    has_excess_balance = balance > max_effective_balance
    return (
        has_execution_withdrawal_credential(validator)
        and has_max_effective_balance
        and has_excess_balance
    )


def is_builder_index(validator_index: ValidatorIndex) -> bool:
    """
    Check whether an index encodes a builder rather than a validator.

    Builders share the validator index space; the high builder flag bit
    distinguishes them.
    """
    return (int(validator_index) & int(BUILDER_INDEX_FLAG)) != 0


def convert_validator_index_to_builder_index(validator_index: ValidatorIndex) -> BuilderIndex:
    """Strip the builder flag bit to recover a builder-registry index."""
    return BuilderIndex(int(validator_index) & ~int(BUILDER_INDEX_FLAG))


def is_builder_withdrawal_credential(withdrawal_credentials: Bytes32) -> bool:
    """Check whether withdrawal credentials carry the builder prefix."""
    return bytes(withdrawal_credentials)[:1] == BUILDER_WITHDRAWAL_PREFIX


def is_valid_indexed_attestation(
    state: BeaconState, indexed_attestation: IndexedAttestation
) -> bool:
    """Check that an indexed attestation has sorted, unique indices and a valid signature."""
    attesting_indices = list(indexed_attestation.attesting_indices)
    if len(attesting_indices) == 0 or attesting_indices != sorted(set(attesting_indices)):
        return False
    public_keys = [state.validators[index].public_key for index in attesting_indices]
    domain = get_domain(state, DOMAIN_BEACON_ATTESTER, indexed_attestation.data.target.epoch)
    signing_root = compute_signing_root(indexed_attestation.data, domain)
    return bls.FastAggregateVerify(public_keys, signing_root, indexed_attestation.signature)
