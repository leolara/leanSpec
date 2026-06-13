"""
Block-operation processing.

Each function validates one operation against the pre-state and returns the
post-state. A failed validation raises, which the upstream vectors signal by
shipping no post-state for that case.
"""

from hashlib import sha256

from lean_spec.spec.crypto import bls
from lean_spec.spec.forks.gloas.constants import (
    BLS_WITHDRAWAL_PREFIX,
    DOMAIN_BLS_TO_EXECUTION_CHANGE,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    BeaconState,
    SignedBLSToExecutionChange,
    Validators,
)
from lean_spec.spec.forks.gloas.signing import compute_domain, compute_signing_root
from lean_spec.spec.ssz import Bytes32

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
