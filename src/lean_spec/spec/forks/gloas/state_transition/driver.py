"""
The top-level state transition driver in the immutable lstar style.

A signed block is imported by advancing empty slots to the block's slot, verifying
the proposer signature, applying the block, and checking the resulting state root.
Each step returns a new state through functional copies rather than mutating in
place.
"""

from hashlib import sha256

from lean_spec.spec.crypto import bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.constants import DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    BeaconBlock,
    BeaconBlockBody,
    BeaconState,
    BlockRoots,
    Eth1DataVotes,
    ExecutionPayloadAvailability,
    RandaoMixes,
    SignedBeaconBlock,
    StateRoots,
)
from lean_spec.spec.forks.gloas.containers.primitives import Bytes32, Root, Slot
from lean_spec.spec.forks.gloas.helpers.math import xor
from lean_spec.spec.forks.gloas.preset import (
    EPOCHS_PER_ETH1_VOTING_PERIOD,
    EPOCHS_PER_HISTORICAL_VECTOR,
    SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Boolean

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_SLOTS_PER_HISTORICAL_ROOT = int(SLOTS_PER_HISTORICAL_ROOT)
_EPOCHS_PER_HISTORICAL_VECTOR = int(EPOCHS_PER_HISTORICAL_VECTOR)
_EPOCHS_PER_ETH1_VOTING_PERIOD = int(EPOCHS_PER_ETH1_VOTING_PERIOD)


class StateTransitionMixin(GloasSpecBase):
    """Top-level state transition behavior for the Gloas spec."""

    def state_transition(
        self, state: BeaconState, signed_block: SignedBeaconBlock, validate_result: bool = True
    ) -> BeaconState:
        """Advance to the block's slot, verify it, apply it, and check the state root."""
        block = signed_block.message
        state = self.process_slots(state, block.slot)
        if validate_result:
            assert self.verify_block_signature(state, signed_block)
        state = self.process_block(state, block)
        if validate_result:
            assert block.state_root == hash_tree_root(state)
        return state

    def verify_block_signature(self, state: BeaconState, signed_block: SignedBeaconBlock) -> bool:
        """Check the block is signed by its named proposer."""
        proposer = state.validators[int(signed_block.message.proposer_index)]
        signing_root = self.compute_signing_root(
            signed_block.message, self.get_domain(state, DOMAIN_BEACON_PROPOSER)
        )
        return bls.Verify(proposer.public_key, signing_root, signed_block.signature)

    def process_slots(self, state: BeaconState, slot: Slot) -> BeaconState:
        """
        Advance the state to a slot, running epoch processing at each boundary.

        Raises:
            AssertionError: If the target slot is not strictly in the future.
        """
        assert int(state.slot) < int(slot)
        while int(state.slot) < int(slot):
            state = self.process_slot(state)
            # Run the epoch transition on the last slot of an epoch.
            if (int(state.slot) + 1) % _SLOTS_PER_EPOCH == 0:
                state = self.process_epoch(state)
            state = state.model_copy(update={"slot": Slot(int(state.slot) + 1)})
        return state

    def process_slot(self, state: BeaconState) -> BeaconState:
        """Cache the state and block roots for the current slot and clear next availability."""
        slot_position = int(state.slot) % _SLOTS_PER_HISTORICAL_ROOT
        previous_state_root = Root(hash_tree_root(state))
        state_roots = list(state.state_roots)
        state_roots[slot_position] = previous_state_root
        state = state.model_copy(update={"state_roots": StateRoots(data=state_roots)})

        # Fill the latest header's empty state root so its block root is well-defined.
        if state.latest_block_header.state_root == Root.zero():
            filled_header = state.latest_block_header.model_copy(
                update={"state_root": previous_state_root}
            )
            state = state.model_copy(update={"latest_block_header": filled_header})

        previous_block_root = Root(hash_tree_root(state.latest_block_header))
        block_roots = list(state.block_roots)
        block_roots[slot_position] = previous_block_root
        state = state.model_copy(update={"block_roots": BlockRoots(data=block_roots)})

        # The next slot's payload is not yet available until its block proves it.
        availability = list(state.execution_payload_availability.data)
        availability[(int(state.slot) + 1) % _SLOTS_PER_HISTORICAL_ROOT] = Boolean(False)
        return state.model_copy(
            update={
                "execution_payload_availability": ExecutionPayloadAvailability(data=availability)
            }
        )

    def process_block(self, state: BeaconState, block: BeaconBlock) -> BeaconState:
        """Apply one block: import the parent payload, then the header, payload, and operations."""
        state = self.process_parent_execution_payload(state, block)
        state = self.process_block_header(state, block)
        state = self.process_withdrawals(state)
        state = self.process_execution_payload_bid(state, block)
        state = self.process_randao(state, block.body)
        state = self.process_eth1_data(state, block.body)
        state = self.process_operations(state, block.body)
        return self.process_sync_aggregate(state, block.body.sync_aggregate)

    def process_randao(self, state: BeaconState, body: BeaconBlockBody) -> BeaconState:
        """Verify the proposer's randao reveal and mix it into the current epoch's randomness."""
        epoch = self.get_current_epoch(state)
        proposer = state.validators[int(self.get_beacon_proposer_index(state))]
        signing_root = self.compute_signing_root(epoch, self.get_domain(state, DOMAIN_RANDAO))
        assert bls.Verify(proposer.public_key, signing_root, body.randao_reveal)
        mixed = xor(
            self.get_randao_mix(state, epoch),
            Bytes32(sha256(bytes(body.randao_reveal)).digest()),
        )
        randao_mixes = list(state.randao_mixes)
        randao_mixes[int(epoch) % _EPOCHS_PER_HISTORICAL_VECTOR] = mixed
        return state.model_copy(update={"randao_mixes": RandaoMixes(data=randao_mixes)})

    def process_eth1_data(self, state: BeaconState, body: BeaconBlockBody) -> BeaconState:
        """Record the block's eth1 vote and adopt it once it wins a majority of the period."""
        votes = [*list(state.eth1_data_votes), body.eth1_data]
        state = state.model_copy(update={"eth1_data_votes": Eth1DataVotes(data=votes)})
        if votes.count(body.eth1_data) * 2 > _EPOCHS_PER_ETH1_VOTING_PERIOD * _SLOTS_PER_EPOCH:
            state = state.model_copy(update={"eth1_data": body.eth1_data})
        return state

    def process_operations(self, state: BeaconState, body: BeaconBlockBody) -> BeaconState:
        """
        Apply every block operation in its fixed order.

        Raises:
            AssertionError: If the block carries any legacy deposit, or an operation is invalid.
        """
        # Deposits move through execution requests in Gloas, so the legacy list is empty.
        assert len(body.deposits) == 0
        for proposer_slashing in body.proposer_slashings:
            state = self.process_proposer_slashing(state, proposer_slashing)
        for attester_slashing in body.attester_slashings:
            state = self.process_attester_slashing(state, attester_slashing)
        for attestation in body.attestations:
            state = self.process_attestation(state, attestation)
        for voluntary_exit in body.voluntary_exits:
            state = self.process_voluntary_exit(state, voluntary_exit)
        for signed_address_change in body.bls_to_execution_changes:
            state = self.process_bls_to_execution_change(state, signed_address_change)
        for payload_attestation in body.payload_attestations:
            state = self.process_payload_attestation(state, payload_attestation)
        return state
