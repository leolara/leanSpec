"""
The Gloas fork choice: LMD-GHOST over payload-aware nodes.

The store is a node's local, mutable view of the chain. Block, attestation,
payload, and tick events update it in place; the head is the leaf the
balance-weighted search reaches. Gloas threads payload presence through the
search, so a node is a block root plus its payload-presence decision, and a slot
can fork into an empty branch and a full branch.

The execution engine and blob-data availability are treated as trusted here: the
fork-choice vectors ship payloads the execution layer is assumed to accept.
"""

from copy import deepcopy

from lean_spec.spec.crypto import bls
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.gloas.config import (
    ATTESTATION_DUE_BPS_GLOAS,
    PAYLOAD_ATTESTATION_DUE_BPS,
    PROPOSER_SCORE_BOOST,
    REORG_HEAD_WEIGHT_THRESHOLD,
    SLOT_DURATION_MS,
)
from lean_spec.spec.forks.gloas.constants import (
    ATTESTATION_TIMELINESS_INDEX,
    BASIS_POINTS,
    BUILDER_INDEX_SELF_BUILD,
    DOMAIN_BEACON_BUILDER,
    GENESIS_EPOCH,
    GENESIS_SLOT,
    PTC_TIMELINESS_INDEX,
)
from lean_spec.spec.forks.gloas.containers.beacon_chain import (
    Attestation,
    AttesterSlashing,
    BeaconBlock,
    BeaconState,
    Checkpoint,
    IndexedPayloadAttestation,
    IndexedpayloadattestationAttestingIndices,
    PayloadAttestationMessage,
    PayloadAttestations,
    SignedBeaconBlock,
    SignedExecutionPayloadEnvelope,
)
from lean_spec.spec.forks.gloas.containers.fork_choice import (
    PAYLOAD_STATUS_EMPTY,
    PAYLOAD_STATUS_FULL,
    PAYLOAD_STATUS_PENDING,
    ForkChoiceNode,
    LatestMessage,
    PayloadStatus,
    Store,
)
from lean_spec.spec.forks.gloas.containers.primitives import (
    BLSSignature,
    CommitteeIndex,
    Epoch,
    Gwei,
    Root,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.gloas.preset import (
    DATA_AVAILABILITY_TIMELY_THRESHOLD,
    MIN_SEED_LOOKAHEAD,
    PAYLOAD_TIMELY_THRESHOLD,
    PTC_SIZE,
    SLOTS_PER_EPOCH,
)
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz import Boolean, Uint8, Uint64

_SLOTS_PER_EPOCH = int(SLOTS_PER_EPOCH)
_SLOT_DURATION_MS = int(SLOT_DURATION_MS)
_BASIS_POINTS = int(BASIS_POINTS)
_UINT64_MAX = 2**64 - 1


class ForkChoiceMixin(GloasSpecBase):
    """Fork-choice behavior for the Gloas spec."""

    def get_forkchoice_store(self, anchor_state: BeaconState, anchor_block: BeaconBlock) -> Store:
        """Build the initial store anchored at a trusted block and its post-state."""
        assert anchor_block.state_root == hash_tree_root(anchor_state)
        anchor_root = Root(hash_tree_root(anchor_block))
        anchor_epoch = self.get_current_epoch(anchor_state)
        justified_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
        finalized_checkpoint = Checkpoint(epoch=anchor_epoch, root=anchor_root)
        anchor_time = Uint64(
            int(anchor_state.genesis_time) + _SLOT_DURATION_MS * int(anchor_state.slot) // 1000
        )
        return Store(
            time=anchor_time,
            genesis_time=anchor_state.genesis_time,
            justified_checkpoint=justified_checkpoint,
            finalized_checkpoint=finalized_checkpoint,
            unrealized_justified_checkpoint=justified_checkpoint,
            unrealized_finalized_checkpoint=finalized_checkpoint,
            proposer_boost_root=Root.zero(),
            equivocating_indices=set(),
            blocks={anchor_root: anchor_block},
            block_states={anchor_root: anchor_state},
            block_timeliness={anchor_root: [Boolean(True), Boolean(True)]},
            checkpoint_states={justified_checkpoint: anchor_state},
            unrealized_justifications={anchor_root: justified_checkpoint},
            payloads={},
            payload_timeliness_vote={},
            payload_data_availability_vote={},
        )

    def get_slots_since_genesis(self, store: Store) -> int:
        """Return the number of whole slots that have elapsed since genesis."""
        return (int(store.time) - int(store.genesis_time)) * 1000 // _SLOT_DURATION_MS

    def get_current_slot(self, store: Store) -> Slot:
        """Return the slot the store's clock currently sits in."""
        return Slot(int(GENESIS_SLOT) + self.get_slots_since_genesis(store))

    def get_current_store_epoch(self, store: Store) -> Epoch:
        """Return the epoch the store's clock currently sits in."""
        return self.compute_epoch_at_slot(self.get_current_slot(store))

    def compute_slots_since_epoch_start(self, slot: Slot) -> int:
        """Return how many slots into its epoch a slot is."""
        return int(slot) - int(self.compute_start_slot_at_epoch(self.compute_epoch_at_slot(slot)))

    def get_parent_payload_status(self, store: Store, block: BeaconBlock) -> PayloadStatus:
        """Decide whether a block builds on its parent's full payload or an empty slot."""
        parent = store.blocks[block.parent_root]
        parent_block_hash = block.body.signed_execution_payload_bid.message.parent_block_hash
        message_block_hash = parent.body.signed_execution_payload_bid.message.block_hash
        return (
            PAYLOAD_STATUS_FULL if parent_block_hash == message_block_hash else PAYLOAD_STATUS_EMPTY
        )

    def is_parent_node_full(self, store: Store, block: BeaconBlock) -> bool:
        """Check a block builds on its parent's full payload."""
        return self.get_parent_payload_status(store, block) == PAYLOAD_STATUS_FULL

    def is_payload_verified(self, store: Store, root: Root) -> bool:
        """Check the execution payload envelope for a block has been delivered and verified."""
        return root in store.payloads

    def get_ancestor(self, store: Store, node: ForkChoiceNode, slot: Slot) -> ForkChoiceNode:
        """Walk a node back to its ancestor at or before a slot, carrying payload status."""
        block = store.blocks[node.root]
        if int(block.slot) > int(slot):
            parent = ForkChoiceNode(
                root=block.parent_root,
                payload_status=self.get_parent_payload_status(store, block),
            )
            return self.get_ancestor(store, parent, slot)
        return node

    def is_ancestor(self, store: Store, node: ForkChoiceNode, ancestor: ForkChoiceNode) -> bool:
        """Check a node descends from a candidate ancestor node, matching payload status."""
        node_ancestor = self.get_ancestor(store, node, store.blocks[ancestor.root].slot)
        if node_ancestor.root != ancestor.root:
            return False
        return (
            node_ancestor.payload_status == ancestor.payload_status
            or ancestor.payload_status == PAYLOAD_STATUS_PENDING
        )

    def calculate_committee_fraction(self, state: BeaconState, committee_percent: Uint64) -> Gwei:
        """Return a percentage of one slot's committee weight."""
        committee_weight = int(self.get_total_active_balance(state)) // _SLOTS_PER_EPOCH
        return Gwei(committee_weight * int(committee_percent) // 100)

    def get_checkpoint_block(self, store: Store, root: Root, epoch: Epoch) -> Root:
        """Return the block root at an epoch boundary in a chain."""
        epoch_first_slot = self.compute_start_slot_at_epoch(epoch)
        node = ForkChoiceNode(root=root, payload_status=PAYLOAD_STATUS_PENDING)
        return self.get_ancestor(store, node, epoch_first_slot).root

    def get_supported_node(self, store: Store, message: LatestMessage) -> ForkChoiceNode:
        """Resolve a validator's latest message to the node it supports."""
        block = store.blocks[message.root]
        if int(block.slot) < int(message.slot):
            payload_status = (
                PAYLOAD_STATUS_FULL if message.payload_present else PAYLOAD_STATUS_EMPTY
            )
        else:
            payload_status = PAYLOAD_STATUS_PENDING
        return ForkChoiceNode(root=message.root, payload_status=payload_status)

    def get_attestation_score(self, store: Store, node: ForkChoiceNode, state: BeaconState) -> Gwei:
        """Sum the effective balance of unslashed validators whose latest vote backs a node."""
        unslashed_and_active_indices = [
            validator_index
            for validator_index in self.get_active_validator_indices(
                state, self.get_current_epoch(state)
            )
            if not state.validators[int(validator_index)].slashed
        ]
        return Gwei(
            sum(
                int(state.validators[int(validator_index)].effective_balance)
                for validator_index in unslashed_and_active_indices
                if (
                    validator_index in store.latest_messages
                    and validator_index not in store.equivocating_indices
                    and self.is_ancestor(
                        store,
                        self.get_supported_node(store, store.latest_messages[validator_index]),
                        node,
                    )
                )
            )
        )

    def get_proposer_score(self, store: Store) -> Gwei:
        """Return the proposer-boost weight measured against the justified state."""
        justified_state = store.checkpoint_states[store.justified_checkpoint]
        committee_weight = int(self.get_total_active_balance(justified_state)) // _SLOTS_PER_EPOCH
        return Gwei(committee_weight * int(PROPOSER_SCORE_BOOST) // 100)

    def is_previous_slot_payload_decision(self, store: Store, node: ForkChoiceNode) -> bool:
        """Check a node settles a payload decision for the immediately preceding slot."""
        is_previous_slot = int(store.blocks[node.root].slot) + 1 == int(
            self.get_current_slot(store)
        )
        is_payload_decision = node.payload_status in (PAYLOAD_STATUS_EMPTY, PAYLOAD_STATUS_FULL)
        return is_previous_slot and is_payload_decision

    def should_apply_proposer_boost(self, store: Store) -> bool:
        """Decide whether the current proposer boost still counts toward fork choice."""
        if store.proposer_boost_root == Root.zero():
            return False
        block = store.blocks[store.proposer_boost_root]
        parent = store.blocks[block.parent_root]
        if int(parent.slot) + 1 < int(block.slot):
            return True
        if not self.is_head_weak(store, block.parent_root):
            return True
        # A weak parent from the previous slot keeps the boost only without early equivocations.
        equivocations = [
            root
            for root, other_block in store.blocks.items()
            if (
                store.block_timeliness[root][int(PTC_TIMELINESS_INDEX)]
                and other_block.proposer_index == parent.proposer_index
                and int(other_block.slot) + 1 == int(block.slot)
                and root != block.parent_root
            )
        ]
        return len(equivocations) == 0

    def get_weight(self, store: Store, node: ForkChoiceNode) -> Gwei:
        """Return a node's fork-choice weight: attestation score plus any proposer boost."""
        # A settled prior-slot payload node never carries weight of its own.
        if self.is_previous_slot_payload_decision(store, node):
            return Gwei(0)
        state = store.checkpoint_states[store.justified_checkpoint]
        attestation_score = int(self.get_attestation_score(store, node, state))
        if not self.should_apply_proposer_boost(store):
            return Gwei(attestation_score)
        proposer_boost_node = ForkChoiceNode(
            root=store.proposer_boost_root, payload_status=PAYLOAD_STATUS_PENDING
        )
        proposer_score = 0
        if self.is_ancestor(store, proposer_boost_node, node):
            proposer_score = int(self.get_proposer_score(store))
        return Gwei(attestation_score + proposer_score)

    def get_voting_source(self, store: Store, block_root: Root) -> Checkpoint:
        """Return the justification a block would vote from were it the head."""
        block = store.blocks[block_root]
        current_epoch = self.get_current_store_epoch(store)
        block_epoch = self.compute_epoch_at_slot(block.slot)
        if int(current_epoch) > int(block_epoch):
            return store.unrealized_justifications[block_root]
        return store.block_states[block_root].current_justified_checkpoint

    def filter_block_tree(
        self, store: Store, block_root: Root, blocks: dict[Root, BeaconBlock]
    ) -> bool:
        """Collect into blocks the subtree whose leaves agree with the store's checkpoints."""
        block = store.blocks[block_root]
        children = [root for root in store.blocks if store.blocks[root].parent_root == block_root]
        if any(children):
            filter_results = [self.filter_block_tree(store, child, blocks) for child in children]
            if any(filter_results):
                blocks[block_root] = block
                return True
            return False

        current_epoch = self.get_current_store_epoch(store)
        voting_source = self.get_voting_source(store, block_root)
        correct_justified = (
            int(store.justified_checkpoint.epoch) == int(GENESIS_EPOCH)
            or int(voting_source.epoch) == int(store.justified_checkpoint.epoch)
            or int(voting_source.epoch) + 2 >= int(current_epoch)
        )
        finalized_checkpoint_block = self.get_checkpoint_block(
            store, block_root, store.finalized_checkpoint.epoch
        )
        correct_finalized = (
            int(store.finalized_checkpoint.epoch) == int(GENESIS_EPOCH)
            or store.finalized_checkpoint.root == finalized_checkpoint_block
        )
        if correct_justified and correct_finalized:
            blocks[block_root] = block
            return True
        return False

    def get_filtered_block_tree(self, store: Store) -> dict[Root, BeaconBlock]:
        """Return the viable block subtree rooted at the justified checkpoint."""
        blocks: dict[Root, BeaconBlock] = {}
        self.filter_block_tree(store, store.justified_checkpoint.root, blocks)
        return blocks

    def get_node_children(
        self, store: Store, blocks: dict[Root, BeaconBlock], node: ForkChoiceNode
    ) -> list[ForkChoiceNode]:
        """Return a node's fork-choice children: payload branches, then child blocks."""
        if node.payload_status == PAYLOAD_STATUS_PENDING:
            children = [ForkChoiceNode(root=node.root, payload_status=PAYLOAD_STATUS_EMPTY)]
            if self.is_payload_verified(store, node.root):
                children.append(ForkChoiceNode(root=node.root, payload_status=PAYLOAD_STATUS_FULL))
            return children
        return [
            ForkChoiceNode(root=root, payload_status=PAYLOAD_STATUS_PENDING)
            for root in blocks
            if (
                blocks[root].parent_root == node.root
                and node.payload_status == self.get_parent_payload_status(store, blocks[root])
            )
        ]

    def payload_timeliness(self, store: Store, root: Root, timely: bool) -> bool:
        """Check the payload-timeliness votes for a block clear the timeliness threshold."""
        assert root in store.payload_timeliness_vote
        if not self.is_payload_verified(store, root):
            return not timely
        votes = store.payload_timeliness_vote[root]
        return sum(vote is timely for vote in votes) > int(PAYLOAD_TIMELY_THRESHOLD)

    def payload_data_availability(self, store: Store, root: Root, available: bool) -> bool:
        """Check the data-availability votes for a block clear the availability threshold."""
        assert root in store.payload_data_availability_vote
        if not self.is_payload_verified(store, root):
            return not available
        votes = store.payload_data_availability_vote[root]
        return sum(vote is available for vote in votes) > int(DATA_AVAILABILITY_TIMELY_THRESHOLD)

    def should_extend_payload(self, store: Store, root: Root) -> bool:
        """Decide whether the next proposer should build on a block's full payload."""
        if not self.is_payload_verified(store, root):
            return False
        proposer_root = store.proposer_boost_root
        payload_is_timely = self.payload_timeliness(store, root, timely=True)
        payload_data_is_available = self.payload_data_availability(store, root, available=True)
        return (
            (payload_is_timely and payload_data_is_available)
            or proposer_root == Root.zero()
            or store.blocks[proposer_root].parent_root != root
            or self.is_parent_node_full(store, store.blocks[proposer_root])
        )

    def get_payload_status_tiebreaker(self, store: Store, node: ForkChoiceNode) -> Uint8:
        """Rank a node's payload status, breaking ties on prior-slot payload decisions."""
        if self.is_previous_slot_payload_decision(store, node):
            if node.payload_status == PAYLOAD_STATUS_EMPTY:
                return Uint8(1)
            if self.should_extend_payload(store, node.root):
                return Uint8(2)
            return Uint8(0)
        return Uint8(int(node.payload_status))

    def get_head(self, store: Store) -> ForkChoiceNode:
        """Run payload-aware LMD-GHOST to the head leaf of the viable block tree."""
        blocks = self.get_filtered_block_tree(store)
        head = ForkChoiceNode(
            root=store.justified_checkpoint.root, payload_status=PAYLOAD_STATUS_PENDING
        )
        while True:
            children = self.get_node_children(store, blocks, head)
            if len(children) == 0:
                return head
            head = max(
                children,
                key=lambda child: (
                    int(self.get_weight(store, child)),
                    bytes(child.root),
                    int(self.get_payload_status_tiebreaker(store, child)),
                ),
            )

    def update_checkpoints(
        self, store: Store, justified_checkpoint: Checkpoint, finalized_checkpoint: Checkpoint
    ) -> None:
        """Adopt higher justified and finalized checkpoints into the store."""
        if int(justified_checkpoint.epoch) > int(store.justified_checkpoint.epoch):
            store.justified_checkpoint = justified_checkpoint
        if int(finalized_checkpoint.epoch) > int(store.finalized_checkpoint.epoch):
            store.finalized_checkpoint = finalized_checkpoint

    def update_unrealized_checkpoints(
        self,
        store: Store,
        unrealized_justified_checkpoint: Checkpoint,
        unrealized_finalized_checkpoint: Checkpoint,
    ) -> None:
        """Adopt higher unrealized justified and finalized checkpoints into the store."""
        if int(unrealized_justified_checkpoint.epoch) > int(
            store.unrealized_justified_checkpoint.epoch
        ):
            store.unrealized_justified_checkpoint = unrealized_justified_checkpoint
        if int(unrealized_finalized_checkpoint.epoch) > int(
            store.unrealized_finalized_checkpoint.epoch
        ):
            store.unrealized_finalized_checkpoint = unrealized_finalized_checkpoint

    def compute_pulled_up_tip(self, store: Store, block_root: Root) -> None:
        """Pull a block's post-state to its epoch boundary and record realized checkpoints."""
        state = self.process_justification_and_finalization(
            deepcopy(store.block_states[block_root])
        )
        store.unrealized_justifications[block_root] = state.current_justified_checkpoint
        self.update_unrealized_checkpoints(
            store, state.current_justified_checkpoint, state.finalized_checkpoint
        )
        block_epoch = self.compute_epoch_at_slot(store.blocks[block_root].slot)
        current_epoch = self.get_current_store_epoch(store)
        if int(block_epoch) < int(current_epoch):
            self.update_checkpoints(
                store, state.current_justified_checkpoint, state.finalized_checkpoint
            )

    def on_tick_per_slot(self, store: Store, time: Uint64) -> None:
        """Advance the store's clock by one tick, resetting boost and pulling up at epoch starts."""
        previous_slot = self.get_current_slot(store)
        store.time = time
        current_slot = self.get_current_slot(store)
        if int(current_slot) > int(previous_slot):
            store.proposer_boost_root = Root.zero()
        if (
            int(current_slot) > int(previous_slot)
            and self.compute_slots_since_epoch_start(current_slot) == 0
        ):
            self.update_checkpoints(
                store,
                store.unrealized_justified_checkpoint,
                store.unrealized_finalized_checkpoint,
            )

    def on_tick(self, store: Store, time: Uint64) -> None:
        """Advance the store's clock to a time, processing every intervening slot."""
        tick_slot = (int(time) - int(store.genesis_time)) * 1000 // _SLOT_DURATION_MS
        while int(self.get_current_slot(store)) < tick_slot:
            previous_time = Uint64(
                int(store.genesis_time)
                + (int(self.get_current_slot(store)) + 1) * _SLOT_DURATION_MS // 1000
            )
            self.on_tick_per_slot(store, previous_time)
        self.on_tick_per_slot(store, time)

    def store_target_checkpoint_state(self, store: Store, target: Checkpoint) -> None:
        """Cache the state at a target checkpoint, advancing empty slots if needed."""
        if target not in store.checkpoint_states:
            base_state = deepcopy(store.block_states[target.root])
            target_slot = self.compute_start_slot_at_epoch(target.epoch)
            if int(base_state.slot) < int(target_slot):
                base_state = self.process_slots(base_state, target_slot)
            store.checkpoint_states[target] = base_state

    def update_latest_messages(
        self, store: Store, attesting_indices: list[ValidatorIndex], attestation: Attestation
    ) -> None:
        """Record each non-equivocating attester's vote as its latest message."""
        slot = attestation.data.slot
        beacon_block_root = attestation.data.beacon_block_root
        payload_present = Boolean(int(attestation.data.index) == 1)
        for validator_index in attesting_indices:
            if validator_index in store.equivocating_indices:
                continue
            if validator_index not in store.latest_messages or int(slot) > int(
                store.latest_messages[validator_index].slot
            ):
                store.latest_messages[validator_index] = LatestMessage(
                    slot=slot, root=beacon_block_root, payload_present=payload_present
                )

    def record_block_timeliness(self, store: Store, root: Root) -> None:
        """Record whether a block arrived in time for the attestation and PTC deadlines."""
        block = store.blocks[root]
        time_into_slot_ms = self._time_into_slot_ms(store)
        is_current_slot = int(self.get_current_slot(store)) == int(block.slot)
        attestation_threshold_ms = self._slot_component_ms(ATTESTATION_DUE_BPS_GLOAS)
        ptc_threshold_ms = self._slot_component_ms(PAYLOAD_ATTESTATION_DUE_BPS)
        store.block_timeliness[root] = [
            Boolean(is_current_slot and time_into_slot_ms < threshold)
            for threshold in (attestation_threshold_ms, ptc_threshold_ms)
        ]

    def get_dependent_root(self, store: Store, root: Root) -> Root:
        """Return the shuffling-dependent root for a block's chain."""
        epoch = self.get_current_store_epoch(store)
        if int(epoch) <= int(MIN_SEED_LOOKAHEAD):
            return Root.zero()
        node = ForkChoiceNode(root=root, payload_status=PAYLOAD_STATUS_PENDING)
        dependent_slot = Slot(
            int(self.compute_start_slot_at_epoch(Epoch(int(epoch) - int(MIN_SEED_LOOKAHEAD)))) - 1
        )
        return self.get_ancestor(store, node, dependent_slot).root

    def update_proposer_boost_root(self, store: Store, head: Root, root: Root) -> None:
        """Grant proposer boost to a timely first block sharing the head's dependent root."""
        is_first_block = store.proposer_boost_root == Root.zero()
        is_timely = bool(store.block_timeliness[root][int(ATTESTATION_TIMELINESS_INDEX)])
        is_same_dependent_root = self.get_dependent_root(store, root) == self.get_dependent_root(
            store, head
        )
        if is_timely and is_first_block and is_same_dependent_root:
            store.proposer_boost_root = root

    def on_block(self, store: Store, signed_block: SignedBeaconBlock) -> None:
        """Import a block: validate, transition its state, and fold it into the store."""
        block = signed_block.message
        assert block.parent_root in store.block_states
        if self.is_parent_node_full(store, block):
            assert self.is_payload_verified(store, block.parent_root)
        assert int(self.get_current_slot(store)) >= int(block.slot)
        finalized_slot = self.compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
        assert int(block.slot) > int(finalized_slot)
        finalized_checkpoint_block = self.get_checkpoint_block(
            store, block.parent_root, store.finalized_checkpoint.epoch
        )
        assert store.finalized_checkpoint.root == finalized_checkpoint_block

        state = deepcopy(store.block_states[block.parent_root])
        block_root = Root(hash_tree_root(block))
        state = self.state_transition(state, signed_block, validate_result=True)

        head = self.get_head(store)
        store.blocks[block_root] = block
        store.block_states[block_root] = state
        store.payload_timeliness_vote[block_root] = [None] * int(PTC_SIZE)
        store.payload_data_availability_vote[block_root] = [None] * int(PTC_SIZE)

        self.notify_ptc_messages(store, state, block.body.payload_attestations)
        self.record_block_timeliness(store, block_root)
        self.update_proposer_boost_root(store, head.root, block_root)
        self.update_checkpoints(
            store, state.current_justified_checkpoint, state.finalized_checkpoint
        )
        self.compute_pulled_up_tip(store, block_root)

    def validate_target_epoch_against_current_time(
        self, store: Store, attestation: Attestation
    ) -> None:
        """Check an off-chain attestation targets the current or previous epoch."""
        target = attestation.data.target
        current_epoch = self.get_current_store_epoch(store)
        previous_epoch = (
            Epoch(int(current_epoch) - 1)
            if int(current_epoch) > int(GENESIS_EPOCH)
            else GENESIS_EPOCH
        )
        assert target.epoch in (current_epoch, previous_epoch)

    def validate_on_attestation(
        self, store: Store, attestation: Attestation, is_from_block: bool
    ) -> None:
        """Check an attestation is well-timed, references known blocks, and is self-consistent."""
        target = attestation.data.target
        if not is_from_block:
            self.validate_target_epoch_against_current_time(store, attestation)
        assert target.epoch == self.compute_epoch_at_slot(attestation.data.slot)
        assert target.root in store.blocks
        assert attestation.data.beacon_block_root in store.blocks
        block_slot = store.blocks[attestation.data.beacon_block_root].slot
        assert int(block_slot) <= int(attestation.data.slot)
        assert int(attestation.data.index) in (0, 1)
        if int(block_slot) == int(attestation.data.slot):
            assert int(attestation.data.index) == 0
        if int(attestation.data.index) == 1:
            assert self.is_payload_verified(store, attestation.data.beacon_block_root)
        assert target.root == self.get_checkpoint_block(
            store, attestation.data.beacon_block_root, target.epoch
        )
        assert int(self.get_current_slot(store)) >= int(attestation.data.slot) + 1

    def on_attestation(
        self, store: Store, attestation: Attestation, is_from_block: bool = False
    ) -> None:
        """Import an attestation, updating the latest messages of its attesters."""
        self.validate_on_attestation(store, attestation, is_from_block)
        self.store_target_checkpoint_state(store, attestation.data.target)
        target_state = store.checkpoint_states[attestation.data.target]
        indexed_attestation = self.get_indexed_attestation(target_state, attestation)
        assert self.is_valid_indexed_attestation(target_state, indexed_attestation)
        self.update_latest_messages(store, list(indexed_attestation.attesting_indices), attestation)

    def on_attester_slashing(self, store: Store, attester_slashing: AttesterSlashing) -> None:
        """Mark the validators common to a slashable attestation pair as equivocating."""
        attestation_1 = attester_slashing.attestation_1
        attestation_2 = attester_slashing.attestation_2
        assert self.is_slashable_attestation_data(attestation_1.data, attestation_2.data)
        state = store.block_states[store.justified_checkpoint.root]
        assert self.is_valid_indexed_attestation(state, attestation_1)
        assert self.is_valid_indexed_attestation(state, attestation_2)
        common_indices = set(attestation_1.attesting_indices) & set(attestation_2.attesting_indices)
        for validator_index in common_indices:
            store.equivocating_indices.add(validator_index)

    def notify_ptc_messages(
        self, store: Store, state: BeaconState, payload_attestations: PayloadAttestations
    ) -> None:
        """Feed a block's payload attestations into the store as PTC messages."""
        if int(state.slot) == 0:
            return
        for payload_attestation in payload_attestations:
            indexed = self.get_indexed_payload_attestation(state, payload_attestation)
            for validator_index in indexed.attesting_indices:
                self.on_payload_attestation_message(
                    store,
                    PayloadAttestationMessage(
                        validator_index=validator_index,
                        data=payload_attestation.data,
                        signature=BLSSignature.zero(),
                    ),
                    is_from_block=True,
                )

    def on_payload_attestation_message(
        self, store: Store, ptc_message: PayloadAttestationMessage, is_from_block: bool = False
    ) -> None:
        """Record a PTC member's timeliness and availability votes for its assigned block."""
        data = ptc_message.data
        assert data.beacon_block_root in store.block_states
        state = store.block_states[data.beacon_block_root]
        if int(data.slot) != int(state.slot):
            return
        payload_timeliness_committee = self.get_ptc(state, data.slot)
        ptc_indices = [
            ptc_index
            for ptc_index, validator_index in enumerate(payload_timeliness_committee)
            if validator_index == ptc_message.validator_index
        ]
        assert len(ptc_indices) > 0
        if not is_from_block:
            assert int(data.slot) == int(self.get_current_slot(store))
            assert self.is_valid_indexed_payload_attestation(
                state,
                IndexedPayloadAttestation(
                    attesting_indices=IndexedpayloadattestationAttestingIndices(
                        data=[ptc_message.validator_index]
                    ),
                    data=data,
                    signature=ptc_message.signature,
                ),
            )
        timeliness_votes = store.payload_timeliness_vote[data.beacon_block_root]
        availability_votes = store.payload_data_availability_vote[data.beacon_block_root]
        for ptc_index in ptc_indices:
            timeliness_votes[ptc_index] = data.payload_present
            availability_votes[ptc_index] = data.blob_data_available

    def on_execution_payload_envelope(
        self, store: Store, signed_envelope: SignedExecutionPayloadEnvelope
    ) -> None:
        """Verify a delivered execution payload envelope and record it in the store."""
        envelope = signed_envelope.message
        assert envelope.beacon_block_root in store.block_states
        state = store.block_states[envelope.beacon_block_root]
        self.verify_execution_payload_envelope(state, signed_envelope)
        store.payloads[envelope.beacon_block_root] = envelope

    def verify_execution_payload_envelope(
        self, state: BeaconState, signed_envelope: SignedExecutionPayloadEnvelope
    ) -> None:
        """Check an envelope's signature and consistency with the block and the committed bid."""
        envelope = signed_envelope.message
        payload = envelope.payload
        assert self.verify_execution_payload_envelope_signature(state, signed_envelope)

        header = state.latest_block_header.model_copy(
            update={"state_root": Root(hash_tree_root(state))}
        )
        assert envelope.beacon_block_root == Root(hash_tree_root(header))
        assert envelope.parent_beacon_block_root == state.latest_block_header.parent_root

        bid = state.latest_execution_payload_bid
        assert envelope.builder_index == bid.builder_index
        assert payload.previous_randao == bid.previous_randao
        assert payload.gas_limit == bid.gas_limit
        assert payload.block_hash == bid.block_hash
        assert hash_tree_root(envelope.execution_requests) == bid.execution_requests_root

        assert int(payload.slot_number) == int(state.slot)
        assert payload.parent_hash == state.latest_block_hash
        assert int(payload.timestamp) == int(self._compute_time_at_slot(state, state.slot))
        assert hash_tree_root(payload.withdrawals) == hash_tree_root(
            state.payload_expected_withdrawals
        )

    def verify_execution_payload_envelope_signature(
        self, state: BeaconState, signed_envelope: SignedExecutionPayloadEnvelope
    ) -> bool:
        """Check a payload envelope is signed by its builder, or the proposer for a self-build."""
        builder_index = signed_envelope.message.builder_index
        if int(builder_index) == BUILDER_INDEX_SELF_BUILD:
            proposer_index = int(state.latest_block_header.proposer_index)
            public_key = state.validators[proposer_index].public_key
        else:
            public_key = state.builders[int(builder_index)].public_key
        signing_root = self.compute_signing_root(
            signed_envelope.message, self.get_domain(state, DOMAIN_BEACON_BUILDER)
        )
        return bls.Verify(public_key, signing_root, signed_envelope.signature)

    def is_head_late(self, store: Store, head_root: Root) -> bool:
        """Check the head block arrived after the attestation deadline."""
        return not bool(store.block_timeliness[head_root][int(ATTESTATION_TIMELINESS_INDEX)])

    def is_head_weak(self, store: Store, head_root: Root) -> bool:
        """Check a head's weight, counting equivocations, is below the re-org threshold."""
        justified_state = store.checkpoint_states[store.justified_checkpoint]
        reorg_threshold = int(
            self.calculate_committee_fraction(justified_state, REORG_HEAD_WEIGHT_THRESHOLD)
        )
        head_block = store.blocks[head_root]
        epoch = self.compute_epoch_at_slot(head_block.slot)
        head_node = ForkChoiceNode(root=head_root, payload_status=PAYLOAD_STATUS_PENDING)
        head_weight = int(self.get_attestation_score(store, head_node, justified_state))
        for committee_index in range(
            int(self.get_committee_count_per_slot(justified_state, epoch))
        ):
            committee = self.get_beacon_committee(
                justified_state, head_block.slot, CommitteeIndex(committee_index)
            )
            head_weight += sum(
                int(justified_state.validators[int(i)].effective_balance)
                for i in committee
                if i in store.equivocating_indices
            )
        return head_weight < reorg_threshold

    def _slot_component_ms(self, basis_points: Uint64) -> int:
        """Return the millisecond offset into a slot for a basis-point fraction."""
        return int(basis_points) * _SLOT_DURATION_MS // _BASIS_POINTS

    def _time_into_slot_ms(self, store: Store) -> int:
        """Return how many milliseconds the store's clock is into the current slot."""
        seconds_since_genesis = int(store.time) - int(store.genesis_time)
        return self._seconds_to_milliseconds(seconds_since_genesis) % _SLOT_DURATION_MS

    def _seconds_to_milliseconds(self, seconds: int) -> int:
        """Convert seconds to milliseconds, saturating at the unsigned 64-bit ceiling."""
        if seconds > _UINT64_MAX // 1000:
            return _UINT64_MAX
        return seconds * 1000

    def _compute_time_at_slot(self, state: BeaconState, slot: Slot) -> int:
        """Return the wall-clock seconds at the start of a slot."""
        slots_since_genesis = int(slot) - int(GENESIS_SLOT)
        return int(state.genesis_time) + slots_since_genesis * _SLOT_DURATION_MS // 1000
