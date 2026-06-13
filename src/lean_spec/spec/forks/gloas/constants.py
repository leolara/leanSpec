"""
Protocol constants for the Gloas reference port.

These values are fixed by the consensus specification and do not vary by
preset: signature domain tags, reward weights, withdrawal prefixes, and the
other constants shared across every network.
"""

from lean_spec.spec.forks.gloas.containers.primitives import (
    BLSSignature,
    DomainType,
    Epoch,
    Hash32,
    Slot,
)
from lean_spec.spec.ssz import Uint64, Uint256

UINT64_MAX = Uint64(18446744073709551615)
"""Uint64 max."""

UINT64_MAX_SQRT = Uint64(4294967295)
"""Uint64 max sqrt."""

GENESIS_SLOT = Slot(0)
"""Genesis slot."""

GENESIS_EPOCH = Epoch(0)
"""Genesis epoch."""

FAR_FUTURE_EPOCH = Epoch(18446744073709551615)
"""Far future epoch."""

BASE_REWARDS_PER_EPOCH = Uint64(4)
"""Base rewards per epoch."""

DEPOSIT_CONTRACT_TREE_DEPTH = Uint64(32)
"""Deposit contract tree depth."""

JUSTIFICATION_BITS_LENGTH = Uint64(4)
"""Justification bits length."""

BLS_WITHDRAWAL_PREFIX = bytes.fromhex("00")
"""Bls withdrawal prefix."""

ETH1_ADDRESS_WITHDRAWAL_PREFIX = bytes.fromhex("01")
"""Eth1 address withdrawal prefix."""

DOMAIN_BEACON_PROPOSER = DomainType("0x00000000")
"""Domain beacon proposer."""

DOMAIN_BEACON_ATTESTER = DomainType("0x01000000")
"""Domain beacon attester."""

DOMAIN_RANDAO = DomainType("0x02000000")
"""Domain randao."""

DOMAIN_DEPOSIT = DomainType("0x03000000")
"""Domain deposit."""

DOMAIN_VOLUNTARY_EXIT = DomainType("0x04000000")
"""Domain voluntary exit."""

DOMAIN_SELECTION_PROOF = DomainType("0x05000000")
"""Domain selection proof."""

DOMAIN_AGGREGATE_AND_PROOF = DomainType("0x06000000")
"""Domain aggregate and proof."""

DOMAIN_APPLICATION_MASK = DomainType("0x00000001")
"""Domain application mask."""

COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR = Uint64(5)
"""Committee weight estimation adjustment factor."""

BASIS_POINTS = Uint64(10000)
"""Basis points."""

NODE_ID_BITS = 256
"""Node id bits."""

MAX_CONCURRENT_REQUESTS = 2
"""Max concurrent requests."""

TARGET_AGGREGATORS_PER_COMMITTEE = 16
"""Target aggregators per committee."""

ETH_TO_GWEI = Uint64(1000000000)
"""Eth to gwei."""

SAFETY_DECAY = Uint64(10)
"""Safety decay."""

TIMELY_SOURCE_FLAG_INDEX = 0
"""Timely source flag index."""

TIMELY_TARGET_FLAG_INDEX = 1
"""Timely target flag index."""

TIMELY_HEAD_FLAG_INDEX = 2
"""Timely head flag index."""

TIMELY_SOURCE_WEIGHT = Uint64(14)
"""Timely source weight."""

TIMELY_TARGET_WEIGHT = Uint64(26)
"""Timely target weight."""

TIMELY_HEAD_WEIGHT = Uint64(14)
"""Timely head weight."""

SYNC_REWARD_WEIGHT = Uint64(2)
"""Sync reward weight."""

PROPOSER_WEIGHT = Uint64(8)
"""Proposer weight."""

WEIGHT_DENOMINATOR = Uint64(64)
"""Weight denominator."""

DOMAIN_SYNC_COMMITTEE = DomainType("0x07000000")
"""Domain sync committee."""

DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF = DomainType("0x08000000")
"""Domain sync committee selection proof."""

DOMAIN_CONTRIBUTION_AND_PROOF = DomainType("0x09000000")
"""Domain contribution and proof."""

PARTICIPATION_FLAG_WEIGHTS = [Uint64(14), Uint64(26), Uint64(14)]
"""Participation flag weights."""

G2_POINT_AT_INFINITY = BLSSignature(
    "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
"""G2 point at infinity."""

TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16
"""Target aggregators per sync subcommittee."""

SYNC_COMMITTEE_SUBNET_COUNT = 4
"""Sync committee subnet count."""

MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128
"""Max request light client updates."""

EMPTY_BLOCK_HASH = Hash32("0x0000000000000000000000000000000000000000000000000000000000000000")
"""Empty block hash."""

PAYLOAD_STATUS_VALID = 0
"""Payload status valid."""

PAYLOAD_STATUS_INVALIDATED = 1
"""Payload status invalidated."""

PAYLOAD_STATUS_NOT_VALIDATED = 2
"""Payload status not validated."""

SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY = 128
"""Safe slots to import optimistically."""

DOMAIN_BLS_TO_EXECUTION_CHANGE = DomainType("0x0a000000")
"""Domain bls to execution change."""

VERSIONED_HASH_VERSION_KZG = bytes.fromhex("01")
"""Versioned hash version kzg."""

UNSET_DEPOSIT_REQUESTS_START_INDEX = Uint64(18446744073709551615)
"""Unset deposit requests start index."""

FULL_EXIT_REQUEST_AMOUNT = Uint64(0)
"""Full exit request amount."""

COMPOUNDING_WITHDRAWAL_PREFIX = bytes.fromhex("02")
"""Compounding withdrawal prefix."""

DEPOSIT_REQUEST_TYPE = bytes.fromhex("00")
"""Deposit request type."""

WITHDRAWAL_REQUEST_TYPE = bytes.fromhex("01")
"""Withdrawal request type."""

CONSOLIDATION_REQUEST_TYPE = bytes.fromhex("02")
"""Consolidation request type."""

UINT256_MAX = Uint256(
    115792089237316195423570985008687907853269984665640564039457584007913129639935
)
"""Uint256 max."""

BUILDER_INDEX_FLAG = Uint64(1099511627776)
"""Builder index flag."""

DOMAIN_BEACON_BUILDER = DomainType("0x0b000000")
"""Domain beacon builder."""

DOMAIN_PTC_ATTESTER = DomainType("0x0c000000")
"""Domain ptc attester."""

DOMAIN_PROPOSER_PREFERENCES = DomainType("0x0d000000")
"""Domain proposer preferences."""

BUILDER_INDEX_SELF_BUILD = 18446744073709551615
"""Builder index self build."""

BUILDER_PAYMENT_THRESHOLD_NUMERATOR = Uint64(6)
"""Builder payment threshold numerator."""

BUILDER_PAYMENT_THRESHOLD_DENOMINATOR = Uint64(10)
"""Builder payment threshold denominator."""

BUILDER_WITHDRAWAL_PREFIX = bytes.fromhex("03")
"""Builder withdrawal prefix."""

PAYLOAD_STATUS_EMPTY = 0
"""Payload status empty."""

PAYLOAD_STATUS_FULL = 1
"""Payload status full."""

PAYLOAD_STATUS_PENDING = 2
"""Payload status pending."""

ATTESTATION_TIMELINESS_INDEX = 0
"""Attestation timeliness index."""

PTC_TIMELINESS_INDEX = 1
"""Ptc timeliness index."""

NUM_BLOCK_TIMELINESS_DEADLINES = 2
"""Num block timeliness deadlines."""
