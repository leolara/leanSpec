"""
Protocol constants for the Gloas reference port.

These values are fixed by the consensus specification and do not vary by
preset: signature domain tags, reward weights, withdrawal prefixes, and the
other constants shared across every network.
"""

from lean_spec.spec.forks.beacon.gloas.containers.primitives import (
    BLSSignature,
    DomainType,
    Epoch,
    Slot,
)
from lean_spec.spec.ssz import Uint64

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

BASIS_POINTS = Uint64(10000)
"""Basis points."""

MAX_CONCURRENT_REQUESTS = 2
"""Max concurrent requests."""

TIMELY_SOURCE_FLAG_INDEX = 0
"""Timely source flag index."""

TIMELY_TARGET_FLAG_INDEX = 1
"""Timely target flag index."""

TIMELY_HEAD_FLAG_INDEX = 2
"""Timely head flag index."""

SYNC_REWARD_WEIGHT = Uint64(2)
"""Sync reward weight."""

PROPOSER_WEIGHT = Uint64(8)
"""Proposer weight."""

WEIGHT_DENOMINATOR = Uint64(64)
"""Weight denominator."""

DOMAIN_SYNC_COMMITTEE = DomainType("0x07000000")
"""Domain sync committee."""

PARTICIPATION_FLAG_WEIGHTS = [Uint64(14), Uint64(26), Uint64(14)]
"""Participation flag weights."""

G2_POINT_AT_INFINITY = BLSSignature(
    "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
"""G2 point at infinity."""

DOMAIN_BLS_TO_EXECUTION_CHANGE = DomainType("0x0a000000")
"""Domain bls to execution change."""

FULL_EXIT_REQUEST_AMOUNT = Uint64(0)
"""Full exit request amount."""

COMPOUNDING_WITHDRAWAL_PREFIX = bytes.fromhex("02")
"""Compounding withdrawal prefix."""

BUILDER_INDEX_FLAG = Uint64(1099511627776)
"""Builder index flag."""

DOMAIN_BEACON_BUILDER = DomainType("0x0b000000")
"""Domain beacon builder."""

DOMAIN_PTC_ATTESTER = DomainType("0x0c000000")
"""Domain ptc attester."""

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
