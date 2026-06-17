"""
Preset-selected constants for the Gloas reference port.

The mainnet and minimal presets differ in committee sizes, history lengths,
and collection limits. One preset is fixed per process by an environment
variable read at import, so the spec stays module-constant style and every
worker in a parallel run shares one consistent preset.
"""

import os

from lean_spec.spec.forks.beacon.gloas.containers.primitives import Gwei
from lean_spec.spec.ssz import Uint64

_PRESET = os.environ.get("GLOAS_PRESET", "mainnet").lower()
"""Active preset, "mainnet" or "minimal", fixed for the whole process."""

if _PRESET not in ("mainnet", "minimal"):
    raise ValueError(f"Invalid GLOAS_PRESET: {_PRESET!r}; expected mainnet or minimal")

MAX_COMMITTEES_PER_SLOT = Uint64(4) if _PRESET == "minimal" else Uint64(64)
"""Max committees per slot (preset-selected)."""

TARGET_COMMITTEE_SIZE = Uint64(4) if _PRESET == "minimal" else Uint64(128)
"""Target committee size (preset-selected)."""

SHUFFLE_ROUND_COUNT = Uint64(10) if _PRESET == "minimal" else Uint64(90)
"""Shuffle round count (preset-selected)."""

HYSTERESIS_QUOTIENT = Uint64(4)
"""Hysteresis quotient (preset constant)."""

HYSTERESIS_DOWNWARD_MULTIPLIER = Uint64(1)
"""Hysteresis downward multiplier (preset constant)."""

HYSTERESIS_UPWARD_MULTIPLIER = Uint64(5)
"""Hysteresis upward multiplier (preset constant)."""

MIN_DEPOSIT_AMOUNT = Gwei(1000000000)
"""Min deposit amount (preset constant)."""

EFFECTIVE_BALANCE_INCREMENT = Gwei(1000000000)
"""Effective balance increment (preset constant)."""

MIN_ATTESTATION_INCLUSION_DELAY = Uint64(1)
"""Min attestation inclusion delay (preset constant)."""

SLOTS_PER_EPOCH = Uint64(8) if _PRESET == "minimal" else Uint64(32)
"""Slots per epoch (preset-selected)."""

MIN_SEED_LOOKAHEAD = Uint64(1)
"""Min seed lookahead (preset constant)."""

MAX_SEED_LOOKAHEAD = Uint64(4)
"""Max seed lookahead (preset constant)."""

MIN_EPOCHS_TO_INACTIVITY_PENALTY = Uint64(4)
"""Min epochs to inactivity penalty (preset constant)."""

EPOCHS_PER_ETH1_VOTING_PERIOD = Uint64(4) if _PRESET == "minimal" else Uint64(64)
"""Epochs per eth1 voting period (preset-selected)."""

SLOTS_PER_HISTORICAL_ROOT = Uint64(64) if _PRESET == "minimal" else Uint64(8192)
"""Slots per historical root (preset-selected)."""

EPOCHS_PER_HISTORICAL_VECTOR = Uint64(64) if _PRESET == "minimal" else Uint64(65536)
"""Epochs per historical vector (preset-selected)."""

EPOCHS_PER_SLASHINGS_VECTOR = Uint64(64) if _PRESET == "minimal" else Uint64(8192)
"""Epochs per slashings vector (preset-selected)."""

HISTORICAL_ROOTS_LIMIT = Uint64(16777216)
"""Historical roots limit (preset constant)."""

VALIDATOR_REGISTRY_LIMIT = Uint64(1099511627776)
"""Validator registry limit (preset constant)."""

BASE_REWARD_FACTOR = Uint64(64)
"""Base reward factor (preset constant)."""

SYNC_COMMITTEE_SIZE = Uint64(32) if _PRESET == "minimal" else Uint64(512)
"""Sync committee size (preset-selected)."""

EPOCHS_PER_SYNC_COMMITTEE_PERIOD = Uint64(8) if _PRESET == "minimal" else Uint64(256)
"""Epochs per sync committee period (preset-selected)."""

INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = Uint64(16777216)
"""Inactivity penalty quotient bellatrix (preset constant)."""

PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = Uint64(3)
"""Proportional slashing multiplier bellatrix (preset constant)."""

MAX_WITHDRAWALS_PER_PAYLOAD = Uint64(4) if _PRESET == "minimal" else Uint64(16)
"""Max withdrawals per payload (preset-selected)."""

MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP = 16 if _PRESET == "minimal" else 16384
"""Max validators per withdrawals sweep (preset-selected)."""

MIN_ACTIVATION_BALANCE = Gwei(32000000000)
"""Min activation balance (preset constant)."""

MAX_EFFECTIVE_BALANCE_ELECTRA = Gwei(2048000000000)
"""Max effective balance electra (preset constant)."""

MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA = Uint64(4096)
"""Min slashing penalty quotient electra (preset constant)."""

WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA = Uint64(4096)
"""Whistleblower reward quotient electra (preset constant)."""

PENDING_PARTIAL_WITHDRAWALS_LIMIT = Uint64(64) if _PRESET == "minimal" else Uint64(134217728)
"""Pending partial withdrawals limit (preset-selected)."""

PENDING_CONSOLIDATIONS_LIMIT = Uint64(64) if _PRESET == "minimal" else Uint64(262144)
"""Pending consolidations limit (preset-selected)."""

MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = Uint64(2) if _PRESET == "minimal" else Uint64(8)
"""Max pending partials per withdrawals sweep (preset-selected)."""

MAX_PENDING_DEPOSITS_PER_EPOCH = Uint64(16)
"""Max pending deposits per epoch (preset constant)."""

PTC_SIZE = Uint64(16) if _PRESET == "minimal" else Uint64(512)
"""Ptc size (preset-selected)."""

PAYLOAD_TIMELY_THRESHOLD = PTC_SIZE // Uint64(2)
"""Payload timeliness committee votes needed to call a payload timely."""

DATA_AVAILABILITY_TIMELY_THRESHOLD = PTC_SIZE // Uint64(2)
"""Payload timeliness committee votes needed to call blob data available."""

MAX_BUILDERS_PER_WITHDRAWALS_SWEEP = 16 if _PRESET == "minimal" else 16384
"""Max builders per withdrawals sweep (preset-selected)."""
