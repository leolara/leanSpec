"""
Preset-selected constants for the Gloas reference port.

The mainnet and minimal presets differ in committee sizes, history lengths,
and collection limits. One preset is fixed per process by an environment
variable read at import, so the spec stays module-constant style and every
worker in a parallel run shares one consistent preset.
"""

import os

from lean_spec.spec.forks.gloas.containers.primitives import Gwei
from lean_spec.spec.ssz import Uint64

_PRESET = os.environ.get("GLOAS_PRESET", "mainnet").lower()
"""Active preset, "mainnet" or "minimal", fixed for the whole process."""

if _PRESET not in ("mainnet", "minimal"):
    raise ValueError(f"Invalid GLOAS_PRESET: {_PRESET!r}; expected mainnet or minimal")

MAX_COMMITTEES_PER_SLOT = Uint64(4) if _PRESET == "minimal" else Uint64(64)
"""Max committees per slot (preset-selected)."""

TARGET_COMMITTEE_SIZE = Uint64(4) if _PRESET == "minimal" else Uint64(128)
"""Target committee size (preset-selected)."""

MAX_VALIDATORS_PER_COMMITTEE = Uint64(2048)
"""Max validators per committee (preset constant)."""

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

MAX_EFFECTIVE_BALANCE = Gwei(32000000000)
"""Max effective balance (preset constant)."""

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

WHISTLEBLOWER_REWARD_QUOTIENT = Uint64(512)
"""Whistleblower reward quotient (preset constant)."""

PROPOSER_REWARD_QUOTIENT = Uint64(8)
"""Proposer reward quotient (preset constant)."""

INACTIVITY_PENALTY_QUOTIENT = Uint64(33554432) if _PRESET == "minimal" else Uint64(67108864)
"""Inactivity penalty quotient (preset-selected)."""

MIN_SLASHING_PENALTY_QUOTIENT = Uint64(64) if _PRESET == "minimal" else Uint64(128)
"""Min slashing penalty quotient (preset-selected)."""

PROPORTIONAL_SLASHING_MULTIPLIER = Uint64(2) if _PRESET == "minimal" else Uint64(1)
"""Proportional slashing multiplier (preset-selected)."""

MAX_PROPOSER_SLASHINGS = 16
"""Max proposer slashings (preset constant)."""

MAX_ATTESTER_SLASHINGS = 2
"""Max attester slashings (preset constant)."""

MAX_ATTESTATIONS = 128
"""Max attestations (preset constant)."""

MAX_DEPOSITS = 16
"""Max deposits (preset constant)."""

MAX_VOLUNTARY_EXITS = 16
"""Max voluntary exits (preset constant)."""

INACTIVITY_PENALTY_QUOTIENT_ALTAIR = Uint64(50331648)
"""Inactivity penalty quotient altair (preset constant)."""

MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR = Uint64(64)
"""Min slashing penalty quotient altair (preset constant)."""

PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR = Uint64(2)
"""Proportional slashing multiplier altair (preset constant)."""

SYNC_COMMITTEE_SIZE = Uint64(32) if _PRESET == "minimal" else Uint64(512)
"""Sync committee size (preset-selected)."""

EPOCHS_PER_SYNC_COMMITTEE_PERIOD = Uint64(8) if _PRESET == "minimal" else Uint64(256)
"""Epochs per sync committee period (preset-selected)."""

MIN_SYNC_COMMITTEE_PARTICIPANTS = 1
"""Min sync committee participants (preset constant)."""

UPDATE_TIMEOUT = 64 if _PRESET == "minimal" else 8192
"""Update timeout (preset-selected)."""

INACTIVITY_PENALTY_QUOTIENT_BELLATRIX = Uint64(16777216)
"""Inactivity penalty quotient bellatrix (preset constant)."""

MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX = Uint64(32)
"""Min slashing penalty quotient bellatrix (preset constant)."""

PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX = Uint64(3)
"""Proportional slashing multiplier bellatrix (preset constant)."""

MAX_BYTES_PER_TRANSACTION = Uint64(1073741824)
"""Max bytes per transaction (preset constant)."""

MAX_TRANSACTIONS_PER_PAYLOAD = Uint64(1048576)
"""Max transactions per payload (preset constant)."""

BYTES_PER_LOGS_BLOOM = Uint64(256)
"""Bytes per logs bloom (preset constant)."""

MAX_EXTRA_DATA_BYTES = 32
"""Max extra data bytes (preset constant)."""

MAX_BLS_TO_EXECUTION_CHANGES = 16
"""Max bls to execution changes (preset constant)."""

MAX_WITHDRAWALS_PER_PAYLOAD = Uint64(4) if _PRESET == "minimal" else Uint64(16)
"""Max withdrawals per payload (preset-selected)."""

MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP = 16 if _PRESET == "minimal" else 16384
"""Max validators per withdrawals sweep (preset-selected)."""

MAX_BLOB_COMMITMENTS_PER_BLOCK = Uint64(4096)
"""Max blob commitments per block (preset constant)."""

FIELD_ELEMENTS_PER_BLOB = Uint64(4096)
"""Field elements per blob (preset constant)."""

KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = Uint64(17)
"""Kzg commitment inclusion proof depth (preset constant)."""

MIN_ACTIVATION_BALANCE = Gwei(32000000000)
"""Min activation balance (preset constant)."""

MAX_EFFECTIVE_BALANCE_ELECTRA = Gwei(2048000000000)
"""Max effective balance electra (preset constant)."""

MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA = Uint64(4096)
"""Min slashing penalty quotient electra (preset constant)."""

WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA = Uint64(4096)
"""Whistleblower reward quotient electra (preset constant)."""

PENDING_DEPOSITS_LIMIT = Uint64(134217728)
"""Pending deposits limit (preset constant)."""

PENDING_PARTIAL_WITHDRAWALS_LIMIT = Uint64(64) if _PRESET == "minimal" else Uint64(134217728)
"""Pending partial withdrawals limit (preset-selected)."""

PENDING_CONSOLIDATIONS_LIMIT = Uint64(64) if _PRESET == "minimal" else Uint64(262144)
"""Pending consolidations limit (preset-selected)."""

MAX_ATTESTER_SLASHINGS_ELECTRA = 1
"""Max attester slashings electra (preset constant)."""

MAX_ATTESTATIONS_ELECTRA = 8
"""Max attestations electra (preset constant)."""

MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = Uint64(8192)
"""Max deposit requests per payload (preset constant)."""

MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = Uint64(16)
"""Max withdrawal requests per payload (preset constant)."""

MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = Uint64(2)
"""Max consolidation requests per payload (preset constant)."""

MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = Uint64(2) if _PRESET == "minimal" else Uint64(8)
"""Max pending partials per withdrawals sweep (preset-selected)."""

MAX_PENDING_DEPOSITS_PER_EPOCH = Uint64(16)
"""Max pending deposits per epoch (preset constant)."""

FIELD_ELEMENTS_PER_EXT_BLOB = 8192
"""Field elements per ext blob (preset constant)."""

FIELD_ELEMENTS_PER_CELL = Uint64(64)
"""Field elements per cell (preset constant)."""

CELLS_PER_EXT_BLOB = 128
"""Cells per ext blob (preset constant)."""

NUMBER_OF_COLUMNS = Uint64(128)
"""Number of columns (preset constant)."""

KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = Uint64(4)
"""Kzg commitments inclusion proof depth (preset constant)."""

PTC_SIZE = Uint64(16) if _PRESET == "minimal" else Uint64(512)
"""Ptc size (preset-selected)."""

MAX_PAYLOAD_ATTESTATIONS = 4
"""Max payload attestations (preset constant)."""

BUILDER_REGISTRY_LIMIT = Uint64(1099511627776)
"""Builder registry limit (preset constant)."""

BUILDER_PENDING_WITHDRAWALS_LIMIT = Uint64(1048576)
"""Builder pending withdrawals limit (preset constant)."""

MAX_BUILDERS_PER_WITHDRAWALS_SWEEP = 16 if _PRESET == "minimal" else 16384
"""Max builders per withdrawals sweep (preset-selected)."""
