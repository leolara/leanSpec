"""
Runtime configuration for the Gloas reference port.

Configuration values, unlike preset values, identify a specific network rather
than tuning the protocol's size parameters. The fork schedule below selects its
values by the same per-process preset environment variable, since the minimal
and mainnet test networks assign different fork versions and activation epochs.
"""

import os
from dataclasses import dataclass

from lean_spec.spec.forks.beacon.gloas.containers.primitives import Epoch, Gwei, Version
from lean_spec.spec.ssz import Uint64

_PRESET = os.environ.get("GLOAS_PRESET", "mainnet").lower()
"""Active preset, "mainnet" or "minimal", fixed for the whole process."""

if _PRESET not in ("mainnet", "minimal"):
    raise ValueError(f"Invalid GLOAS_PRESET: {_PRESET!r}; expected mainnet or minimal")

_MINIMAL = _PRESET == "minimal"

GENESIS_FORK_VERSION = Version("0x00000001") if _MINIMAL else Version("0x00000000")
"""Fork version in effect at genesis."""

CAPELLA_FORK_VERSION = Version("0x03000001") if _MINIMAL else Version("0x03000000")
"""Fork version introduced by the Capella upgrade."""

# A far-future activation epoch keeps an upgrade inactive on a network.
# The minimal preset leaves the post-genesis upgrades unscheduled this way.
_FAR_FUTURE = Epoch(18446744073709551615)

ELECTRA_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(364032)
"""Activation epoch of the Electra upgrade."""

MIN_VALIDATOR_WITHDRAWABILITY_DELAY = Epoch(256)
"""Epochs an exited validator waits before its balance becomes withdrawable."""

MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA = Gwei(64000000000) if _MINIMAL else Gwei(128000000000)
"""Floor on the per-epoch exit churn, denominated in gwei."""

CHURN_LIMIT_QUOTIENT_GLOAS = Uint64(16) if _MINIMAL else Uint64(32768)
"""Divisor of total active balance setting the per-epoch exit churn."""

SHARD_COMMITTEE_PERIOD = Uint64(64) if _MINIMAL else Uint64(256)
"""Epochs a validator must be active before it may request a voluntary exit."""

MIN_BUILDER_WITHDRAWABILITY_DELAY = Epoch(2) if _MINIMAL else Epoch(8192)
"""Epochs an exited builder waits before its balance becomes withdrawable."""

CONSOLIDATION_CHURN_LIMIT_QUOTIENT = Uint64(32) if _MINIMAL else Uint64(65536)
"""Divisor of total active balance setting the per-epoch consolidation churn."""

EJECTION_BALANCE = Gwei(16000000000)
"""Effective-balance floor below which an active validator is force-exited."""

MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS = Gwei(128000000000) if _MINIMAL else Gwei(256000000000)
"""Ceiling on the per-epoch activation churn, in gwei."""

INACTIVITY_SCORE_BIAS = Uint64(4)
"""Per-epoch inactivity-score increase for a validator that misses the target."""

INACTIVITY_SCORE_RECOVERY_RATE = Uint64(16)
"""Per-epoch inactivity-score decrease once the chain is no longer leaking."""

SLOT_DURATION_MS = Uint64(6000) if _MINIMAL else Uint64(12000)
"""Wall-clock duration of a slot in milliseconds."""

PROPOSER_SCORE_BOOST = Uint64(40)
"""Percent of one slot's committee weight a timely block's proposer is boosted by."""

REORG_HEAD_WEIGHT_THRESHOLD = Uint64(20)
"""Percent of committee weight below which a head is weak enough to re-org."""

ATTESTATION_DUE_BPS_GLOAS = Uint64(2500)
"""Basis points into a slot by which an attestation is due to be timely."""

PAYLOAD_ATTESTATION_DUE_BPS = Uint64(7500)
"""Basis points into a slot by which a payload timeliness attestation is due."""


@dataclass(frozen=True)
class BlobParameters:
    """Per-epoch ceiling on how many blobs one block may carry."""

    epoch: Epoch
    """First epoch the ceiling applies from."""

    max_blobs_per_block: Uint64
    """Maximum number of blob commitments permitted in a block."""


MAX_BLOBS_PER_BLOCK_ELECTRA = Uint64(9)
"""Blob ceiling in force from the Electra upgrade until the first scheduled bump."""

BLOB_SCHEDULE: tuple[BlobParameters, ...] = (
    ()
    if _MINIMAL
    else (
        BlobParameters(epoch=Epoch(412672), max_blobs_per_block=Uint64(15)),
        BlobParameters(epoch=Epoch(419072), max_blobs_per_block=Uint64(21)),
    )
)
"""Scheduled blob-ceiling increases, each taking effect at its activation epoch."""
