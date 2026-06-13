"""
Runtime configuration for the Gloas reference port.

Configuration values, unlike preset values, identify a specific network rather
than tuning the protocol's size parameters. The fork schedule below selects its
values by the same per-process preset environment variable, since the minimal
and mainnet test networks assign different fork versions and activation epochs.
"""

import os

from lean_spec.spec.forks.gloas.containers.primitives import Epoch, Version

_PRESET = os.environ.get("GLOAS_PRESET", "mainnet").lower()
"""Active preset, "mainnet" or "minimal", fixed for the whole process."""

if _PRESET not in ("mainnet", "minimal"):
    raise ValueError(f"Invalid GLOAS_PRESET: {_PRESET!r}; expected mainnet or minimal")

_MINIMAL = _PRESET == "minimal"

GENESIS_FORK_VERSION = Version("0x00000001") if _MINIMAL else Version("0x00000000")
"""Fork version in effect at genesis."""

ALTAIR_FORK_VERSION = Version("0x01000001") if _MINIMAL else Version("0x01000000")
"""Fork version introduced by the Altair upgrade."""

BELLATRIX_FORK_VERSION = Version("0x02000001") if _MINIMAL else Version("0x02000000")
"""Fork version introduced by the Bellatrix upgrade."""

CAPELLA_FORK_VERSION = Version("0x03000001") if _MINIMAL else Version("0x03000000")
"""Fork version introduced by the Capella upgrade."""

DENEB_FORK_VERSION = Version("0x04000001") if _MINIMAL else Version("0x04000000")
"""Fork version introduced by the Deneb upgrade."""

ELECTRA_FORK_VERSION = Version("0x05000001") if _MINIMAL else Version("0x05000000")
"""Fork version introduced by the Electra upgrade."""

FULU_FORK_VERSION = Version("0x06000001") if _MINIMAL else Version("0x06000000")
"""Fork version introduced by the Fulu upgrade."""

GLOAS_FORK_VERSION = Version("0x07000001") if _MINIMAL else Version("0x07000000")
"""Fork version introduced by the Gloas upgrade."""

# A far-future activation epoch keeps an upgrade inactive on a network.
# The minimal preset leaves the post-genesis upgrades unscheduled this way.
_FAR_FUTURE = Epoch(18446744073709551615)

ALTAIR_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(74240)
"""Activation epoch of the Altair upgrade."""

BELLATRIX_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(144896)
"""Activation epoch of the Bellatrix upgrade."""

CAPELLA_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(194048)
"""Activation epoch of the Capella upgrade."""

DENEB_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(269568)
"""Activation epoch of the Deneb upgrade."""

ELECTRA_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(364032)
"""Activation epoch of the Electra upgrade."""

FULU_FORK_EPOCH = _FAR_FUTURE if _MINIMAL else Epoch(411392)
"""Activation epoch of the Fulu upgrade."""

GLOAS_FORK_EPOCH = _FAR_FUTURE
"""Activation epoch of the Gloas upgrade, unscheduled on both test networks."""
