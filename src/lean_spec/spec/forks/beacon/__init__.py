"""The mainnet beacon-chain fork family (Gloas and its successors)."""

from lean_spec.spec.forks.beacon.gloas.spec import GloasSpec
from lean_spec.spec.forks.beacon.protocol import BeaconForkProtocol
from lean_spec.spec.forks.beacon.registry import BeaconForkRegistry

BEACON_FORK_SEQUENCE: list[BeaconForkProtocol] = [GloasSpec()]
"""Ordered oldest to newest. BeaconForkRegistry enforces strictly increasing VERSION."""

BEACON_REGISTRY: BeaconForkRegistry = BeaconForkRegistry(BEACON_FORK_SEQUENCE)
"""Shared registry over the registered beacon forks."""

__all__ = [
    "BEACON_FORK_SEQUENCE",
    "BEACON_REGISTRY",
    "BeaconForkProtocol",
    "BeaconForkRegistry",
    "GloasSpec",
]
