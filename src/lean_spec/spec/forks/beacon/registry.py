"""Registry of registered beacon-chain forks, ordered oldest to newest."""

from itertools import pairwise

from lean_spec.spec.forks.beacon.protocol import BeaconForkProtocol


class BeaconForkRegistry:
    """Registry of registered beacon-chain forks, ordered by version."""

    def __init__(self, forks: list[BeaconForkProtocol]) -> None:
        """
        Initialize with an ordered list of beacon forks.

        Forks must be:

        - Strictly monotonic in VERSION (ascending).
        - Unique by NAME.

        Args:
            forks: Ordered list of beacon fork implementations.

        Raises:
            ValueError: If the fork list is empty, versions are not strictly
                monotonic, or names collide.
        """
        if not forks:
            raise ValueError("BeaconForkRegistry requires at least one fork")

        versions = [fork.VERSION for fork in forks]
        if any(earlier >= later for earlier, later in pairwise(versions)):
            raise ValueError(f"Forks must be ordered by strictly increasing VERSION: {versions}")

        names = [fork.NAME for fork in forks]
        if len(set(names)) != len(names):
            raise ValueError(f"Fork names must be unique: {names}")

        self._forks = forks

    @property
    def current(self) -> BeaconForkProtocol:
        """Return the latest, highest-version fork."""
        return self._forks[-1]
