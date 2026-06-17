"""
Signature domains and signing roots for the Gloas reference port.

A BLS signature in the consensus protocol never signs a message root directly.
It signs a domain-separated root: the message root mixed with a domain tag and a
fork-and-chain identifier. This separation stops a signature valid on one fork,
network, or message purpose from being replayed on another.
"""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.beacon.gloas import config
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import (
    BeaconState,
    ForkData,
    SigningData,
)
from lean_spec.spec.forks.beacon.gloas.containers.primitives import (
    Domain,
    DomainType,
    Epoch,
    Root,
    Version,
)
from lean_spec.spec.forks.beacon.gloas.preset import SLOTS_PER_EPOCH
from lean_spec.spec.forks.beacon.gloas.spec_base import GloasSpecBase
from lean_spec.spec.ssz.ssz_base import SSZType

_FORK_DATA_ROOT_DOMAIN_BYTES = 28


class SignatureMixin(GloasSpecBase):
    """Signature behavior for the Gloas spec."""

    def compute_fork_data_root(
        self, current_version: Version, genesis_validators_root: Root
    ) -> Root:
        """
        Combine a fork version and the genesis validators root into one root.

        Mixing the genesis validators root in makes the result unique per network, so
        a signature domain cannot collide across chains that share a fork version.
        """
        return Root(
            hash_tree_root(
                ForkData(
                    current_version=current_version,
                    genesis_validators_root=genesis_validators_root,
                )
            )
        )

    def compute_domain(
        self,
        domain_type: DomainType,
        fork_version: Version | None = None,
        genesis_validators_root: Root | None = None,
    ) -> Domain:
        """
        Build the 32-byte signature domain for a purpose, fork, and network.

        The domain is the four-byte domain type followed by the leading bytes of the
        fork-data root. An absent fork version defaults to the genesis version, and an
        absent genesis validators root defaults to all zeros.
        """
        if fork_version is None:
            fork_version = config.GENESIS_FORK_VERSION
        if genesis_validators_root is None:
            genesis_validators_root = Root.zero()
        fork_data_root = self.compute_fork_data_root(fork_version, genesis_validators_root)
        return Domain(bytes(domain_type) + bytes(fork_data_root)[:_FORK_DATA_ROOT_DOMAIN_BYTES])

    def compute_signing_root(self, ssz_object: SSZType, domain: Domain) -> Root:
        """Return the domain-separated root a validator actually signs."""
        object_root = Root(hash_tree_root(ssz_object))
        return Root(hash_tree_root(SigningData(object_root=object_root, domain=domain)))

    def get_domain(
        self, state: BeaconState, domain_type: DomainType, epoch: Epoch | None = None
    ) -> Domain:
        """
        Return the signature domain for a message anchored to the state's fork.

        A message from before the fork transition epoch uses the previous fork
        version, so signatures created across a fork boundary still verify.
        """
        # The current epoch is the state slot divided by the slots-per-epoch span.
        # This inlines the epoch accessor that the state-transition phase introduces.
        current_epoch = Epoch(int(state.slot) // int(SLOTS_PER_EPOCH)) if epoch is None else epoch
        fork_version = (
            state.fork.previous_version
            if current_epoch < state.fork.epoch
            else state.fork.current_version
        )
        return self.compute_domain(domain_type, fork_version, state.genesis_validators_root)
