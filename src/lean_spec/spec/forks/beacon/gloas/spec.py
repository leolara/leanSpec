"""
The Gloas fork spec, composed from behavior mixins.

Like the lean fork, the spec is a single class assembled from per-concern mixins
over a shared typed base. It is standalone: it does not join the lean fork
registry and is driven only by the consensus spec-test vector harness.
"""

from typing import ClassVar

from lean_spec.spec.forks.beacon.gloas.accessors import AccessorMixin
from lean_spec.spec.forks.beacon.gloas.containers.beacon_chain import (
    BeaconBlock,
    BeaconBlockBody,
    BeaconBlockHeader,
    BeaconState,
)
from lean_spec.spec.forks.beacon.gloas.containers.fork_choice import Store
from lean_spec.spec.forks.beacon.gloas.fork_choice import ForkChoiceMixin
from lean_spec.spec.forks.beacon.gloas.predicates import PredicatesMixin
from lean_spec.spec.forks.beacon.gloas.signing import SignatureMixin
from lean_spec.spec.forks.beacon.gloas.spec_base import GloasSpecBase
from lean_spec.spec.forks.beacon.gloas.state_transition.driver import StateTransitionMixin
from lean_spec.spec.forks.beacon.gloas.state_transition.epoch import EpochMixin
from lean_spec.spec.forks.beacon.gloas.state_transition.mutators import MutatorMixin
from lean_spec.spec.forks.beacon.gloas.state_transition.operations import OperationMixin

__all__ = ["GloasSpec"]


class GloasSpec(
    SignatureMixin,
    PredicatesMixin,
    AccessorMixin,
    MutatorMixin,
    OperationMixin,
    EpochMixin,
    StateTransitionMixin,
    ForkChoiceMixin,
    GloasSpecBase,
):
    """The standalone mainnet Gloas reference spec."""

    NAME: ClassVar[str] = "gloas"
    VERSION: ClassVar[int] = 0

    state_class: type[BeaconState] = BeaconState
    block_class: type[BeaconBlock] = BeaconBlock
    block_body_class: type[BeaconBlockBody] = BeaconBlockBody
    block_header_class: type[BeaconBlockHeader] = BeaconBlockHeader
    store_class: type[Store] = Store
