"""
The Gloas fork spec, composed from behavior mixins.

Like the lean fork, the spec is a single class assembled from per-concern mixins
over a shared typed base. It is standalone: it does not join the lean fork
registry and is driven only by the consensus spec-test vector harness.
"""

import os
from typing import ClassVar

from lean_spec.spec.forks.gloas.accessors import AccessorMixin
from lean_spec.spec.forks.gloas.predicates import PredicatesMixin
from lean_spec.spec.forks.gloas.signing import SignatureMixin
from lean_spec.spec.forks.gloas.spec_base import GloasSpecBase
from lean_spec.spec.forks.gloas.state_transition.mutators import MutatorMixin
from lean_spec.spec.forks.gloas.state_transition.operations import OperationMixin

__all__ = ["GloasSpec"]


class GloasSpec(
    SignatureMixin,
    PredicatesMixin,
    AccessorMixin,
    MutatorMixin,
    OperationMixin,
    GloasSpecBase,
):
    """The standalone mainnet Gloas reference spec."""

    NAME: ClassVar[str] = "gloas"
    PRESET: ClassVar[str] = os.environ.get("GLOAS_PRESET", "mainnet").lower()
