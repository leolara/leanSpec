"""
Fork protocol interface for the mainnet beacon-chain fork family.

This module is agnostic of any individual beacon fork. A concrete fork, Gloas and
its successors, supplies the identity, the container classes, and the spec method
implementations. It mirrors the lean fork protocol, adapted to the beacon-chain
container set.
"""

from abc import ABC
from typing import ClassVar

from lean_spec.spec.ssz.ssz_base import SSZType


class BeaconForkProtocol(ABC):
    """Identity and container facade shared by every beacon-chain fork."""

    NAME: ClassVar[str]
    """Fork name, unique across the beacon fork family."""

    PRESET: ClassVar[str]
    """Active consensus preset, mainnet or minimal."""

    state_class: type[SSZType]
    """Concrete beacon-state container class owned by this fork."""

    block_class: type[SSZType]
    """Concrete beacon-block container class owned by this fork."""

    block_body_class: type[SSZType]
    """Concrete beacon-block-body container class owned by this fork."""

    block_header_class: type[SSZType]
    """Concrete beacon-block-header container class owned by this fork."""

    signed_block_class: type[SSZType]
    """Concrete signed-beacon-block container class owned by this fork."""

    store_class: type
    """Concrete fork-choice store class owned by this fork."""
