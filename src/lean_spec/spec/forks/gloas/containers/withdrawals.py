"""
Aggregate result of computing a block's expected withdrawals.

The withdrawal sweep is built in stages: queued builder withdrawals, pending
partial withdrawals, the builder balance sweep, and the validator balance sweep.
Each stage reports how many entries it processed so the state can advance its
per-stage cursors after the withdrawals are applied.

This is a transient computation result, not an SSZ type: it is returned by the
withdrawal sweep and consumed at once when the withdrawals are applied, never
serialized or stored in the state.
"""

from dataclasses import dataclass

from lean_spec.spec.forks.gloas.containers.beacon_chain import Withdrawal
from lean_spec.spec.ssz import Uint64


@dataclass(frozen=True)
class ExpectedWithdrawals:
    """The withdrawals a block must honor, with each stage's processed count."""

    withdrawals: list[Withdrawal]
    """The ordered withdrawals across all sweep stages."""

    processed_builder_withdrawals_count: Uint64
    """Number of queued builder withdrawals drained from the front of the queue."""

    processed_partial_withdrawals_count: Uint64
    """Number of pending partial withdrawals drained from the front of the queue."""

    processed_builders_sweep_count: Uint64
    """Number of builder registry entries advanced past in the builder sweep."""

    processed_sweep_withdrawals_count: Uint64
    """Number of validator registry entries advanced past in the validator sweep."""
