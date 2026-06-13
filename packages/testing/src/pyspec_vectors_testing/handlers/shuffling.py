"""
Runner for the shuffling format.

A shuffling case pins a seed and an index count, and lists the position every
index shuffles to. The runner reproduces the full permutation and compares it to
that mapping.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from lean_spec.spec.forks.gloas.helpers.shuffle import compute_shuffled_permutation
from lean_spec.spec.ssz import Bytes32, Uint64


def run_shuffling_case(case_dir: Path) -> None:
    """
    Run one shuffling case, raising on any divergence from the expected mapping.

    Raises:
        AssertionError: If the computed permutation differs from the expected one.
    """
    mapping = yaml.safe_load((case_dir / "mapping.yaml").read_text())
    seed = Bytes32(mapping["seed"])
    index_count = Uint64(mapping["count"])
    expected_permutation = mapping["mapping"]
    actual_permutation = [int(index) for index in compute_shuffled_permutation(index_count, seed)]
    assert actual_permutation == expected_permutation, (
        f"shuffled permutation mismatch for count {int(index_count)}:\n"
        f"  expected: {expected_permutation}\n"
        f"  actual:   {actual_permutation}"
    )
