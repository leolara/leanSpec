"""
Consumer of upstream consensus spec-test vectors for the Gloas port.

This package is the inverse of consensus_testing: where that one generates lean
test vectors, this one downloads a pinned consensus-spec-tests release and runs
its Gloas vectors against the standalone gloas reference under spec/forks/gloas.
"""
