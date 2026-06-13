"""
Standalone literal port of the mainnet Gloas fork (ePBS / EIP-7732).

This package reproduces the flattened upstream consensus specification for the
Gloas fork as a self-contained reference. It reuses the shared SSZ and
merkleization machinery and a BLS wrapper, but does not implement the lean fork
protocol and is not part of the lean fork registry or node. Its only driver is
the upstream consensus-spec-test vector harness.
"""
