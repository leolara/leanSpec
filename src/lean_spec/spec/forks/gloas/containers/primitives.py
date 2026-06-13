"""
Scalar SSZ newtypes for the mainnet Gloas reference port.

These wrap the shared SSZ scalar and byte-vector types with domain names so the
container declarations and the state transition read like the upstream spec.
Each newtype serializes and merkleizes identically to its base; the distinct
class only documents intent.
"""

from lean_spec.spec.ssz import (
    Bytes4,
    Bytes8,
    Bytes20,
    Bytes32,
    Bytes48,
    Bytes96,
    Uint8,
    Uint64,
)


class Slot(Uint64):
    """A slot, the smallest unit of time in the beacon chain."""


class Epoch(Uint64):
    """An epoch, a fixed run of consecutive slots."""


class CommitteeIndex(Uint64):
    """Index of a committee within a slot."""


class ValidatorIndex(Uint64):
    """Position of a validator in the registry."""


class BuilderIndex(Uint64):
    """Position of a builder in the builder registry."""


class WithdrawalIndex(Uint64):
    """Monotonic counter identifying a withdrawal."""


class Gwei(Uint64):
    """An amount of Ether denominated in gwei."""


class Ether(Uint64):
    """An amount denominated in whole Ether."""


class ParticipationFlags(Uint8):
    """Bit set of participation flags recorded for one validator in one epoch."""


class PayloadStatus(Uint8):
    """Status of the execution payload slot in the beacon state bookkeeping."""


class PayloadValidationStatus(Uint8):
    """Outcome of execution-payload validation as tracked by fork choice."""


class Root(Bytes32):
    """A 32-byte Merkle root or block/state root."""


class Hash32(Bytes32):
    """A 32-byte opaque hash, such as an execution block hash."""


class VersionedHash(Bytes32):
    """A 32-byte versioned hash committing to a blob KZG commitment."""


class Domain(Bytes32):
    """A 32-byte signature domain separator."""


class Version(Bytes4):
    """A 4-byte fork version."""


class DomainType(Bytes4):
    """A 4-byte domain tag selecting the purpose of a signature."""


class ForkDigest(Bytes4):
    """A 4-byte fork digest identifying the active fork on the wire."""


class ExecutionAddress(Bytes20):
    """A 20-byte execution-layer account address."""


class PayloadId(Bytes8):
    """An 8-byte identifier for an execution payload build job."""


class BLSPubkey(Bytes48):
    """A 48-byte compressed BLS12-381 public key in G1."""


class BLSSignature(Bytes96):
    """A 96-byte compressed BLS12-381 signature in G2."""


class KZGCommitment(Bytes48):
    """A 48-byte KZG commitment to a blob polynomial."""


class KZGProof(Bytes48):
    """A 48-byte KZG opening proof."""
