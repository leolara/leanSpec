"""Tests for the BLS12-381 signature wrapper used by the Gloas port."""

import pytest

from lean_spec.spec.crypto import bls
from lean_spec.spec.ssz import Bytes48, Bytes96

# Two distinct, fixed secret-key scalars in the valid range for the curve order.
# Fixed values keep the round-trip assertions deterministic across runs.
SECRET_KEY_A = 0x2CD4BA406B522BB0E4CB6C5D2F3F3F2E0DB3A3B3C3D3E3F4051525354555657
SECRET_KEY_B = 0x1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F809

MESSAGE = b"\x12" * 32
"""A 32-byte signing root, the shape Gloas signs over."""

OTHER_MESSAGE = b"\x34" * 32
"""A different 32-byte signing root, used to force a verification failure."""


class TestSignVerify:
    """Single-signature signing and verification."""

    def test_sign_verify_round_trip(self) -> None:
        """A freshly signed message verifies against its public key."""
        public_key = bls.SkToPk(SECRET_KEY_A)
        signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        assert bls.Verify(public_key, MESSAGE, signature) is True

    def test_sign_returns_typed_signature(self) -> None:
        """Signing returns a 96-byte compressed signature."""
        signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        assert isinstance(signature, Bytes96)

    def test_public_key_is_typed(self) -> None:
        """Public-key derivation returns a 48-byte compressed key."""
        public_key = bls.SkToPk(SECRET_KEY_A)
        assert isinstance(public_key, Bytes48)

    def test_verify_rejects_wrong_message(self) -> None:
        """A signature over one message does not verify against another."""
        public_key = bls.SkToPk(SECRET_KEY_A)
        signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        assert bls.Verify(public_key, OTHER_MESSAGE, signature) is False

    def test_verify_rejects_wrong_public_key(self) -> None:
        """A signature does not verify against an unrelated public key."""
        signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        other_public_key = bls.SkToPk(SECRET_KEY_B)
        assert bls.Verify(other_public_key, MESSAGE, signature) is False

    def test_verify_returns_false_for_malformed_signature(self) -> None:
        """A signature that decodes to no valid point verifies as false, not an error."""
        public_key = bls.SkToPk(SECRET_KEY_A)
        malformed_signature = Bytes96(b"\x00" * 96)
        assert bls.Verify(public_key, MESSAGE, malformed_signature) is False

    def test_verify_returns_false_for_malformed_public_key(self) -> None:
        """A public key that decodes to no valid point verifies as false, not an error."""
        signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        malformed_public_key = Bytes48(b"\x00" * 48)
        assert bls.Verify(malformed_public_key, MESSAGE, signature) is False


class TestAggregate:
    """Aggregate signing and the two aggregate-verification predicates."""

    def test_fast_aggregate_verify_common_message(self) -> None:
        """An aggregate of two signatures over one message verifies under both keys."""
        public_key_a = bls.SkToPk(SECRET_KEY_A)
        public_key_b = bls.SkToPk(SECRET_KEY_B)
        aggregate_signature = bls.Aggregate(
            [bls.Sign(SECRET_KEY_A, MESSAGE), bls.Sign(SECRET_KEY_B, MESSAGE)]
        )
        assert isinstance(aggregate_signature, Bytes96)
        assert (
            bls.FastAggregateVerify([public_key_a, public_key_b], MESSAGE, aggregate_signature)
            is True
        )

    def test_fast_aggregate_verify_rejects_missing_signer(self) -> None:
        """Dropping one signer's key from the set fails the aggregate check."""
        public_key_a = bls.SkToPk(SECRET_KEY_A)
        aggregate_signature = bls.Aggregate(
            [bls.Sign(SECRET_KEY_A, MESSAGE), bls.Sign(SECRET_KEY_B, MESSAGE)]
        )
        assert bls.FastAggregateVerify([public_key_a], MESSAGE, aggregate_signature) is False

    def test_aggregate_verify_distinct_messages(self) -> None:
        """An aggregate over two distinct messages verifies pairwise with its keys."""
        public_key_a = bls.SkToPk(SECRET_KEY_A)
        public_key_b = bls.SkToPk(SECRET_KEY_B)
        aggregate_signature = bls.Aggregate(
            [bls.Sign(SECRET_KEY_A, MESSAGE), bls.Sign(SECRET_KEY_B, OTHER_MESSAGE)]
        )
        assert (
            bls.AggregateVerify(
                [public_key_a, public_key_b], [MESSAGE, OTHER_MESSAGE], aggregate_signature
            )
            is True
        )

    def test_aggregate_verify_rejects_swapped_messages(self) -> None:
        """Pairing the keys with each other's messages fails the aggregate check."""
        public_key_a = bls.SkToPk(SECRET_KEY_A)
        public_key_b = bls.SkToPk(SECRET_KEY_B)
        aggregate_signature = bls.Aggregate(
            [bls.Sign(SECRET_KEY_A, MESSAGE), bls.Sign(SECRET_KEY_B, OTHER_MESSAGE)]
        )
        assert (
            bls.AggregateVerify(
                [public_key_a, public_key_b], [OTHER_MESSAGE, MESSAGE], aggregate_signature
            )
            is False
        )

    def test_eth_fast_aggregate_verify_empty_accepts_infinity(self) -> None:
        """An empty key set verifies only against the infinity signature."""
        assert bls.eth_fast_aggregate_verify([], MESSAGE, bls.G2_POINT_AT_INFINITY) is True

    def test_eth_fast_aggregate_verify_empty_rejects_non_infinity(self) -> None:
        """An empty key set rejects any signature that is not the infinity signature."""
        non_infinity_signature = bls.Sign(SECRET_KEY_A, MESSAGE)
        assert bls.eth_fast_aggregate_verify([], MESSAGE, non_infinity_signature) is False

    def test_eth_fast_aggregate_verify_non_empty_verifies_aggregate(self) -> None:
        """A non-empty key set delegates to the aggregate signature check."""
        public_key_a = bls.SkToPk(SECRET_KEY_A)
        public_key_b = bls.SkToPk(SECRET_KEY_B)
        aggregate_signature = bls.Aggregate(
            [bls.Sign(SECRET_KEY_A, MESSAGE), bls.Sign(SECRET_KEY_B, MESSAGE)]
        )
        assert (
            bls.eth_fast_aggregate_verify(
                [public_key_a, public_key_b], MESSAGE, aggregate_signature
            )
            is True
        )


class TestKeyValidate:
    """Public-key validation against the prime-order subgroup."""

    def test_accepts_valid_public_key(self) -> None:
        """A key derived from a secret key passes validation."""
        assert bls.KeyValidate(bls.SkToPk(SECRET_KEY_A)) is True

    def test_rejects_point_at_infinity(self) -> None:
        """The compressed point at infinity is the identity, so it is rejected."""
        point_at_infinity = Bytes48(b"\xc0" + b"\x00" * 47)
        assert bls.KeyValidate(point_at_infinity) is False

    def test_rejects_undecodable_key(self) -> None:
        """An all-zero key decodes to no valid point and is rejected."""
        assert bls.KeyValidate(Bytes48(b"\x00" * 48)) is False


class TestInactiveBackend:
    """Behavior when the cryptographic backend is switched off."""

    def test_verify_passes_when_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verification predicates return true so a signature-stripped vector still runs."""
        monkeypatch.setattr(bls, "bls_active", False)
        public_key = Bytes48(b"\x00" * 48)
        signature = Bytes96(b"\x00" * 96)
        assert bls.Verify(public_key, MESSAGE, signature) is True
        assert bls.FastAggregateVerify([public_key], MESSAGE, signature) is True
        assert bls.AggregateVerify([public_key], [MESSAGE], signature) is True
        assert bls.KeyValidate(public_key) is True

    def test_sign_returns_stub_when_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Signing and aggregation return the fixed stub signature."""
        monkeypatch.setattr(bls, "bls_active", False)
        assert bls.Sign(SECRET_KEY_A, MESSAGE) == bls.STUB_SIGNATURE
        assert bls.Aggregate([bls.STUB_SIGNATURE]) == bls.STUB_SIGNATURE

    def test_public_key_returns_stub_when_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Public-key derivation returns the fixed stub public key."""
        monkeypatch.setattr(bls, "bls_active", False)
        assert bls.SkToPk(SECRET_KEY_A) == bls.STUB_PUBKEY


def test_module_constants_are_typed() -> None:
    """The aliases and stubs carry the SSZ byte-vector types Gloas containers expect."""
    assert bls.BLSPubkey is Bytes48
    assert bls.BLSSignature is Bytes96
    assert isinstance(bls.STUB_SIGNATURE, Bytes96)
    assert isinstance(bls.STUB_PUBKEY, Bytes48)
    assert bls.G2_POINT_AT_INFINITY == Bytes96(b"\xc0" + b"\x00" * 95)
