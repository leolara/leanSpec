"""
Decode vector case inputs into Gloas containers.

Vector objects are SSZ values compressed with the snappy block format (a varint
length prefix, not the streaming frame format). Each case also carries a small
metadata file that may pin the BLS verification setting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import cramjam
import yaml

from lean_spec.spec.ssz.ssz_base import SSZType

# The compiled cramjam binding ships no type information, so its call surface is
# bound through a dynamically typed alias for the type checker.
_cramjam: Any = cramjam


def decompress_ssz(path: Path) -> bytes:
    """Decompress a snappy-block-framed SSZ file to its raw bytes."""
    return bytes(_cramjam.snappy.decompress_raw(path.read_bytes()))


def load_object(path: Path, container: type[SSZType]) -> Any:
    """Deserialize one compressed SSZ object into the given container type."""
    return container.decode_bytes(decompress_ssz(path))


def load_meta(case_dir: Path) -> dict[str, Any]:
    """Read a case's metadata, or an empty mapping when it has none."""
    meta_path = case_dir / "meta.yaml"
    if not meta_path.exists():
        return {}
    return yaml.safe_load(meta_path.read_text()) or {}


def bls_is_active(meta: dict[str, Any]) -> bool:
    """
    Decide whether to verify signatures for a case from its metadata.

    A setting of zero disables verification; anything else keeps it on, which is
    what the signature-rejection cases need to actually fail.
    """
    return meta.get("bls_setting", 1) != 0
