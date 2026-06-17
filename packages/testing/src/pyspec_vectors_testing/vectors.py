"""
Locate (and if needed download) the pinned consensus-spec-tests vectors.

The vectors are a large pinned release downloaded once to a local cache, outside
the repository, so the default unit-test run never collects them. The pin ties
the vectors to the exact upstream commit the gloas reference was translated from.
"""

from __future__ import annotations

import os
import tarfile
import urllib.request
from pathlib import Path

PINNED_RELEASE = "v1.7.0-alpha.10"
"""Consensus-spec-tests release the gloas reference is pinned to.

The flattened pyspec module and the vectors must come from one commit, so the
release tag is recorded alongside the spec it was translated from.
"""

_DOWNLOAD_URL = (
    "https://github.com/ethereum/consensus-specs/releases/download/"
    f"{PINNED_RELEASE}/{{preset}}.tar.gz"
)

PRESETS = ("minimal", "mainnet")
"""Test presets, run one at a time per invocation."""


def cache_root() -> Path:
    """
    Directory holding the downloaded, extracted vectors.

    An explicit override points at an existing extraction; otherwise a per-user
    cache keyed by the pinned release is used.
    """
    override = os.environ.get("PYSPEC_VECTORS_DIR")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "lean-pyspec-vectors" / PINNED_RELEASE


def preset_root(preset: str) -> Path:
    """Path to one preset's vector tree, for example <cache>/tests/minimal."""
    return cache_root() / "tests" / preset


def ensure_preset(preset: str) -> Path:
    """
    Return the preset's vector tree, downloading and extracting it if absent.

    Raises:
        ValueError: If the preset name is not recognized.
    """
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset {preset!r}; expected one of {PRESETS}")
    root = preset_root(preset)
    if root.is_dir():
        return root
    cache_root().mkdir(parents=True, exist_ok=True)
    archive = cache_root() / f"{preset}.tar.gz"
    if not archive.exists():
        url = _DOWNLOAD_URL.format(preset=preset)
        urllib.request.urlretrieve(url, archive)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(cache_root(), filter="data")
    return root
