"""
Command-line wrapper that runs the pinned Gloas vectors through pytest.

It fixes the preset for the whole run by exporting an environment variable
before launching pytest in a subprocess, so the freshly started interpreter
imports the spec under that preset. Vectors are downloaded to a local cache on
first use. Extra arguments pass straight through to pytest.

Examples:
    uv run pyspec-vectors --preset minimal -k shuffling -n auto
    uv run pyspec-vectors --preset mainnet -k shuffling
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import click

from pyspec_vectors_testing.vectors import ensure_preset


@click.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--preset",
    type=click.Choice(["minimal", "mainnet"], case_sensitive=False),
    default="minimal",
    help="Consensus preset to run (default: minimal).",
)
def pyspec_vectors(pytest_args: Sequence[str], preset: str) -> None:
    """Run the pinned upstream Gloas vectors for one preset against the port."""
    preset = preset.lower()
    # The spec reads the preset once at import; only the fresh subprocess below
    # sees this export, so it must be set before pytest starts.
    os.environ["GLOAS_PRESET"] = preset

    vectors_path = ensure_preset(preset)

    config_path = Path(__file__).parent / "pytest_ini_files" / "pytest-pyspec-vectors.ini"
    args = [
        "-c",
        str(config_path),
        f"--preset={preset}",
        str(vectors_path),
        *pytest_args,
    ]
    exit_code = subprocess.run([sys.executable, "-m", "pytest", *args]).returncode
    sys.exit(exit_code)
