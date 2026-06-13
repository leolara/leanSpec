"""
Pytest plugin that collects upstream vector cases as first-class test items.

Each vector case directory becomes one pytest item, so the run gets granular
pass/fail reporting, name-based filtering, last-failed reruns, and xdist
distribution for free. A custom failure representation renders the handler's
own diff rather than a deep Python traceback.

The active preset is fixed by the GLOAS_PRESET environment variable, which the
command-line wrapper exports before launching pytest so every worker imports the
spec under one consistent preset.
"""

from __future__ import annotations

import pytest
import yaml

from pyspec_vectors_testing.handlers.epoch_processing import run_epoch_processing_case
from pyspec_vectors_testing.handlers.operations import run_operations_case
from pyspec_vectors_testing.handlers.rewards import run_rewards_case
from pyspec_vectors_testing.handlers.shuffling import run_shuffling_case
from pyspec_vectors_testing.handlers.state_transition import run_blocks_case, run_sanity_case

# Runners whose cases this harness knows how to execute.
SUPPORTED_RUNNERS = frozenset(
    {"shuffling", "operations", "epoch_processing", "sanity", "finality", "random", "rewards"}
)


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the preset option, recorded for reporting and filtering."""
    group = parser.getgroup("pyspec-vectors")
    group.addoption(
        "--preset",
        choices=("minimal", "mainnet"),
        default="mainnet",
        help="Consensus preset the vectors belong to.",
    )


class VectorCaseFile(pytest.File):
    """A vector case directory, identified by its manifest file."""

    def collect(self):  # noqa: ANN201
        """Yield the single item that runs this case."""
        yield VectorCaseItem.from_parent(self, name=self.path.parent.name)


class VectorCaseItem(pytest.Item):
    """One vector case, dispatched to a handler by the runner named in its manifest."""

    def runtest(self) -> None:
        """Dispatch the case to the handler for its runner."""
        case_dir = self.path.parent
        manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
        runner = manifest.get("runner")
        if runner == "shuffling":
            run_shuffling_case(case_dir)
        elif runner == "operations":
            run_operations_case(case_dir, manifest.get("handler"))
        elif runner == "epoch_processing":
            run_epoch_processing_case(case_dir, manifest.get("handler"))
        elif runner == "sanity":
            run_sanity_case(case_dir, manifest.get("handler"))
        elif runner in ("finality", "random"):
            run_blocks_case(case_dir)
        elif runner == "rewards":
            run_rewards_case(case_dir)
        else:
            pytest.skip(f"runner not yet supported: {runner}")

    def repr_failure(self, excinfo, style=None):  # noqa: ANN001, ANN201
        """Render the handler's own assertion message, not a Python traceback."""
        if isinstance(excinfo.value, AssertionError):
            return str(excinfo.value)
        return super().repr_failure(excinfo, style=style)

    def reportinfo(self):  # noqa: ANN201
        """Provide a readable location for the item in reports."""
        return self.path, 0, self.name


def pytest_collect_file(parent: pytest.Collector, file_path) -> pytest.Collector | None:  # noqa: ANN001
    """Collect each supported vector case from its manifest file."""
    if file_path.name != "manifest.yaml":
        return None
    manifest = yaml.safe_load(file_path.read_text())
    if manifest and manifest.get("runner") in SUPPORTED_RUNNERS:
        return VectorCaseFile.from_parent(parent, path=file_path)
    return None
