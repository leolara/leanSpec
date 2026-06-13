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

from pyspec_vectors_testing.handlers.shuffling import run_shuffling_case


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the preset option, recorded for reporting and filtering."""
    group = parser.getgroup("pyspec-vectors")
    group.addoption(
        "--preset",
        choices=("minimal", "mainnet"),
        default="mainnet",
        help="Consensus preset the vectors belong to.",
    )


class ShufflingCaseFile(pytest.File):
    """A shuffling case directory, identified by its mapping file."""

    def collect(self):  # noqa: ANN201
        """Yield the single item that runs this case."""
        yield ShufflingCaseItem.from_parent(self, name=self.path.parent.name)


class ShufflingCaseItem(pytest.Item):
    """One shuffling vector case."""

    def runtest(self) -> None:
        """Run the case through the shuffling handler."""
        run_shuffling_case(self.path.parent)

    def repr_failure(self, excinfo, style=None):  # noqa: ANN001, ANN201
        """Render the handler's own assertion message, not a Python traceback."""
        if isinstance(excinfo.value, AssertionError):
            return str(excinfo.value)
        return super().repr_failure(excinfo, style=style)

    def reportinfo(self):  # noqa: ANN201
        """Provide a readable location for the item in reports."""
        return self.path, 0, f"shuffling: {self.name}"


def pytest_collect_file(parent: pytest.Collector, file_path) -> pytest.Collector | None:  # noqa: ANN001
    """Collect each shuffling case from its mapping file."""
    if file_path.name == "mapping.yaml" and "shuffling" in file_path.parts:
        return ShufflingCaseFile.from_parent(parent, path=file_path)
    return None
