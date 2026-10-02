"""Shared pytest configuration: gate root/lab integration tests."""

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    lab_ok = os.geteuid() == 0 and os.environ.get("LEAKPROBE_LAB") == "1"
    if lab_ok:
        return
    skip = pytest.mark.skip(reason="needs root and LEAKPROBE_LAB=1")
    for item in items:
        if "root" in item.keywords:
            item.add_marker(skip)
