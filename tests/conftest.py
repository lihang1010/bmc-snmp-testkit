"""Register the generated-case plugin and provide offline fixtures."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest_plugins = ["snmp_test.runner.pytest_plugin"]

ROOT = Path(__file__).resolve().parents[1]
MIB = ROOT / "TTY-T1ZDG-v1.0_20261026.mib"
CONFIG_EXAMPLE = ROOT / "config" / "config.example.yaml"


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def mib_path() -> Path:
    return MIB


@pytest.fixture(scope="session")
def example_config_path() -> Path:
    return CONFIG_EXAMPLE


@pytest.fixture(scope="session")
def offline_config():
    from snmp_test.config import load_config

    cfg = load_config(CONFIG_EXAMPLE)
    assert cfg.validate() == []
    return cfg


@pytest.fixture(scope="session")
def offline_model(mib_path):
    from snmp_test.model.mib_model import build_model

    return build_model(mib_path)


@pytest.fixture
def event_loop_for_agent():
    """Give synchronous tests a dedicated loop when they need one."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)
