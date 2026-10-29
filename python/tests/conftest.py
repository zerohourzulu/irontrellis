"""Shared fixtures: repository paths, the reference fixtures and the conformance material."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

PYTHON_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PYTHON_ROOT.parent
SRC = PYTHON_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

LEGACY_FIXTURES = REPO_ROOT / "packages" / "reference-0.2" / "tests" / "fixtures"
CONFORMANCE = REPO_ROOT / "conformance"
CRYPTO_VECTORS = CONFORMANCE / "crypto-vectors.json"
if not CRYPTO_VECTORS.exists():  # fall back to the specs copy in a partial checkout
    CRYPTO_VECTORS = REPO_ROOT.parent / "irontrellis-work" / "specs" / "04-crypto-vectors.json"
CORE_DIST = REPO_ROOT / "packages" / "core" / "dist" / "index.js"
NODE = shutil.which("node")


def load_json(path: Path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="session")
def crypto_vectors():
    return load_json(CRYPTO_VECTORS)


@pytest.fixture(scope="session")
def legacy_histories():
    from irontrellis.canonical import from_plain
    names = {"first-look": "handover-history.json", "no-review-power": "handover-denied-history.json", "mandate": "mandate-history.json"}
    histories = {name: from_plain(load_json(LEGACY_FIXTURES / file)) for name, file in names.items()}
    histories["mandate-quantitative-only"] = histories["mandate"][:6]
    return histories


@pytest.fixture(scope="session")
def v1_histories():
    from irontrellis.canonical import from_plain
    folder = CONFORMANCE / "v1" / "histories"
    if not folder.exists():
        pytest.skip("conformance/v1 histories are not generated")
    return {path.stem: from_plain(load_json(path)) for path in sorted(folder.glob("*.json"))}


def requires_node():
    if NODE is None or not CORE_DIST.exists():
        pytest.skip("node and packages/core/dist are required for differential tests")
