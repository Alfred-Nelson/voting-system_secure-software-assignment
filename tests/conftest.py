import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app                    # noqa: E402
from app.config import TestConfig             # noqa: E402
from app.seed import seed                     # noqa: E402


class _Cfg(TestConfig):
    MASTER_KEY_HEX = secrets.token_hex(32)
    LEDGER_BATCH_SIZE = 3


@pytest.fixture
def app(tmp_path):
    return create_app(_Cfg, tmp_path / "data")


@pytest.fixture
def svc(app):
    return app.evote


@pytest.fixture
def creds(svc):
    return seed(svc)
