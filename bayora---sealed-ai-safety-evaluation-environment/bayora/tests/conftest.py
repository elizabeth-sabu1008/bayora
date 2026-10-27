import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from gateway.main import app, db
from gateway.database import Database
from common.crypto import create_jwt_token


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Use a temporary SQLite database for test runs."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_path = tmp.name
    tmp.close()

    original_db = db.db_path
    db.db_path = tmp_path
    db.init_db()

    yield

    # Cleanup
    if os.path.exists(tmp_path):
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    return create_jwt_token(sub="admin-operator", role="admin", zone="admin", expires_in_seconds=600)


@pytest.fixture
def red_token():
    return create_jwt_token(sub="red-agent-01", role="red", zone="red", expires_in_seconds=600)


@pytest.fixture
def blue_token():
    return create_jwt_token(sub="blue-guard-01", role="blue", zone="blue", expires_in_seconds=600)


@pytest.fixture
def auditor_token():
    return create_jwt_token(sub="auditor-eval-01", role="auditor", zone="evidence", expires_in_seconds=600)


@pytest.fixture
def expired_token():
    # Token expired 1 second ago (negative expiration)
    return create_jwt_token(sub="expired-user", role="admin", zone="admin", expires_in_seconds=-5)
