import os
import tempfile

# Use an isolated temp DB per test session before app imports read settings.
_tmp = tempfile.mkdtemp(prefix="cyberorch-test-")
os.environ["CO_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c
