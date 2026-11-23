from unittest.mock import AsyncMock

import httpx
import pytest


@pytest.fixture
def client():
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def expected_vulnerabilities():
    return [
        {
            "id": "GHSA-1234-5678-9012",
            "summary": "Example Jinja2 vulnerability",
        }
    ]


@pytest.fixture
def jinja2_pypi():
    return {
        "name": "jinja2",
        "version": "2.4.1",
        "ecosystem": "pypi",
    }


@pytest.fixture
def jinja2_unknown_ecosystem():
    return {
        "name": "jinja2",
        "version": "2.4.1",
        "ecosystem": "unknown",
    }
