from unittest.mock import MagicMock

import pytest

from vuln_tracker.osv import get_vulnerabilities


@pytest.mark.asyncio
async def test_get_vulnerabilities(client, expected_vulnerabilities, jinja2_pypi):
    response = MagicMock()
    response.json.return_value = {
        "vulns": expected_vulnerabilities,
    }
    response.raise_for_status = lambda: None

    client.post.return_value = response

    vulnerabilities = await get_vulnerabilities(
        **jinja2_pypi,
        client=client,
    )

    assert vulnerabilities == expected_vulnerabilities


@pytest.mark.asyncio
async def test_get_vulnerabilities_returns_empty_list(client, jinja2_pypi):
    response = MagicMock()
    response.json.return_value = {}
    response.raise_for_status = lambda: None

    client.post.return_value = response

    vulnerabilities = await get_vulnerabilities(
        **jinja2_pypi,
        client=client,
    )

    assert vulnerabilities == []


@pytest.mark.asyncio
async def test_get_vulnerabilities_unsupported_ecosystem(
    client,
    jinja2_unknown_ecosystem,
):

    with pytest.raises(ValueError, match="Unsupported ecosystem"):
        await get_vulnerabilities(
            **jinja2_unknown_ecosystem,
            client=client,
        )

    client.post.assert_not_awaited()
