import httpx

OSV_API_URL = "https://api.osv.dev/v1/query"

ECOSYSTEM_MAPPING = {
    "pypi": "PyPI",
    "npm": "npm",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "maven": "Maven",
}


async def get_vulnerabilities(
    name: str,
    version: str,
    ecosystem: str,
    client: httpx.AsyncClient,
) -> list[dict]:
    osv_ecosystem = ECOSYSTEM_MAPPING.get(ecosystem.lower())

    if osv_ecosystem is None:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")

    payload = {
        "package": {
            "name": name,
            "ecosystem": osv_ecosystem,
        },
        "version": version,
    }

    response = await client.post(OSV_API_URL, json=payload)
    response.raise_for_status()

    data = response.json()
    return data.get("vulns", [])


def deduplicate_vulnerabilities(
    vulnerabilities: list[dict],
) -> list[dict]:
    grouped = {}

    for vulnerability in vulnerabilities:
        identifiers = {
            vulnerability["id"],
            *vulnerability.get("aliases", []),
        }

        existing = next(
            (key for key in identifiers if key in grouped),
            None,
        )

        if existing:
            grouped[existing]["aliases"] = list(
                set(
                    grouped[existing].get("aliases", [])
                    + vulnerability.get("aliases", [])
                    + [vulnerability["id"]]
                )
            )
        else:
            grouped[vulnerability["id"]] = {
                **vulnerability,
                "aliases": list(set(vulnerability.get("aliases", []))),
            }

    return list(grouped.values())
