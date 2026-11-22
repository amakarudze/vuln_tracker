import asyncio

import httpx

from vuln_tracker.registries import (
    get_npm_package_info,
    get_pypi_package_info,
)

PYTHON_FILES = {
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
}


async def enrich_dependencies(
    dependencies: list[dict],
    client: httpx.AsyncClient,
) -> tuple[list[dict], list[dict]]:
    semaphore = asyncio.Semaphore(10)

    # Avoid looking up the same package repeatedly within one analysis.
    lookups = {}

    for dependency in dependencies:
        ecosystem = "pypi" if dependency["source_file"] in PYTHON_FILES else "npm"

        key = (ecosystem, dependency["name"])

        if key not in lookups:
            lookups[key] = ecosystem

    async def fetch_metadata(ecosystem: str, package_name: str):
        async with semaphore:
            if ecosystem == "pypi":
                return await get_pypi_package_info(package_name, client)

            return await get_npm_package_info(package_name, client)

    metadata_results = await asyncio.gather(
        *[
            fetch_metadata(ecosystem, package_name)
            for ecosystem, package_name in lookups
        ]
    )

    metadata_by_package = dict(zip(lookups, metadata_results))

    package_metadata = []

    for (ecosystem, package_name), metadata in metadata_by_package.items():
        if not metadata or metadata.get("lookup_error"):
            continue

        package_metadata.append(
            {
                **metadata,
                "ecosystem": ecosystem,
                "name": package_name,
            }
        )

    for dependency in dependencies:
        ecosystem = "pypi" if dependency["source_file"] in PYTHON_FILES else "npm"

        dependency["ecosystem"] = ecosystem
        dependency["package_key"] = f"{ecosystem}:{dependency['name']}"

    return dependencies, package_metadata
