from urllib.parse import quote

import httpx


def extract_pypi_releases(releases: dict) -> dict:
    """Extract release dates and file information from PyPI releases."""
    release_history = {}

    for version, files in releases.items():
        file_details = [
            {
                "filename": file.get("filename"),
                "upload_time": (
                    file.get("upload_time_iso_8601") or file.get("upload_time")
                ),
                "url": file.get("url"),
                "size": file.get("size"),
                "package_type": file.get("packagetype"),
                "requires_python": file.get("requires_python"),
            }
            for file in files
        ]

        dates = [file["upload_time"] for file in file_details if file["upload_time"]]

        release_history[version] = {
            "release_date": min(dates) if dates else None,
            "files": file_details,
        }

    return release_history


async def get_pypi_package_info(
    package_name: str,
    client: httpx.AsyncClient,
) -> dict:
    url = f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"

    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

        info = data.get("info", {})
        releases = extract_pypi_releases(data.get("releases", {}))
        latest_version = info.get("version")

        latest_release = releases.get(latest_version, {})

        # These fields are publisher-provided metadata.
        maintainers = []

        if info.get("maintainer"):
            maintainers.append(
                {
                    "name": info.get("maintainer"),
                    "email": info.get("maintainer_email"),
                    "role": "Maintainer",
                    "source": "project_metadata",
                }
            )

        if info.get("author"):
            maintainers.append(
                {
                    "name": info.get("author"),
                    "email": info.get("author_email"),
                    "role": "Author",
                    "source": "project_metadata",
                }
            )

        # PyPI ownership information is not present for every project.
        ownership = data.get("ownership") or {}

        for role in ownership.get("roles", []):
            maintainers.append(
                {
                    "name": role.get("user"),
                    "email": None,
                    "role": role.get("role"),
                    "source": "pypi_ownership",
                }
            )

        return {
            "registry": "pypi",
            "name": info.get("name", package_name),
            "latest_version": latest_version,
            "summary": info.get("summary"),
            "description": info.get("description"),
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "license": info.get("license"),
            "requires_python": info.get("requires_python"),
            "keywords": info.get("keywords"),
            "classifiers": info.get("classifiers"),
            "project_urls": info.get("project_urls"),
            "dependencies": info.get("requires_dist"),
            "maintainers": maintainers,
            "release_date": latest_release.get("release_date"),
            "releases": releases,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "registry": "pypi",
            "name": package_name,
            "lookup_error": f"PyPI returned HTTP {exc.response.status_code}",
        }

    except (httpx.RequestError, ValueError) as exc:
        return {
            "registry": "pypi",
            "name": package_name,
            "lookup_error": f"Could not retrieve PyPI metadata: {exc}",
        }


async def get_npm_package_info(
    package_name: str,
    client: httpx.AsyncClient,
) -> dict:
    # Preserve @ for scoped packages, but encode the slash.
    encoded_name = quote(package_name, safe="@")
    url = f"https://registry.npmjs.org/{encoded_name}"

    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

        latest_version = data.get("dist-tags", {}).get("latest")
        versions = data.get("versions", {})
        times = data.get("time", {})

        release_history = {
            version: {
                "release_date": times.get(version),
                "dependencies": metadata.get("dependencies", {}),
                "dev_dependencies": metadata.get("devDependencies", {}),
                "peer_dependencies": metadata.get("peerDependencies", {}),
                "engines": metadata.get("engines", {}),
                "dist": metadata.get("dist", {}),
            }
            for version, metadata in versions.items()
        }

        latest_metadata = versions.get(latest_version, {})

        maintainers = [
            {
                "name": maintainer.get("name"),
                "email": maintainer.get("email"),
                "role": "Maintainer",
                "source": "npm_registry",
            }
            for maintainer in data.get("maintainers", [])
        ]

        return {
            "registry": "npm",
            "name": data.get("name", package_name),
            "latest_version": latest_version,
            "description": data.get("description"),
            "license": latest_metadata.get("license"),
            "author": latest_metadata.get("author"),
            "maintainers": maintainers,
            "repository": data.get("repository"),
            "homepage": data.get("homepage"),
            "keywords": data.get("keywords", []),
            "dependencies": latest_metadata.get("dependencies", {}),
            "release_date": times.get(latest_version),
            "releases": release_history,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "registry": "npm",
            "name": package_name,
            "lookup_error": f"npm returned HTTP {exc.response.status_code}",
        }

    except (httpx.RequestError, ValueError) as exc:
        return {
            "registry": "npm",
            "name": package_name,
            "lookup_error": f"Could not retrieve npm metadata: {exc}",
        }
