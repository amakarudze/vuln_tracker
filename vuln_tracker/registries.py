from urllib.parse import quote

import httpx


async def get_pypi_package_info(
    package_name: str,
    client: httpx.AsyncClient,
) -> dict:
    url = f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"

    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

        info = data["info"]
        releases = data.get("releases", {})
        latest_version = info.get("version")

        release_history = {
            version: [
                {
                    "filename": file.get("filename"),
                    "upload_time": file.get("upload_time_iso_8601"),
                    "url": file.get("url"),
                    "size": file.get("size"),
                    "package_type": file.get("packagetype"),
                    "requires_python": file.get("requires_python"),
                }
                for file in files
            ]
            for version, files in releases.items()
        }

        latest_files = release_history.get(latest_version, [])

        return {
            "registry": "pypi",
            "name": info.get("name"),
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
            "release_date": (
                latest_files[0].get("upload_time") if latest_files else None
            ),
            "releases": release_history,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "registry": "pypi",
            "name": package_name,
            "lookup_error": f"PyPI returned HTTP {exc.response.status_code}",
        }

    except httpx.RequestError as exc:
        return {
            "registry": "pypi",
            "name": package_name,
            "lookup_error": f"Could not reach PyPI: {exc}",
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

        return {
            "registry": "npm",
            "name": data.get("name", package_name),
            "latest_version": latest_version,
            "description": data.get("description"),
            "license": latest_metadata.get("license"),
            "author": latest_metadata.get("author"),
            "maintainers": data.get("maintainers", []),
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

    except httpx.RequestError as exc:
        return {
            "registry": "npm",
            "name": package_name,
            "lookup_error": f"Could not reach npm: {exc}",
        }
