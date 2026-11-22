import os

import requests
from fastapi import HTTPException

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def get_github_file_contents(file_url: str) -> requests.Response:
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    response = requests.get(file_url, headers=headers)
    return response


def get_pypi_package_info(package_name: str) -> dict:
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        info = data["info"]

        latest_version = info["version"]

        # Get release dates for all published versions
        releases = {}

        for version, files in data.get("releases", {}).items():
            releases[version] = [
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

        return {
            "name": info.get("name"),
            "version": latest_version,
            "summary": info.get("summary"),
            "description": info.get("description"),
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "maintainer": info.get("maintainer"),
            "maintainer_email": info.get("maintainer_email"),
            "license": info.get("license"),
            "requires_python": info.get("requires_python"),
            "keywords": info.get("keywords"),
            "classifiers": info.get("classifiers"),
            "project_urls": info.get("project_urls"),
            "dependencies": info.get("requires_dist"),
            "release_date": (
                releases.get(latest_version, [{}])[0].get("upload_time")
                if releases.get(latest_version)
                else None
            ),
            "releases": releases,
        }

    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(
                status_code=404, detail=f"Package '{package_name}' not found on PyPI"
            )
        raise HTTPException(status_code=502, detail="PyPI API error")

    except requests.RequestException:
        raise HTTPException(status_code=503, detail="Unable to reach PyPI")
