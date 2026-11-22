import base64
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from vuln_tracker.database import COLLECTION, save_dependencies
from vuln_tracker.parsers import (
    get_username_and_repo,
    parse_package_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
)

app = FastAPI()

GITHUB_BASE_URL = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
USER_NAME = os.getenv("GITHUB_USERNAME")

FILE_NAMES = [
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "package-lock.json",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


class RepositoryRequest(BaseModel):
    repoUrl: HttpUrl


@app.post("/analyse")
async def analyse(request: RepositoryRequest):
    repo_url = str(request.repoUrl)
    username, repo = get_username_and_repo(repo_url)

    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    project_dependencies = []

    for file_name in FILE_NAMES:
        repository_url = f"{GITHUB_BASE_URL}/repos/{username}/{repo}"
        file_url = f"{repository_url}/contents/{file_name}"
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    file_url,
                    headers=headers,
                )

            if response.status_code == 404:
                logger.info("Skipping %s: file not found", file_name)
                continue

            response.raise_for_status()

        except httpx.TimeoutException:
            logger.exception("GitHub request timed out for %s", file_name)
            raise HTTPException(
                status_code=504,
                detail=f"GitHub request timed out for {file_name}",
            )

        except httpx.RequestError:
            logger.exception("GitHub connection failed for %s", file_name)
            raise HTTPException(
                status_code=502,
                detail=f"Could not connect to GitHub while retrieving {file_name}",
            )

        except httpx.HTTPStatusError as exc:
            logger.exception("GitHub returned an HTTP error for %s", file_name)
            raise HTTPException(
                status_code=502,
                detail=f"GitHub returned HTTP {exc.response.status_code} for {file_name}",
            )

        if response.status_code == 200:
            file_data = response.json()
            content = base64.b64decode(file_data["content"]).decode("utf-8")

            if file_name == "requirements.txt":
                dependencies = parse_requirements(content, repo)
                save_dependencies(dependencies)
            elif file_name == "uv.lock":
                dependencies = parse_uv_lock(content, repo)
                save_dependencies(dependencies)
            elif file_name == "poetry.lock":
                dependencies = parse_poetry_lock(content, repo)
                save_dependencies(dependencies)
            elif file_name == "package-lock.json":
                dependencies = parse_package_lock(content, repo)
                save_dependencies(dependencies)
            else:
                continue

            project_dependencies.append(
                {
                    "file_name": file_name,
                    "dependencies": dependencies,
                }
            )

    return {
        "repository": repo_url,
        "message": "Repository analysis completed.",
        "dependencies": project_dependencies,
    }


@app.get("/packages/{package_name}")
def read_item(package_name: str, q: str | None = None):
    package = COLLECTION.find_one({"package_name": package_name}) or {}
    if package:
        package["_id"] = str(package["_id"])
    return {"package": package, "q": q}


@app.get("/")
async def root():
    return {"message": "Vulnerability Tracker API is running"}
