import base64
import logging
import os
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from vuln_tracker.database import (
    DEPENDENCIES,
    PACKAGE_METADATA,
    close_database_connection,
    create_indexes,
    save_analysis,
)
from vuln_tracker.enrichment import enrich_dependencies
from vuln_tracker.parsers import (
    get_username_and_repo,
    parse_package_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_indexes()

    yield

    close_database_connection()


app = FastAPI(lifespan=lifespan)


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

    async with httpx.AsyncClient(timeout=20) as client:
        for file_name in FILE_NAMES:
            repository_url = f"{GITHUB_BASE_URL}/repos/{username}/{repo}"
            file_url = f"{repository_url}/contents/{file_name}"

            try:
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

            file_data = response.json()
            content = base64.b64decode(file_data["content"]).decode("utf-8")

            if file_name == "requirements.txt":
                dependencies = parse_requirements(content, repo)
            elif file_name == "uv.lock":
                dependencies = parse_uv_lock(content, repo)
            elif file_name == "poetry.lock":
                dependencies = parse_poetry_lock(content, repo)
            elif file_name == "package-lock.json":
                dependencies = parse_package_lock(content, repo)
            else:
                dependencies = []

            project_dependencies.extend(dependencies)

        analysis_id = str(uuid4())

        dependencies, package_metadata = await enrich_dependencies(
            project_dependencies,
            client,
        )

    saved_dependencies = save_analysis(
        analysis_id,
        dependencies,
        package_metadata,
    )

    return {
        "repository": repo_url,
        "analysis_id": analysis_id,
        "message": "Repository analysis completed.",
        "dependency_count": len(saved_dependencies),
        "dependencies": saved_dependencies,
    }


@app.get("/dependencies/{dependency_id}")
async def get_dependency_details(dependency_id: str):
    try:
        dependency = DEPENDENCIES.find_one({"_id": ObjectId(dependency_id)})
    except InvalidId:
        raise HTTPException(
            status_code=400,
            detail="Invalid dependency ID",
        )

    if not dependency:
        raise HTTPException(
            status_code=404,
            detail="Dependency not found",
        )

    metadata = PACKAGE_METADATA.find_one(
        {
            "ecosystem": dependency["ecosystem"],
            "name": dependency["name"],
        }
    )

    dependency["_id"] = str(dependency["_id"])

    if metadata:
        metadata["_id"] = str(metadata["_id"])

    return {
        "dependency": dependency,
        "metadata": metadata,
    }


@app.get("/")
async def root():
    return {"message": "Vulnerability Tracker API is running"}
