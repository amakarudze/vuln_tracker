import logging
import os
from contextlib import asynccontextmanager

import httpx
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from vuln_tracker.database import (
    DEPENDENCIES,
    PACKAGE_METADATA,
    close_database_connection,
    complete_analysis,
    create_indexes,
    fail_analysis,
    get_dependency_vulnerabilities,
    get_repository_metadata,
    save_analysis,
    save_repository_metadata,
    save_vulnerabilities,
    start_analysis,
)
from vuln_tracker.enrichment import enrich_dependencies
from vuln_tracker.github import get_github_contributors, get_username_and_repo
from vuln_tracker.osv import deduplicate_vulnerabilities, get_vulnerabilities
from vuln_tracker.parsers.javascript import parse_package_lock
from vuln_tracker.parsers.python import (
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
)
from vuln_tracker.repository_files import (
    get_dependency_file_content,
    get_dependency_file_paths,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_indexes()

    yield

    close_database_connection()


app = FastAPI(lifespan=lifespan)


GITHUB_BASE_URL = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

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

    analysis = start_analysis(
        owner=username,
        repository=repo,
        repository_url=repo_url,
    )
    analysis_id = analysis["analysis_id"]

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    project_dependencies = []
    contributors = None
    saved_dependencies = []
    total_vulnerability_count = 0
    analysis_warnings = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                dependency_files = await get_dependency_file_paths(
                    username,
                    repo,
                    client,
                    headers,
                )

            except httpx.TimeoutException as exc:
                logger.exception("Timed out while scanning repository tree")
                raise HTTPException(
                    status_code=504,
                    detail="Timed out while scanning repository files.",
                ) from exc

            except httpx.HTTPError as exc:
                logger.exception("Could not scan repository tree")
                raise HTTPException(
                    status_code=502,
                    detail=("Could not retrieve the repository file structure."),
                ) from exc

            logger.info(
                "Found %d supported dependency files in %s/%s",
                len(dependency_files),
                username,
                repo,
            )

            for dependency_file in dependency_files:
                file_path = dependency_file["path"]
                file_name = file_path.rsplit("/", maxsplit=1)[-1]

                try:
                    content = await get_dependency_file_content(
                        username,
                        repo,
                        file_path,
                        client,
                        headers,
                    )

                except httpx.TimeoutException:
                    logger.warning(
                        "Timed out retrieving dependency file %s",
                        file_path,
                    )
                    analysis_warnings.append(f"Timed out retrieving {file_path}")
                    continue

                except httpx.HTTPError:
                    logger.exception(
                        "Could not retrieve dependency file %s",
                        file_path,
                    )
                    analysis_warnings.append(f"Could not retrieve {file_path}")
                    continue

                except ValueError, KeyError:
                    logger.exception(
                        "Could not decode dependency file %s",
                        file_path,
                    )
                    analysis_warnings.append(f"Could not decode {file_path}")
                    continue

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

                for dependency in dependencies:
                    dependency["source_file"] = file_path

                project_dependencies.extend(dependencies)

            if project_dependencies:
                dependencies, package_metadata = await enrich_dependencies(
                    project_dependencies,
                    client,
                )
            else:
                dependencies = []
                package_metadata = []

            # Save dependencies under this analysis snapshot.
            saved_dependencies = save_analysis(
                analysis_id=analysis_id,
                dependencies=dependencies,
                package_metadata=package_metadata,
            )

            try:
                contributors = await get_github_contributors(
                    username,
                    repo,
                    client,
                    token=GITHUB_TOKEN,
                )

            except RuntimeError as exc:
                logger.warning(
                    "Could not retrieve GitHub contributors for %s/%s: %s",
                    username,
                    repo,
                    exc,
                )
                analysis_warnings.append("Could not retrieve GitHub contributors")

            # Group identical packages to avoid duplicate OSV requests.
            dependency_groups = {}

            for dependency in saved_dependencies:
                package_key = (
                    dependency["ecosystem"],
                    dependency["name"],
                    dependency["version"],
                )

                dependency_groups.setdefault(
                    package_key,
                    [],
                ).append(dependency)

            for (
                ecosystem,
                name,
                version,
            ), matching_dependencies in dependency_groups.items():
                try:
                    vulnerabilities = await get_vulnerabilities(
                        name=name,
                        version=version,
                        ecosystem=ecosystem,
                        client=client,
                    )

                except httpx.TimeoutException:
                    logger.warning(
                        "OSV lookup timed out for %s %s (%s)",
                        name,
                        version,
                        ecosystem,
                    )
                    analysis_warnings.append(
                        f"OSV lookup timed out for {name} {version}"
                    )
                    continue

                except httpx.HTTPError, ValueError:
                    logger.exception(
                        "OSV lookup failed for %s %s (%s)",
                        name,
                        version,
                        ecosystem,
                    )
                    analysis_warnings.append(f"OSV lookup failed for {name} {version}")
                    continue

                # Save the same lookup result against each matching
                # dependency record.
                for dependency in matching_dependencies:
                    save_vulnerabilities(
                        analysis_id=analysis_id,
                        dependency_id=dependency["_id"],
                        dependency=dependency,
                        vulnerabilities=vulnerabilities,
                    )

                total_vulnerability_count += len(vulnerabilities)

            if contributors is not None:
                save_repository_metadata(
                    owner=username,
                    repository=repo,
                    contributors=contributors,
                )

        if not dependency_files:
            message = "No supported dependency files were found in this repository."
        elif not saved_dependencies:
            message = (
                "Dependency files were found, but no dependencies could be extracted."
            )
        elif analysis_warnings:
            message = "Repository analysis completed with warnings."
        else:
            message = "Repository analysis completed."

        # Only update the project's latest successful analysis
        # after all processing and persistence have finished.
        complete_analysis(
            analysis_id=analysis_id,
            dependency_count=len(saved_dependencies),
            vulnerability_count=total_vulnerability_count,
        )

        return {
            "repository": repo_url,
            "analysis_id": analysis_id,
            "message": message,
            "status": "completed",
            "warnings": analysis_warnings,
            "dependency_file_count": len(dependency_files),
            "dependency_count": len(saved_dependencies),
            "vulnerability_count": total_vulnerability_count,
            "dependencies": saved_dependencies,
        }

    except Exception as exc:
        logger.exception(
            "Analysis failed for %s/%s (analysis_id=%s)",
            username,
            repo,
            analysis_id,
        )

        fail_analysis(analysis_id, str(exc))

        raise


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


@app.get("/dependencies/{dependency_id}/vulnerabilities")
async def get_dependency_vulnerabilities_endpoint(dependency_id: str):
    record = get_dependency_vulnerabilities(dependency_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability results not found for this dependency.",
        )

    vulnerabilities = deduplicate_vulnerabilities(record["vulnerabilities"])

    return {
        "dependency_id": dependency_id,
        "package_name": record["package_name"],
        "installed_version": record["installed_version"],
        "ecosystem": record["ecosystem"],
        "vulnerability_count": len(vulnerabilities),
        "advisory_count": record["vulnerability_count"],
        "vulnerabilities": vulnerabilities,
        "last_checked": record["last_checked"],
    }


@app.get("/repositories/{owner}/{repository}/contributors")
async def get_repository_contributors(owner: str, repository: str):
    metadata = get_repository_metadata(owner, repository)

    if metadata is not None:
        return {
            "owner": owner,
            "repository": repository,
            "contributors": metadata.get("contributors", []),
        }

    # Fetch contributor information if it is not cached.
    async with httpx.AsyncClient() as client:
        contributors = await get_github_contributors(
            owner,
            repository,
            client,
            token=os.getenv("GITHUB_TOKEN"),
        )

    save_repository_metadata(owner, repository, contributors)

    return {
        "owner": owner,
        "repository": repository,
        "contributors": contributors,
    }


@app.get("/")
async def root():
    return {"message": "Vulnerability Tracker API is running"}
