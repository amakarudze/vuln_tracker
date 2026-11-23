import os
from datetime import UTC, datetime
from uuid import uuid4

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, MongoClient, ReturnDocument, UpdateOne

client = MongoClient(os.getenv("MONGODB_URL"))
db = client["vuln_tracker"]

PROJECTS = db["projects"]
ANALYSES = db["analyses"]
DEPENDENCIES = db["dependencies"]
PACKAGE_METADATA = db["package_metadata"]
REPOSITORY_METADATA = db["repository_metadata"]
VULNERABILITIES = db["vulnerabilities"]


def create_indexes():
    # One project per GitHub owner/repository.
    PROJECTS.create_index(
        [
            ("owner", ASCENDING),
            ("repository", ASCENDING),
        ],
        unique=True,
    )

    # Analysis history for each project.
    ANALYSES.create_index(
        [
            ("project_id", ASCENDING),
            ("created_at", ASCENDING),
        ]
    )

    ANALYSES.create_index(
        [("analysis_id", ASCENDING)],
        unique=True,
    )

    PACKAGE_METADATA.create_index(
        [
            ("ecosystem", ASCENDING),
            ("name", ASCENDING),
        ],
        unique=True,
    )

    DEPENDENCIES.create_index(
        [
            ("analysis_id", ASCENDING),
            ("project", ASCENDING),
            ("ecosystem", ASCENDING),
            ("name", ASCENDING),
            ("version", ASCENDING),
            ("source_file", ASCENDING),
            ("package_path", ASCENDING),
        ],
        unique=True,
    )

    REPOSITORY_METADATA.create_index(
        [
            ("owner", ASCENDING),
            ("repository", ASCENDING),
        ],
        unique=True,
    )

    VULNERABILITIES.create_index(
        [
            ("analysis_id", ASCENDING),
            ("dependency_id", ASCENDING),
        ],
        unique=True,
    )

    VULNERABILITIES.create_index([("dependency_id", ASCENDING)])


# -------------------------------------------------------------------
# PROJECTS AND ANALYSIS HISTORY
# -------------------------------------------------------------------


def start_analysis(
    owner: str,
    repository: str,
    repository_url: str,
) -> dict:
    """
    Get or create a project and register a new analysis run.

    Every call creates a new analysis_id. Previous analysis records
    and their dependencies/vulnerabilities are preserved.
    """
    now = datetime.now(UTC)

    project = PROJECTS.find_one_and_update(
        {
            "owner": owner,
            "repository": repository,
        },
        {
            "$set": {
                "repository_url": repository_url,
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )

    analysis_id = str(uuid4())

    ANALYSES.insert_one(
        {
            "analysis_id": analysis_id,
            "project_id": project["_id"],
            "owner": owner,
            "repository": repository,
            "repository_url": repository_url,
            "status": "running",
            "created_at": now,
        }
    )

    # Track the latest attempt separately from the latest successful run.
    PROJECTS.update_one(
        {"_id": project["_id"]},
        {
            "$set": {
                "last_analysis_id": analysis_id,
                "last_analysis_status": "running",
                "updated_at": now,
            }
        },
    )

    return {
        "project_id": str(project["_id"]),
        "analysis_id": analysis_id,
    }


def complete_analysis(
    analysis_id: str,
    dependency_count: int,
    vulnerability_count: int,
) -> None:
    """
    Mark an analysis as successful and make it the project's
    latest successful analysis.
    """
    now = datetime.now(UTC)

    analysis = ANALYSES.find_one_and_update(
        {"analysis_id": analysis_id},
        {
            "$set": {
                "status": "completed",
                "completed_at": now,
                "dependency_count": dependency_count,
                "vulnerability_count": vulnerability_count,
            }
        },
        return_document=ReturnDocument.AFTER,
    )

    if analysis is None:
        raise ValueError(f"Analysis not found: {analysis_id}")

    PROJECTS.update_one(
        {"_id": analysis["project_id"]},
        {
            "$set": {
                "latest_analysis_id": analysis_id,
                "latest_analysis_at": now,
                "dependency_count": dependency_count,
                "vulnerability_count": vulnerability_count,
                "last_analysis_id": analysis_id,
                "last_analysis_status": "completed",
                "updated_at": now,
            },
            "$unset": {
                "last_analysis_error": "",
            },
        },
    )


def fail_analysis(analysis_id: str, error: str) -> None:
    """
    Mark an analysis as failed without changing the project's
    latest successful analysis.
    """
    now = datetime.now(UTC)

    analysis = ANALYSES.find_one_and_update(
        {"analysis_id": analysis_id},
        {
            "$set": {
                "status": "failed",
                "completed_at": now,
                "error": str(error),
            }
        },
        return_document=ReturnDocument.AFTER,
    )

    if analysis is None:
        return

    PROJECTS.update_one(
        {
            "_id": analysis["project_id"],
            "last_analysis_id": analysis_id,
        },
        {
            "$set": {
                "last_analysis_status": "failed",
                "last_analysis_error": str(error),
                "updated_at": now,
            }
        },
    )


def get_projects() -> list[dict]:
    """Return all tracked projects."""
    projects = list(PROJECTS.find().sort("updated_at", -1))

    for project in projects:
        project["_id"] = str(project["_id"])

    return projects


def get_project(owner: str, repository: str) -> dict | None:
    """Return a project identified by its GitHub owner/repository."""
    project = PROJECTS.find_one(
        {
            "owner": owner,
            "repository": repository,
        }
    )

    if project is None:
        return None

    project["_id"] = str(project["_id"])
    return project


def get_project_analyses(
    owner: str,
    repository: str,
) -> dict | None:
    """Return a project and all its analysis snapshots."""
    project = PROJECTS.find_one(
        {
            "owner": owner,
            "repository": repository,
        }
    )

    if project is None:
        return None

    analyses = list(
        ANALYSES.find({"project_id": project["_id"]}).sort("created_at", -1)
    )

    for analysis in analyses:
        analysis["_id"] = str(analysis["_id"])
        analysis["project_id"] = str(analysis["project_id"])

    project["_id"] = str(project["_id"])

    return {
        "project": project,
        "analyses": analyses,
    }


def get_analysis(analysis_id: str) -> dict | None:
    """Return one analysis snapshot."""
    analysis = ANALYSES.find_one({"analysis_id": analysis_id})

    if analysis is None:
        return None

    analysis["_id"] = str(analysis["_id"])
    analysis["project_id"] = str(analysis["project_id"])

    return analysis


def get_analysis_dependencies(analysis_id: str) -> list[dict]:
    """Return dependencies belonging to a particular snapshot."""
    dependencies = list(DEPENDENCIES.find({"analysis_id": analysis_id}))

    for dependency in dependencies:
        dependency["_id"] = str(dependency["_id"])

    return dependencies


# -------------------------------------------------------------------
# DEPENDENCIES AND PACKAGE METADATA
# -------------------------------------------------------------------


def save_analysis(
    analysis_id: str,
    dependencies: list[dict],
    package_metadata: list[dict],
) -> list[dict]:
    now = datetime.now(UTC)

    # Save or update package metadata.
    metadata_operations = []

    for metadata in package_metadata:
        if metadata.get("lookup_error"):
            continue

        required_fields = {"ecosystem", "name"}
        missing = required_fields - metadata.keys()

        if missing:
            raise ValueError(f"Package metadata is missing required fields: {missing}")

        metadata_operations.append(
            UpdateOne(
                {
                    "ecosystem": metadata["ecosystem"],
                    "name": metadata["name"],
                },
                {
                    "$set": {
                        **metadata,
                        "updated_at": now,
                    },
                    "$setOnInsert": {
                        "created_at": now,
                    },
                },
                upsert=True,
            )
        )

    if metadata_operations:
        PACKAGE_METADATA.bulk_write(
            metadata_operations,
            ordered=False,
        )

    # Save dependencies for this particular analysis.
    dependency_operations = []

    for dependency in dependencies:
        required_fields = {
            "project",
            "ecosystem",
            "name",
            "version",
            "source_file",
        }
        missing = required_fields - dependency.keys()

        if missing:
            raise ValueError(f"Dependency is missing required fields: {missing}")

        dependency_record = {
            **dependency,
            "analysis_id": analysis_id,
            "package_path": dependency.get("package_path"),
            "package_key": dependency.get(
                "package_key",
                f"{dependency['ecosystem']}:{dependency['name']}",
            ),
        }

        dependency_operations.append(
            UpdateOne(
                {
                    "analysis_id": analysis_id,
                    "project": dependency_record["project"],
                    "ecosystem": dependency_record["ecosystem"],
                    "name": dependency_record["name"],
                    "version": dependency_record["version"],
                    "source_file": dependency_record["source_file"],
                    "package_path": dependency_record["package_path"],
                },
                {
                    "$set": {
                        **dependency_record,
                        "updated_at": now,
                    },
                    "$setOnInsert": {
                        "created_at": now,
                    },
                },
                upsert=True,
            )
        )

    if dependency_operations:
        DEPENDENCIES.bulk_write(
            dependency_operations,
            ordered=False,
        )

    saved_dependencies = list(DEPENDENCIES.find({"analysis_id": analysis_id}))

    for dependency in saved_dependencies:
        dependency["_id"] = str(dependency["_id"])

    return saved_dependencies


def get_dependency(dependency_id: str) -> dict | None:
    try:
        dependency = DEPENDENCIES.find_one({"_id": ObjectId(dependency_id)})
    except InvalidId, TypeError:
        return None

    if dependency is None:
        return None

    dependency["_id"] = str(dependency["_id"])
    return dependency


# -------------------------------------------------------------------
# REPOSITORY METADATA
# -------------------------------------------------------------------


def save_repository_metadata(
    owner: str,
    repository: str,
    contributors: list[dict],
) -> None:
    now = datetime.now(UTC)

    REPOSITORY_METADATA.update_one(
        {
            "owner": owner,
            "repository": repository,
        },
        {
            "$set": {
                "contributors": contributors,
                "repository_url": (f"https://github.com/{owner}/{repository}"),
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


def get_repository_metadata(
    owner: str,
    repository: str,
) -> dict | None:
    metadata = REPOSITORY_METADATA.find_one(
        {
            "owner": owner,
            "repository": repository,
        }
    )

    if metadata is None:
        return None

    metadata["_id"] = str(metadata["_id"])
    return metadata


# -------------------------------------------------------------------
# VULNERABILITIES
# -------------------------------------------------------------------


def save_vulnerabilities(
    analysis_id: str,
    dependency_id: str,
    dependency: dict,
    vulnerabilities: list[dict],
) -> None:
    now = datetime.now(UTC)

    VULNERABILITIES.update_one(
        {
            "analysis_id": analysis_id,
            "dependency_id": dependency_id,
        },
        {
            "$set": {
                "analysis_id": analysis_id,
                "dependency_id": dependency_id,
                "project": dependency["project"],
                "ecosystem": dependency["ecosystem"],
                "package_name": dependency["name"],
                "installed_version": dependency["version"],
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "last_checked": now,
                "updated_at": now,
            },
            "$setOnInsert": {
                "created_at": now,
            },
        },
        upsert=True,
    )


def get_dependency_vulnerabilities(
    dependency_id: str,
) -> dict | None:
    record = VULNERABILITIES.find_one({"dependency_id": dependency_id})

    if record is None:
        return None

    record["_id"] = str(record["_id"])
    return record


def close_database_connection():
    client.close()
