import os
from datetime import UTC, datetime

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, MongoClient, UpdateOne

client = MongoClient(os.getenv("MONGODB_URL"))
db = client["vuln_tracker"]

DEPENDENCIES = db["dependencies"]
PACKAGE_METADATA = db["package_metadata"]


def create_indexes():
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


def save_analysis(
    analysis_id: str,
    dependencies: list[dict],
    package_metadata: list[dict],
) -> list[dict]:
    now = datetime.now(UTC)

    # Save or update package metadata.
    metadata_operations = []

    for metadata in package_metadata:
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
        dependency_record = {
            **dependency,
            "analysis_id": analysis_id,
            "package_path": dependency.get("package_path"),
            "package_key": dependency.get(
                "package_key",
                f"{dependency['ecosystem']}:{dependency['name']}",
            ),
            "created_at": now,
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
                {"$set": dependency_record},
                upsert=True,
            )
        )

    if dependency_operations:
        DEPENDENCIES.bulk_write(
            dependency_operations,
            ordered=False,
        )

    # Retrieve the records that were actually saved.
    saved_dependencies = list(DEPENDENCIES.find({"analysis_id": analysis_id}))

    # ObjectId is not JSON serializable, so convert it to a string.
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


def close_database_connection():
    client.close()
