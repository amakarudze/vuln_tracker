import os

from pymongo import MongoClient, UpdateOne

client = MongoClient(os.getenv("MONGODB_URL"))

db = client["vuln_tracker"]

COLLECTION = db["dependencies"]


def save_dependencies(requirements: list[dict]) -> None:
    required_fields = {"project", "name", "version", "source_file"}

    for index, dependency in enumerate(requirements):
        missing = required_fields - dependency.keys()

        if missing:
            raise ValueError(
                f"Dependency at index {index} is missing "
                f"{sorted(missing)}: {dependency}"
            )

    if not requirements:
        return

    operations = [
        UpdateOne(
            {
                "project": requirement["project"],
                "name": requirement["name"],
                "source_file": requirement["source_file"],
            },
            {"$set": requirement},
            upsert=True,
        )
        for requirement in requirements
    ]

    COLLECTION.bulk_write(operations, ordered=False)
