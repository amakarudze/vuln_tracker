import json
import os
import re
import tomllib
from collections import defaultdict

from packaging.requirements import Requirement
from pymongo import MongoClient

REPO_NAME = "djangogirls"

client = MongoClient(os.getenv("MONGODB_URL"))

db = client["vulnerability_tracker"]
COLLECTION = db["dependencies"]


def parse_requirements(requirements_content: str) -> list[dict]:
    requirements = []
    current_requirement = None

    for line in requirements_content.splitlines():
        line = line.strip()

        if not line:
            continue

        # Extract package name, version and extras
        if not line.startswith("#"):
            requirement = Requirement(line)

            version = None
            match = re.search(r"==\s*([^,\s;]+)", line)

            if match:
                version = match.group(1)

            current_requirement = {
                "project": REPO_NAME,
                "name": requirement.name,
                "version": version,
                "extras": sorted(requirement.extras),
                "required_by": [],
                "source_file": "requirements.txt",
            }

            requirements.append(current_requirement)

        # Extract dependency information from # via comments
        elif line.startswith("# via"):
            dependency = line.removeprefix("# via").strip()

            if dependency:
                current_requirement["required_by"].append(dependency)

        elif line.startswith("#") and current_requirement:
            dependency = line.removeprefix("#").strip()

            if dependency:
                current_requirement["required_by"].append(dependency)
    if requirements:
        COLLECTION.insert_many(requirements)


def parse_uv_lock(lock_content: str) -> list[dict]:
    lock_data = tomllib.loads(lock_content)
    packages = lock_data.get("package", [])

    # Map each dependency to the packages that require it.
    required_by = defaultdict(set)

    for package in packages:
        parent_name = package["name"]

        for dependency in package.get("dependencies", []):
            dependency_name = dependency["name"]
            required_by[dependency_name].add(parent_name)

    results = []

    for package in packages:
        package_name = package["name"]

        results.append(
            {
                "repository": REPO_NAME,
                "package_name": package_name,
                "version": package["version"],
                "extras": package.get("extra", []),
                "required_by": sorted(required_by[package_name]),
                "source_file": "uv.lock",
            }
        )

    if results:
        COLLECTION.insert_many(results)


def parse_package_lock(lock_content: str, repository: str) -> list[dict]:
    lock_data = json.loads(lock_content)
    packages = lock_data.get("packages", {})

    package_names = {}

    for package_path, package_data in packages.items():
        if not package_path:
            continue

        package_name = package_data.get("name")

        if not package_name:
            package_name = package_path.rsplit("node_modules/", 1)[-1]

        package_names[package_path] = package_name

    required_by = defaultdict(set)

    for parent_path, parent_data in packages.items():
        parent_name = (
            parent_data.get("name") or lock_data.get("name")
            if not parent_path
            else parent_data.get("name")
        )

        dependency_types = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        )

        for dependency_type in dependency_types:
            dependencies = parent_data.get(dependency_type, {})

            for dependency_name in dependencies:
                current_path = parent_path

                while True:
                    candidate = (
                        f"{current_path}/node_modules/{dependency_name}"
                        if current_path
                        else f"node_modules/{dependency_name}"
                    )

                    if candidate in packages:
                        required_by[candidate].add(parent_name)
                        break

                    if not current_path:
                        break

                    parts = current_path.split("/node_modules/")
                    if len(parts) > 1:
                        current_path = "/node_modules/".join(parts[:-1])
                    else:
                        current_path = ""

    results = []

    for package_path, package_data in packages.items():
        # Skip the root project.
        if not package_path:
            continue

        package_name = package_names[package_path]
        results.append(
            {
                "repository": REPO_NAME,
                "package_name": package_name,
                "version": package_data.get("version"),
                "extras": [],
                "required_by": sorted(
                    dependency
                    for dependency in required_by[package_path]
                    if dependency is not None
                ),
                "source_file": "package-lock.json",
            }
        )

    if results:
        COLLECTION.insert_many(results)


def parse_poetry_lock(content: str) -> list[dict]:
    lock_data = tomllib.loads(content)

    packages = lock_data.get("package", [])

    required_by = defaultdict(set)
    requested_extras = defaultdict(set)

    for package in packages:
        package_name = package["name"]

        for dependency_name, dependency in package.get("dependencies", {}).items():
            required_by[dependency_name].add(package_name)

            if isinstance(dependency, dict):
                requested_extras[dependency_name].update(dependency.get("extras", []))
    results = []
    for package in packages:
        results.append(
            {
                "repository": REPO_NAME,
                "package_name": package["name"],
                "version": package["version"],
                "extras": sorted(requested_extras[package["name"]]),
                "required_by": sorted(required_by[package["name"]]),
                "source_file": "poetry.lock",
            }
        )

    if results:
        COLLECTION.insert_many(results)
