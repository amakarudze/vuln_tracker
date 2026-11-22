import json
import re
import tomllib
from collections import defaultdict

from packaging.requirements import Requirement

from vuln_tracker.database import db

COLLECTION = db["dependencies"]


def get_username_and_repo(repoUrl: str):
    match = re.search(r"github\.com/([^/]+)/([^/]+)/?$", repoUrl)

    if match:
        username = match.group(1)
        repo = match.group(2)
        return username, repo


def parse_requirements(requirements_content: str, repo: str) -> list[dict]:
    requirements = []
    current_requirement = None

    for line in requirements_content.splitlines():
        line = line.strip()

        if not line:
            continue

        if not line.startswith("#"):
            requirement = Requirement(line)

            version = None
            match = re.search(r"==\s*([^,\s;]+)", line)

            if match:
                version = match.group(1)

            current_requirement = {
                "project": repo,
                "name": requirement.name,
                "version": version,
                "extras": sorted(requirement.extras),
                "required_by": [],
                "source_file": "requirements.txt",
            }

            requirements.append(current_requirement)

        elif line.startswith("# via"):
            dependency = line.removeprefix("# via").strip()

            if dependency and current_requirement:
                current_requirement["required_by"].append(dependency)

        elif line.startswith("#") and current_requirement:
            dependency = line.removeprefix("#").strip()

            if dependency:
                current_requirement["required_by"].append(dependency)

    return requirements


def parse_uv_lock(lock_content: str, repo: str) -> list[dict]:
    lock_data = tomllib.loads(lock_content)
    requirements = lock_data.get("package", [])

    # Map each dependency to the requirements that require it.
    required_by = defaultdict(set)

    for package in requirements:
        parent_name = package["name"]

        for dependency in package.get("dependencies", []):
            dependency_name = dependency["name"]
            required_by[dependency_name].add(parent_name)

    results = []

    for package in requirements:
        package_name = package["name"]

        results.append(
            {
                "project": repo,
                "name": package_name,
                "version": package["version"],
                "extras": package.get("extra", []),
                "required_by": sorted(required_by[package_name]),
                "source_file": "uv.lock",
            }
        )

    return results


def parse_package_lock(lock_content: str, repo: str) -> list[dict]:
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

    dependency_types = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )

    for parent_path, parent_data in packages.items():
        parent_name = (
            package_names.get(parent_path) if parent_path else lock_data.get("name")
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
                        if parent_name:
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

        results.append(
            {
                "project": repo,
                "name": package_names[package_path],
                "version": package_data.get("version"),
                "extras": [],
                "required_by": sorted(required_by[package_path]),
                "source_file": "package-lock.json",
                "package_path": package_path,
            }
        )

    return results


def parse_poetry_lock(content: str, repo: str) -> list[dict]:
    lock_data = tomllib.loads(content)

    requirements = lock_data.get("package", [])

    required_by = defaultdict(set)
    requested_extras = defaultdict(set)

    for package in requirements:
        package_name = package["name"]

        for dependency_name, dependency in package.get("dependencies", {}).items():
            required_by[dependency_name].add(package_name)

            if isinstance(dependency, dict):
                requested_extras[dependency_name].update(dependency.get("extras", []))
    results = []
    for package in requirements:
        results.append(
            {
                "project": repo,
                "name": package["name"],
                "version": package["version"],
                "extras": sorted(requested_extras[package["name"]]),
                "required_by": sorted(required_by[package["name"]]),
                "source_file": "poetry.lock",
            }
        )

    return results
