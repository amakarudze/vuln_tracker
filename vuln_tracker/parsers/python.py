import re
import tomllib
from collections import defaultdict

from packaging.requirements import Requirement


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
