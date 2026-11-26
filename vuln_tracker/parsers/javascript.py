import json
from collections import defaultdict


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
