import base64
from collections import deque
from pathlib import PurePosixPath
from urllib.parse import quote

import httpx

DEPENDENCY_FILES = {
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "package-lock.json",
}


async def get_dependency_file_paths(
    owner: str,
    repository: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> list[dict]:
    """Find supported dependency files anywhere in a repository."""

    repo_url = f"https://api.github.com/repos/{owner}/{repository}"

    response = await client.get(repo_url, headers=headers)
    response.raise_for_status()

    default_branch = response.json()["default_branch"]

    tree_url = (
        f"https://api.github.com/repos/{owner}/{repository}"
        f"/git/trees/{quote(default_branch, safe='')}"
    )

    response = await client.get(
        tree_url,
        params={"recursive": "1"},
        headers=headers,
    )
    response.raise_for_status()

    tree_data = response.json()

    if tree_data.get("truncated"):
        # Fall back to fetching each directory tree separately.
        return await get_dependency_files_without_recursion(
            owner,
            repository,
            tree_data["sha"],
            client,
            headers,
        )

    return [
        {
            "path": item["path"],
            "sha": item["sha"],
        }
        for item in tree_data.get("tree", [])
        if (
            item.get("type") == "blob"
            and PurePosixPath(item["path"]).name in DEPENDENCY_FILES
        )
    ]


async def get_dependency_files_without_recursion(
    owner: str,
    repository: str,
    root_tree_sha: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> list[dict]:
    """Traverse directory trees individually if recursive results truncate."""

    queue = deque([root_tree_sha])
    dependency_files = []

    while queue:
        tree_sha = queue.popleft()

        tree_url = (
            f"https://api.github.com/repos/{owner}/{repository}/git/trees/{tree_sha}"
        )

        response = await client.get(tree_url, headers=headers)
        response.raise_for_status()

        for item in response.json().get("tree", []):
            if item["type"] == "tree":
                queue.append(item["sha"])

            elif (
                item["type"] == "blob"
                and PurePosixPath(item["path"]).name in DEPENDENCY_FILES
            ):
                dependency_files.append(
                    {
                        "path": item["path"],
                        "sha": item["sha"],
                    }
                )

    return dependency_files


async def get_dependency_file_content(
    owner: str,
    repository: str,
    file_path: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> str:
    """Retrieve a dependency file's content from GitHub."""

    encoded_path = quote(file_path, safe="/")

    url = f"https://api.github.com/repos/{owner}/{repository}/contents/{encoded_path}"

    response = await client.get(url, headers=headers)
    response.raise_for_status()

    file_data = response.json()

    if file_data.get("encoding") != "base64":
        raise ValueError(f"Unsupported encoding for dependency file: {file_path}")

    return base64.b64decode(file_data["content"]).decode("utf-8")
