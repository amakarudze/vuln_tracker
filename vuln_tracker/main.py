import base64
import os

import requests
from fastapi import FastAPI

from vuln_tracker.parsers import (
    COLLECTION,
    parse_package_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
)

app = FastAPI()

GITHUB_BASE_URL = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
USER_NAME = os.getenv("GITHUB_USERNAME")


@app.get("/")
def read_root():
    user_name = os.getenv("GITHUB_USERNAME")
    repo_name = "djangogirls"
    repository_url = f"{GITHUB_BASE_URL}/repos/{user_name}/{repo_name}"
    personal_access_token = GITHUB_TOKEN
    file_names = [
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
        "package-lock.json",
    ]
    headers = {"Authorization": f"Bearer {personal_access_token}"}
    project_dependencies = []
    for file_name in file_names:
        file_url = f"{repository_url}/contents/{file_name}"
        response = requests.get(file_url, headers=headers)
        if response.status_code == 200:
            file_data = response.json()
            content = base64.b64decode(file_data["content"]).decode("utf-8")
            if file_name == "requirements.txt":
                dependencies = parse_requirements(content)
                project_dependencies.append(
                    {"file_name": file_name, "dependencies": dependencies}
                )
            elif file_name == "uv.lock":
                dependencies = parse_uv_lock(content)
                project_dependencies.append(
                    {"file_name": file_name, "dependencies": dependencies}
                )
            elif file_name == "poetry.lock":
                dependencies = parse_poetry_lock(content)
                project_dependencies.append(
                    {"file_name": file_name, "dependencies": dependencies}
                )
            elif file_name == "package-lock.json":
                dependencies = parse_package_lock(content, repo_name)
                project_dependencies.append(
                    {"file_name": file_name, "dependencies": dependencies}
                )

        else:
            project_dependencies.append(
                {"file_name": file_name, "status": "File not found."}
            )
    dependencies = list(COLLECTION.find({"repository": "djangogirls"}))
    for dependency in dependencies:
        dependency["_id"] = str(dependency["_id"])
    return {
        "message": "File check completed.",
        "dependencies": dependencies,
    }


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}
