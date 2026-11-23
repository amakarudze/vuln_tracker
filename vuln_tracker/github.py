import asyncio
import re

import httpx

GITHUB_API = "https://api.github.com"
MAX_CONCURRENT_REQUESTS = 10


def get_commit_date(commit: dict) -> str | None:
    """Get the Git author date, falling back to the committer date."""
    commit_data = commit.get("commit", {})

    author = commit_data.get("author") or {}
    committer = commit_data.get("committer") or {}

    return author.get("date") or committer.get("date")


def get_last_page(link_header: str | None) -> int:
    """Extract the last page number from GitHub's Link header."""
    if not link_header:
        return 1

    for link in link_header.split(","):
        if 'rel="last"' in link:
            match = re.search(r"[?&]page=(\d+)", link)
            if match:
                return int(match.group(1))

    return 1


async def get_contributor_commit_dates(
    owner: str,
    repository: str,
    username: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> dict:
    """Retrieve the first and latest commit dates for a contributor."""
    url = f"{GITHUB_API}/repos/{owner}/{repository}/commits"

    try:
        response = await client.get(
            url,
            params={
                "author": username,
                "per_page": 1,
                "page": 1,
            },
            headers=headers,
        )
        response.raise_for_status()

        latest_commits = response.json()

        if not latest_commits:
            return {
                "first_contribution_at": None,
                "last_contribution_at": None,
            }

        last_page = get_last_page(response.headers.get("Link"))

        if last_page > 1:
            oldest_response = await client.get(
                url,
                params={
                    "author": username,
                    "per_page": 1,
                    "page": last_page,
                },
                headers=headers,
            )
            oldest_response.raise_for_status()
            oldest_commits = oldest_response.json()
        else:
            oldest_commits = latest_commits

        return {
            "first_contribution_at": (
                get_commit_date(oldest_commits[0]) if oldest_commits else None
            ),
            "last_contribution_at": get_commit_date(latest_commits[0]),
        }

    except (httpx.HTTPError, ValueError) as exc:
        return {
            "first_contribution_at": None,
            "last_contribution_at": None,
            "lookup_error": str(exc),
        }


async def get_contributor_profile(
    username: str,
    client: httpx.AsyncClient,
    headers: dict,
) -> dict:
    """Retrieve a contributor's public GitHub profile information."""
    url = f"{GITHUB_API}/users/{username}"

    try:
        response = await client.get(url, headers=headers)
        response.raise_for_status()

        if response.status_code == 204:
            return []

        profile = response.json()

        return {
            "name": profile.get("name"),
            "account_created_at": profile.get("created_at"),
            "location": profile.get("location"),
            "bio": profile.get("bio"),
        }

    except (httpx.HTTPError, ValueError) as exc:
        return {
            "profile_lookup_error": str(exc),
        }


async def get_github_contributors(
    owner: str,
    repository: str,
    client: httpx.AsyncClient,
    token: str | None = None,
) -> list[dict]:
    """Retrieve repository contributors and their contribution dates."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    contributors_url = f"{GITHUB_API}/repos/{owner}/{repository}/contributors"

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    contributors = []

    try:
        page = 1

        while True:
            async with semaphore:
                response = await client.get(
                    contributors_url,
                    params={
                        "per_page": 100,
                        "page": page,
                    },
                    headers=headers,
                )
                response.raise_for_status()

            page_contributors = response.json()

            if not page_contributors:
                break

            contributors.extend(page_contributors)

            if not response.links.get("next"):
                break

            page += 1

    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(
            f"Could not retrieve contributors for {owner}/{repository}: {exc}"
        ) from exc

    async def enrich_contributor(contributor: dict) -> dict | None:
        username = contributor.get("login")

        # Anonymous contributors do not have a GitHub profile.
        if not username:
            return None

        async with semaphore:
            profile, commit_dates = await asyncio.gather(
                get_contributor_profile(
                    username,
                    client,
                    headers,
                ),
                get_contributor_commit_dates(
                    owner,
                    repository,
                    username,
                    client,
                    headers,
                ),
            )

        return {
            "username": username,
            "name": profile.get("name"),
            "profile_url": contributor.get("html_url"),
            "avatar_url": contributor.get("avatar_url"),
            "contributions": contributor.get("contributions", 0),
            "account_created_at": profile.get("account_created_at"),
            "first_contribution_at": (commit_dates.get("first_contribution_at")),
            "last_contribution_at": (commit_dates.get("last_contribution_at")),
            "profile_lookup_error": profile.get("profile_lookup_error"),
            "commit_lookup_error": commit_dates.get("lookup_error"),
        }

    results = await asyncio.gather(
        *[enrich_contributor(contributor) for contributor in contributors]
    )

    return [contributor for contributor in results if contributor is not None]
