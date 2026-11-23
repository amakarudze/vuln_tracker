import asyncio

import httpx
from osv import get_vulnerabilities


async def main():
    async with httpx.AsyncClient(timeout=30.0) as client:
        vulnerabilities = await get_vulnerabilities(
            name="jinja2",
            version="2.4.1",
            ecosystem="pypi",
            client=client,
        )

        print(f"Found {len(vulnerabilities)} vulnerabilities")

        for vulnerability in vulnerabilities:
            print(
                vulnerability["id"],
                vulnerability.get("summary"),
            )


asyncio.run(main())
