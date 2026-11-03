FROM python:3.15.2-slim-bookworm

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system --gid 999 nonroot \
 && useradd --system --gid 999 --uid 999 --create-home nonroot

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates

ADD https://astral.sh/uv/0.13.7/install.sh /uv-installer.sh

RUN sh /uv-installer.sh && rm /uv-installer.sh

ENV PATH="/root/.local/bin:$PATH"
ENV UV_NO_DEV=1

COPY . /app

RUN uv sync --locked

ENTRYPOINT []

USER nonroot

CMD ["uv", "run", "fastapi", "dev", "--host", "0.0.0.0", "src/main.py"]