FROM python:3.15.2-slim-bookworm

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
apt-get install -y --no-install-recommends curl ca-certificates

ADD https://astral.sh/uv/0.13.7/install.sh /uv-installer.sh

RUN sh /uv-installer.sh && rm /uv-installer.sh

ENV PATH="/root/.local/bin:$PATH"

COPY . /app

RUN uv sync --locked

HEALTHCHECK CMD ["curl", "--fail", "http://localhost:8000", "||", "exit 1"

CMD ["uv", "run", "fastapi", "dev", "--host", "0.0.0.0", "vuln_tracker/main.py"]