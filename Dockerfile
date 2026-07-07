# Python 3.12 (Ubuntu 24.04 "noble" default), matching the pip `playwright==1.60.0`
# pin below exactly, so the bundled Chromium build matches the Python package version.
# 1.60.0 is the latest version actually published to PyPI as of this writing (2026-07) --
# do not bump this ahead of pyproject.toml's pin without checking PyPI first, since a
# mismatch between this image's bundled Chromium and the pip package's expected browser
# revision can cause Playwright to fail at runtime.
FROM mcr.microsoft.com/playwright/python:v1.60.0-noble

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir '.[dev]' \
    && playwright install --with-deps chromium

COPY tests ./tests

ENTRYPOINT ["audit-redactor"]
CMD ["--help"]
