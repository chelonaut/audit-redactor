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

# Install dependencies (and the Chromium download) against a skeleton
# package first. This is by far the slowest part of the build (torch,
# transformers, Playwright's browser download) and should only re-run when
# pyproject.toml/README.md actually change -- not on every source or test
# edit. `-e` (editable) install links the installed package back to ./src
# rather than copying it, so the real source can be COPY'd in afterward as a
# separate, cheap layer without invalidating this one.
COPY pyproject.toml README.md ./
RUN mkdir -p src/audit_redactor && touch src/audit_redactor/__init__.py \
    && pip install --no-cache-dir -e '.[dev]' \
    && playwright install --with-deps chromium

COPY src ./src
COPY tests ./tests

ENTRYPOINT ["audit-redactor"]
CMD ["--help"]
