# Python 3.12 (Ubuntu 24.04 "noble" default), matching the pip `playwright==1.61.0`
# pin below exactly, so the bundled Chromium build matches the Python package version.
FROM mcr.microsoft.com/playwright/python:v1.61.0-noble

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && playwright install --with-deps chromium

COPY tests ./tests

ENTRYPOINT ["audit-redactor"]
CMD ["--help"]
