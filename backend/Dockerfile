FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies: git, curl, Node.js/npm, WeasyPrint apt libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    nodejs \
    npm \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
  && rm -rf /var/lib/apt/lists/*

# TruffleHog binary
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin v3.93.6

# PWN Mon Site tools: nmap + nuclei
RUN apt-get update && apt-get install -y --no-install-recommends nmap unzip && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    -o /tmp/nuclei.zip && unzip /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip
RUN nuclei -update-templates

# Node-based scanners
RUN npm install -g eslint eslint-plugin-security

# Poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false

COPY pyproject.toml ./
RUN poetry install --no-interaction --no-ansi --no-root

COPY . .

# Smoke test — all 5 analyzer binaries must respond
RUN semgrep --version && bandit --version && trufflehog --version && eslint --version && npm --version

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
