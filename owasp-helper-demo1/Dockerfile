# Pentest.Systems Assistant - Penetration Testing
# Multi-stage build for optimized container

# ============================================
# Stage 1: Base with security tools
# ============================================
FROM python:3.12-slim AS base

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    # Network tools
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    whois \
    iputils-ping \
    traceroute \
    # Security scanning tools
    nmap \
    nikto \
    dirb \
    gobuster \
    xsser \
    amass \
    # Git for exploitdb
    git \
    # Chromium dependencies for Playwright
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    # Cleanup
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# ============================================
# Stage 2: Python dependencies
# ============================================
FROM base AS python-deps

WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel \
    && pip install .[browser]

# Install Playwright browsers
RUN playwright install chromium \
    && playwright install-deps chromium

# ============================================
# Stage 3: Install additional security tools
# ============================================
FROM python-deps AS security-tools

# Install Go for some security tools
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"
ENV GOPATH="/root/go"

# Install Go-based security tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/OJ/gobuster/v3@latest \
    && go install github.com/owasp-amass/amass/v4/...@master

# Install SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py

# Install SearchSploit (ExploitDB)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && chmod +x /opt/exploitdb/searchsploit \
    && cp /opt/exploitdb/.searchsploit_rc /root/.searchsploit_rc \
    && sed -i 's|/opt/exploitdb|/opt/exploitdb|g' /root/.searchsploit_rc

# Update nuclei templates
RUN nuclei -update-templates -silent || true

# ============================================
# Stage 4: Final production image
# ============================================
FROM security-tools AS production

WORKDIR /app

# Copy application code (includes embedded wordlists)
COPY app ./app
COPY scripts ./scripts

# Create non-root user for security (optional, comment out if tools need root)
# RUN useradd -m -u 1000 agent && chown -R agent:agent /app
# USER agent

# Environment variables with defaults
ENV DEEPSEEK_API_KEY="" \
    DEEPSEEK_API_BASE="https://api.deepseek.com/v1" \
    SEARXNG_BASE_URL="" \
    ENV="production" \
    PROMPT_PATH="app/prompts/owasp_pen_tester.md" \
    HOST="0.0.0.0" \
    PORT="8000"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose the application port
EXPOSE ${PORT}

# Labels for container metadata
LABEL maintainer="Pentest.Systems Assistant" \
      version="0.2.0" \
      description="AI-powered penetration testing assistant" \
      org.opencontainers.image.source="https://github.com/sm0k3net/smolagent-demo"

# Run the application
CMD ["sh", "-c", "uvicorn app.main:app --host ${HOST} --port ${PORT}"]
