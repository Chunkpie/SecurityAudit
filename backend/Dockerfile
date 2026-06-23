FROM python:3.12-slim

# Prevent Python buffering
ENV PYTHONUNBUFFERED=1

# Shared Playwright browser location
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    gcc \
    unzip \
    libpq-dev \
    chromium \
    chromium-driver \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libatspi2.0-0 \
    fonts-liberation \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements first
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir sslyze

# Install Playwright browsers
RUN mkdir -p /ms-playwright && \
    playwright install chromium

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -O /tmp/nuclei.zip && \
    cd /tmp && \
    unzip -q nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip && \
    nuclei -update-templates -silent || true

# Install FFUF
RUN wget -qO- https://api.github.com/repos/ffuf/ffuf/releases/latest \
| grep browser_download_url \
| grep linux_amd64 \
| cut -d '"' -f4 \
| xargs wget -O /tmp/ffuf.tar.gz && \
tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin && \
chmod +x /usr/local/bin/ffuf && \
rm /tmp/ffuf.tar.gz

# Copy source code
COPY . .

# Create directories
RUN mkdir -p \
    /app/reports \
    /app/uploads \
    /app/screenshots \
    /app/wordlists

# Default wordlist
RUN echo -e "admin\nlogin\nbackup\napi\nphpinfo.php\n.env\n.git\nwp-admin\ntest\ndebug\nconsole\nswagger\ngraphql\nactuator\nmetrics\nhealth" \
> /app/wordlists/common.txt

# Create non-root user
RUN useradd -m -u 1000 secaudit && \
    chown -R secaudit:secaudit /app && \
    chown -R secaudit:secaudit /ms-playwright

USER secaudit

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]