FROM python:3.12-slim

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    gcc \
    libpq-dev \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -O /tmp/nuclei.zip \
    && cd /tmp && unzip -q nuclei.zip \
    && mv nuclei /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates -silent || true

# Install FFUF
RUN wget -qO- https://api.github.com/repos/ffuf/ffuf/releases/latest \
| grep browser_download_url \
| grep linux_amd64 \
| cut -d '"' -f4 \
| xargs wget -O /tmp/ffuf.tar.gz \
&& tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin \
&& chmod +x /usr/local/bin/ffuf \
&& rm /tmp/ffuf.tar.gz

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium --with-deps || true

# Install SSLyze
RUN pip install --no-cache-dir sslyze

COPY . .

# Create directories
RUN mkdir -p /app/reports /app/uploads /app/screenshots /app/wordlists

# Basic wordlist for directory scanning
RUN echo -e "admin\nlogin\nbackup\napi\nphpinfo.php\n.env\n.git\nwp-admin\ntest\ndebug\nconsole\nswagger\ngraphql\nactuator\nmetrics\nhealth" > /app/wordlists/common.txt

# Non-root user
RUN useradd -m -u 1000 secaudit && chown -R secaudit:secaudit /app
USER secaudit

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
