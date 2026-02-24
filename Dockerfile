FROM python:3.11-slim

# Install system security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    dirb \
    dnsutils \
    curl \
    ruby \
    && rm -rf /var/lib/apt/lists/*

# Install Python/Ruby-based security tools
RUN pip install --no-cache-dir sslyze \
    && gem install whatweb --no-document

RUN groupadd -r dast && useradd -r -g dast -d /app -s /sbin/nologin dast

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY open_dast/ open_dast/
COPY main.py .
COPY playbooks/ playbooks/

USER dast

ENTRYPOINT ["python", "main.py"]
