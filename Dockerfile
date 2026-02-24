# ---- Stage 1a: Build Python packages that need compilation ----
FROM python:3.13 AS builder

RUN pip install --no-cache-dir --target=/build/pip sslyze "cryptography>=46.0.5"

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && git clone --depth 1 https://github.com/sullo/nikto.git /build/nikto \
    && rm -rf /build/nikto/.git

# ---- Stage 1b: Static nmap ----
FROM debian:bookworm-slim AS nmap-builder
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# ---- Stage 2: Runtime image ----
FROM python:3.13-slim

# Runtime-only system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9-dnsutils \
    curl \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# nmap binary + data from builder
COPY --from=nmap-builder /usr/bin/nmap /usr/bin/nmap
COPY --from=nmap-builder /usr/share/nmap /usr/share/nmap

# Pre-built Python packages from builder (sslyze, cryptography, nassl, etc.)
COPY --from=builder /build/pip /usr/local/lib/python3.13/site-packages/
# sslyze CLI entry point
COPY --from=builder /build/pip/bin/sslyze /usr/local/bin/sslyze

# nikto from builder
COPY --from=builder /build/nikto/program /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/nikto.pl

RUN groupadd -r opendast && useradd -r -g opendast -d /app -s /sbin/nologin opendast

WORKDIR /app

COPY pyproject.toml .
COPY opendast/ opendast/
COPY main.py .
RUN pip install --no-cache-dir .
COPY playbooks/ playbooks/

USER opendast

ENV PYTHONUNBUFFERED=1

# Env vars: ANTHROPIC_API_KEY, ANTHROPIC_MODEL, OPENDAST_PLAYBOOK (inline playbook content)
ENTRYPOINT ["python", "main.py"]
