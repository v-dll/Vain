FROM python:3.12-slim

# Nmap is the only system dependency. Raw-socket scans need root, so the
# container runs as root (see README).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY vain ./vain
RUN pip install --no-cache-dir .

# Cache and scan history live in /data (mount a volume there); your own files
# (policies, reports, exports) live in /work (mount your current folder there).
ENV VAIN_HOME=/data
RUN mkdir -p /data /work
VOLUME ["/data"]
WORKDIR /work

ENTRYPOINT ["vain"]
CMD ["--help"]
