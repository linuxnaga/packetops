# syntax=docker/dockerfile:1.7
# One image for the API and the analysis worker (the worker needs tshark; the API needs it for single-frame detail).
FROM python:3.12.10-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# tshark from Debian; answer "no" to non-root capture (we never capture, only read files).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark tini \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 packetops && useradd --system --uid 10001 --gid packetops --home-dir /app --shell /usr/sbin/nologin packetops

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY fixtures ./fixtures
RUN mkdir -p /data/storage /data/work /data/cache && chown -R packetops:packetops /data

ENV PKO_STORAGE_LOCAL_ROOT=/data/storage PKO_WORK_DIR=/data/work PKO_CACHE_DIR=/data/cache
USER packetops
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"
