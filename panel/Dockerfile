# Panel WireGuard Multi-Tenant
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# wireguard-tools: `wg syncconf` (altas/bajas de peers en caliente) y `wg show dump` (estado).
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY static ./static

VOLUME ["/data"]
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PANEL_PORT','5000'), timeout=4)"

CMD ["python", "-m", "app.server"]
