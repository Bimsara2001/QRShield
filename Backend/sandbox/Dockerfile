# This image is a Stage A/B research prototype for harmless URLs.  The
# Playwright project notes that its Docker images alone are not a complete
# security boundary for untrusted websites; runtime hardening follows later.
FROM mcr.microsoft.com/playwright/python:v1.60.0-noble

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN groupadd --gid 10001 qrshield \
    && useradd --uid 10001 --gid qrshield \
        --create-home --home-dir /home/qrshield --shell /usr/sbin/nologin qrshield

COPY --chown=qrshield:qrshield worker.py network_guard.py /app/

ENV HOME=/home/qrshield
USER qrshield

ENTRYPOINT ["python", "/app/worker.py"]
