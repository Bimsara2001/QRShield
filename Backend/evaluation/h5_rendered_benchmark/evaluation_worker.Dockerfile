# Evaluation-only trust overlay. The base worker, /app/worker.py, Playwright
# version, entry point, and non-root runtime are unchanged. The only addition
# is the short-lived CA that signs h5fixtures on the isolated Docker network.
FROM qrshield-sandbox-worker:latest
USER root
COPY ca.crt /usr/local/share/ca-certificates/h5-rendered-evaluation-ca.crt
RUN update-ca-certificates
USER qrshield
