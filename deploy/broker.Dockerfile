# The DARM broker in its own container: darm-guard installed from this repository, the pinned
# kernel downloaded and verified at build time, the governed workspace (which exists only here),
# and the principal's API token, outside the workspace. The api service runs the same image.
FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/Goblohan/Darm-Guard" \
      org.opencontainers.image.description="DARM Guard: the broker, the pinned kernel, and darm-guard demo" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN useradd --create-home --uid 1000 darm && mkdir -p /sock /data /certs && chown darm:darm /sock /data /certs
USER darm
ENV PATH=/home/darm/.local/bin:$PATH
COPY --chown=darm:darm . /home/darm/src
RUN pip install --user --no-cache-dir /home/darm/src && darm-guard-install-kernel
COPY --chown=darm:darm deploy/fixture/ /data/
RUN mkdir -p /data/workspace/reports /data/secrets && echo "hello from notes" > /data/workspace/notes.txt \
 && echo "Bearer deployment-demo-token" > /data/secrets/api-token && chmod 600 /data/secrets/api-token /data/intents.txt
HEALTHCHECK --interval=1s --timeout=2s --retries=90 CMD test -S /sock/broker.sock
CMD ["darm-broker", "--config", "/data/config.json", "--registry", "/data/registry.txt", \
     "--socket", "/sock/broker.sock", "--audit", "/data/audit.jsonl", "--intents", "/data/intents.txt"]
