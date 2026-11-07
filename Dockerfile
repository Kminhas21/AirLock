# syntax=docker/dockerfile:1.7
#
# SENTINEL: one image that serves the backend (approval hub, monitors, policy, event log, identity) AND the built Inbox UI on one port, and can also
# run the MCP proxy (`docker run ... sentinel proxy --config ...`).  Multi-stage and TEST-GATED: the final image cannot be built unless the UI and backend
# test stages passed (TEST_LEVEL=fast|full; none skips them for quick local builds).
#
#   docker build -t sentinel .                                   # CPU PyTorch (default index), tests: fast
#   docker build --build-arg TEST_LEVEL=full -t sentinel .       # whole tests/server + tests/contract suites
#   docker build --target backend-test .                         # run ONLY the backend tests (stops there)
#   docker build --target ui-test .                              # run ONLY tsc + eslint + vitest
#   docker build --target demo -t sentinel:demo .                # runtime + a fake agent/downstream for `docker compose --profile demo`
#
# Build behind a TLS-intercepting proxy / corporate CA:  --build-arg HTTPS_PROXY=... --secret id=buildca,src=/path/ca-bundle.crt
# Reuse a model cache instead of downloading:             --build-context hfseed=$HOME/.cache/huggingface/hub
# No access to download.pytorch.org (uses PyPI's much larger CUDA build):  --build-arg TORCH_INDEX_URL=

ARG PYTHON_IMAGE=python:3.13-slim
ARG NODE_IMAGE=node:22-slim
ARG TEST_LEVEL=fast
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu

# --------------------------------------------------------------------------------------------------------------------------------- Python dependencies
FROM ${PYTHON_IMAGE} AS py-deps
ARG TORCH_INDEX_URL
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
COPY server/requirements.txt server/requirements.txt
COPY seismograph/requirements.txt seismograph/requirements.txt
COPY requirements-proxy.txt requirements-proxy.txt
RUN --mount=type=secret,id=buildca,required=false \
    if [ -f /run/secrets/buildca ]; then export PIP_CERT=/run/secrets/buildca SSL_CERT_FILE=/run/secrets/buildca REQUESTS_CA_BUNDLE=/run/secrets/buildca; fi; \
    if [ -n "$TORCH_INDEX_URL" ]; then pip install torch --index-url "$TORCH_INDEX_URL"; fi; \
    pip install -r server/requirements.txt -r seismograph/requirements.txt -r requirements-proxy.txt

# --------------------------------------------------------------------------------------------------------------------------------- the embedding model
FROM scratch AS hfseed
# (empty by default; `--build-context hfseed=<dir containing models--sentence-transformers--all-MiniLM-L6-v2>` seeds it)
FROM py-deps AS model
ENV HF_HOME=/opt/hf
COPY --from=hfseed / /opt/hf-seed/
COPY scripts/docker/prefetch_model.py /tmp/prefetch_model.py
RUN --mount=type=secret,id=buildca,required=false \
    if [ -f /run/secrets/buildca ]; then export SSL_CERT_FILE=/run/secrets/buildca REQUESTS_CA_BUNDLE=/run/secrets/buildca CURL_CA_BUNDLE=/run/secrets/buildca; fi; \
    python /tmp/prefetch_model.py /opt/hf-seed && rm -rf /opt/hf-seed /tmp/prefetch_model.py

# --------------------------------------------------------------------------------------------------------------------------------- backend tests (gate)
FROM py-deps AS backend-test
ARG TEST_LEVEL
COPY requirements-dev.txt requirements-dev.txt
RUN --mount=type=secret,id=buildca,required=false \
    if [ -f /run/secrets/buildca ]; then export PIP_CERT=/run/secrets/buildca; fi; \
    pip install -r requirements-dev.txt
WORKDIR /app
COPY pytest.ini ./
COPY server server
COPY seismograph seismograph
COPY eval eval
COPY sentinel_proxy sentinel_proxy
COPY demo demo
COPY tests tests
COPY frontend/src frontend/src
COPY docs/examples docs/examples
COPY scripts/docker/backend_tests.sh /usr/local/bin/backend_tests.sh
RUN sh /usr/local/bin/backend_tests.sh "$TEST_LEVEL" && mkdir -p /gate && echo "backend tests ($TEST_LEVEL) passed" > /gate/backend

# --------------------------------------------------------------------------------------------------------------------------------- UI: deps, tests (gate), build
FROM ${NODE_IMAGE} AS ui-deps
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=secret,id=buildca,required=false \
    if [ -f /run/secrets/buildca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/buildca; fi; \
    npm ci --no-audit --no-fund

FROM ui-deps AS ui-test
ARG TEST_LEVEL
COPY frontend/ ./
# types (tsc -b), lint, unit + component tests; `none` skips them like it skips the backend tests
RUN if [ "$TEST_LEVEL" = "none" ]; then echo "UI tests: SKIPPED (TEST_LEVEL=none)"; else npx tsc -b && npm run lint --silent && npm test --silent; fi \
    && mkdir -p /gate && echo "ui tests ($TEST_LEVEL) passed" > /gate/ui

FROM ui-deps AS ui-build
COPY frontend/ ./
# the UI derives its websocket URLs from the page it was loaded from (same origin as the backend that serves it): nothing host-specific is baked in
RUN npm run build --silent && test -f dist/index.html

FROM scratch AS gate
COPY --from=backend-test /gate/backend /gate/backend
COPY --from=ui-test /gate/ui /gate/ui

# --------------------------------------------------------------------------------------------------------------------------------- runtime
FROM py-deps AS runtime
ENV HF_HOME=/opt/hf HF_HUB_OFFLINE=1 OMP_NUM_THREADS=1 TOKENIZERS_PARALLELISM=false \
    SENTINEL_UI_DIR=/app/ui SENTINEL_EMBEDDER=minilm SENTINEL_MONITOR=action_sim SENTINEL_PORT=8080 \
    PYTHONPATH=/app
RUN useradd --system --uid 10001 --user-group --home-dir /home/sentinel --create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /var/lib/sentinel /etc/sentinel && chown sentinel:sentinel /var/lib/sentinel && chmod 700 /var/lib/sentinel
COPY --from=model /opt/hf /opt/hf
WORKDIR /app
COPY server server
COPY seismograph seismograph
COPY eval eval
COPY sentinel_proxy sentinel_proxy
COPY demo demo
COPY --from=ui-build /ui/dist /app/ui
COPY docker/entrypoint.sh /usr/local/bin/sentinel-entrypoint
COPY scripts/docker/bootstrap_identity.py /opt/sentinel/bootstrap_identity.py
RUN chmod 755 /usr/local/bin/sentinel-entrypoint && rm -rf /build
# The image cannot be produced unless BOTH test stages passed: a bind mount of the gate stage forces it to build and leaves nothing in the image.
RUN --mount=type=bind,from=gate,source=/gate,target=/mnt/gate test -f /mnt/gate/backend && test -f /mnt/gate/ui
USER sentinel
VOLUME ["/var/lib/sentinel"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('SENTINEL_PORT', '8080'), timeout=4)"]
ENTRYPOINT ["sentinel-entrypoint"]
CMD ["serve"]

# --------------------------------------------------------------------------------------------------------------------------------- demo (fake agent + fake downstream)
FROM runtime AS demo
USER root
COPY tests/proxy/fake_downstream.py tests/proxy/agent_cli.py /app/demo_agent/
COPY docker/demo/proxy.json /etc/sentinel/demo-proxy.json
USER sentinel

# the default build target is the LAST stage; make it the runtime image
FROM runtime AS final
