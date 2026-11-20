#!/usr/bin/env bash
# Build the images (the Dockerfile's own test stages gate the build) and run the real-container tests.
#
#   scripts/docker_test.sh                  build sentinel:local + sentinel:demo, then tests/docker (static + container tests)
#   scripts/docker_test.sh --no-build       reuse the images that already exist
#
# Optional environment (all unset on a normal machine):
#   SENTINEL_DOCKER_TEST_LEVEL   fast (default) | full | none          tests run INSIDE the build
#   SENTINEL_DOCKER_TORCH_INDEX  PyTorch wheel index; default = the CPU index. Set to "" to use PyPI's (much larger, CUDA) build
#   SENTINEL_DOCKER_EMBEDDINGS   1 (default) | 0 = build without PyTorch/the model (then the container tests expect the stub fallback, not MiniLM)
#   SENTINEL_DOCKER_NETWORK_HOST=1   build with --network host (needed when the only route out is a proxy on the host's loopback)
#   SENTINEL_DOCKER_FORWARD_PROXY=1  pass HTTPS_PROXY/HTTP_PROXY into the build
#   SENTINEL_DOCKER_BUILD_CA     path of a CA bundle to trust during the build (TLS-intercepting proxies); mounted as a build secret, never stored in a layer
#   SENTINEL_DOCKER_HF_SEED      directory holding a Hugging Face hub cache to seed the model from (otherwise it is downloaded)
set -euo pipefail
cd "$(dirname "$0")/.."

build=1
[ "${1:-}" = "--no-build" ] && build=0

if [ "$build" = 1 ]; then
  args=(--build-arg "TEST_LEVEL=${SENTINEL_DOCKER_TEST_LEVEL:-fast}")
  args+=(--build-arg "EMBEDDINGS=${SENTINEL_DOCKER_EMBEDDINGS:-1}")
  [ "${SENTINEL_DOCKER_TORCH_INDEX+set}" = set ] && args+=(--build-arg "TORCH_INDEX_URL=${SENTINEL_DOCKER_TORCH_INDEX}")
  [ "${SENTINEL_DOCKER_NETWORK_HOST:-}" = 1 ] && args+=(--network host)
  if [ "${SENTINEL_DOCKER_FORWARD_PROXY:-}" = 1 ]; then
    args+=(--build-arg "HTTPS_PROXY=${HTTPS_PROXY:-${https_proxy:-}}" --build-arg "HTTP_PROXY=${HTTP_PROXY:-${http_proxy:-${HTTPS_PROXY:-${https_proxy:-}}}}" --build-arg "NO_PROXY=localhost,127.0.0.1")
  fi
  [ -n "${SENTINEL_DOCKER_BUILD_CA:-}" ] && args+=(--secret "id=buildca,src=${SENTINEL_DOCKER_BUILD_CA}")
  [ -n "${SENTINEL_DOCKER_HF_SEED:-}" ] && args+=(--build-context "hfseed=${SENTINEL_DOCKER_HF_SEED}")
  echo "=== building sentinel:local (tests gate the build: TEST_LEVEL=${SENTINEL_DOCKER_TEST_LEVEL:-fast})"
  docker build "${args[@]}" -t sentinel:local .
  echo "=== building sentinel:demo (shares every layer with sentinel:local)"
  docker build "${args[@]}" --target demo -t sentinel:demo .
fi

echo "=== tests/docker (static checks + real containers)"
SENTINEL_DOCKER_TESTS=1 SENTINEL_TEST_EMBEDDINGS="${SENTINEL_DOCKER_EMBEDDINGS:-1}" python -m pytest -p no:cacheprovider tests/docker -v
