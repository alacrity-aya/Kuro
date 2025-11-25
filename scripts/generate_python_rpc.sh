#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_DIR="${PROJECT_ROOT}/server"

cd "$SERVER_DIR"

uv sync

uv run python -m grpc_tools.protoc \
    -I ${PROJECT_ROOT} \
    --python_out=. \
    --grpc_python_out=. \
    ${PROJECT_ROOT}/kuro.proto
