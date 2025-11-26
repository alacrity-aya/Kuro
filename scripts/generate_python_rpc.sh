#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT_DIR="${PROJECT_ROOT}/client"

cd "$CLIENT_DIR"

uv sync

uv run python -m grpc_tools.protoc \
    -I ${PROJECT_ROOT} \
    --python_out=. \
    --grpc_python_out=. \
    ${PROJECT_ROOT}/kuro.proto
