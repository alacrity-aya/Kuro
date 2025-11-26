#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CPP_GEN_DIR="${PROJECT_ROOT}/build/release
PY_GEN_DIR="${PROJECT_ROOT}/client"

echo "Cleaning C++ generated files in ${CPP_GEN_DIR}..."
if [ -d "$CPP_GEN_DIR" ]; then
    rm -f "$CPP_GEN_DIR"/*.pb.cc "$CPP_GEN_DIR"/*.pb.h "$CPP_GEN_DIR"/*.grpc.pb.cc "$CPP_GEN_DIR"/*.grpc.pb.h
fi

echo "Cleaning Python generated files in ${PY_GEN_DIR}..."
rm -f "$PY_GEN_DIR"/*_pb2.py "$PY_GEN_DIR"/*_pb2_grpc.py

echo "RPC generated files cleaned."
