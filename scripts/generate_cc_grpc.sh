#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <proto_file> <output_dir>"
    exit 1
fi

PROTO_FILE="$1"
OUT_DIR="$2"
PROTO_DIR="$(dirname "$PROTO_FILE")"

PROTOC_BIN="/home/alacrity/work/vcpkg/packages/protobuf_x64-linux/tools/protobuf/protoc"
GRPC_PLUGIN="/home/alacrity/work/vcpkg/packages/grpc_x64-linux/tools/grpc/grpc_cpp_plugin"

mkdir -p "$OUT_DIR"

"$PROTOC_BIN" \
    --proto_path="$PROTO_DIR" \
    --cpp_out="$OUT_DIR" \
    --grpc_out="$OUT_DIR" \
    --plugin=protoc-gen-grpc="$GRPC_PLUGIN" \
    "$PROTO_FILE"
