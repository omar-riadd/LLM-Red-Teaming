#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DIR"

echo "Downloading all-MiniLM-L6-v2 ONNX model and tokenizer..."
curl -sSL -o "$DIR/model.onnx" "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx"
curl -sSL -o "$DIR/tokenizer.json" "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json"
echo "Download complete: $DIR/model.onnx ($DIR/tokenizer.json)"
