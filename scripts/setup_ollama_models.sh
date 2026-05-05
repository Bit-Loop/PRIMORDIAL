#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/home/bitloop/Desktop/PRIMORDIAL"
OLLAMA_MODEL_DIR="${PROJECT_ROOT}/AI_MODELS/ollama"

mkdir -p "${OLLAMA_MODEL_DIR}"
export OLLAMA_MODELS="${OLLAMA_MODEL_DIR}"
export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-4}"
export OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-8h}"

echo "Using OLLAMA_MODELS=${OLLAMA_MODELS}"
echo "Using OLLAMA_MAX_LOADED_MODELS=${OLLAMA_MAX_LOADED_MODELS}"
echo "Using OLLAMA_NUM_PARALLEL=${OLLAMA_NUM_PARALLEL}"
echo "Using OLLAMA_KEEP_ALIVE=${OLLAMA_KEEP_ALIVE}"
echo "Expected total download size: about 77.8GB"

if ! ollama list >/dev/null 2>&1; then
  echo "Ollama server is not responding on 127.0.0.1:11434."
  echo "Start it in another terminal with:"
  echo "  OLLAMA_MODELS=${OLLAMA_MODELS} OLLAMA_MAX_LOADED_MODELS=${OLLAMA_MAX_LOADED_MODELS} OLLAMA_NUM_PARALLEL=${OLLAMA_NUM_PARALLEL} OLLAMA_KEEP_ALIVE=${OLLAMA_KEEP_ALIVE} ollama serve"
  exit 1
fi

ollama pull gemma4:e4b
ollama pull phi4-reasoning
ollama pull qwen3-coder-next:q4_K_M
ollama pull deepseek-r1:8b

echo
echo "Installed models:"
ollama list
