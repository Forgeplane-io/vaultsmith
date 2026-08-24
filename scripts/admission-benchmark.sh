#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="${1:-$ROOT_DIR/docs/benchmarks/admission-linux-amd64-2026-08-12.md}"
mkdir -p "$(dirname "$OUT")"

host_cpu="unknown"
host_ram="unknown"
if command -v sysctl >/dev/null 2>&1; then
  host_cpu="$(sysctl -n hw.ncpu 2>/dev/null || printf unknown)"
  host_ram="$(sysctl -n hw.memsize 2>/dev/null || printf unknown)"
fi

docker run --rm \
  --platform linux/amd64 \
  --memory 2g \
  -v "$ROOT_DIR:/workspace" \
  -w /workspace \
  -e BENCH_HOST_CPU="$host_cpu" \
  -e BENCH_HOST_RAM_BYTES="$host_ram" \
  golang:1.27-bookworm \
  go run ./backend/cmd/admissionbench -release -candidates 1,2,4,8,16 -selected 16 -concurrency 32 -duration 5s -profiles 4 \
  | tee "$OUT"
