#!/usr/bin/env bash
# Quick dependency-free build of the AEGIS desktop edition.
#   ./build.sh            -> embeds assets, compiles ./aegis-desktop (browser launch)
#   ./build.sh --cmake    -> configures a CMake build in ./build (native window)
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--cmake" ]]; then
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release "${@:2}"
  cmake --build build --config Release -j
  echo "Built via CMake. Binary in ./build (run 'cmake --build build --target package' to make an installer)."
  exit 0
fi

echo "[1/2] Embedding web assets…"
python3 tools/embed_assets.py web src/assets_generated.h
echo "[2/2] Compiling…"
g++ -std=c++17 -O2 -Wall -pthread -I third_party -I src src/main.cpp -o aegis-desktop
echo "Done -> ./aegis-desktop   (run it, then your browser opens the suite)"
