#!/usr/bin/env bash
# Builds the sample plugin JARs from their (dependency-free) sources.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_one() {
  local name="$1" out="$2"
  local src="$DIR/$name"
  local work
  work="$(mktemp -d)"
  mkdir -p "$work/classes"
  find "$src/src" -name '*.java' > "$work/sources.txt"
  javac -d "$work/classes" @"$work/sources.txt"
  cp "$src/plugin.yml" "$work/classes/plugin.yml"
  ( cd "$work/classes" && jar --create --file "$DIR/$out" . )
  rm -rf "$work"
  echo "built $out"
}

build_one benign-plugin BenignChat-1.2.0.jar
build_one malicious-plugin FreeRanks-2.3.jar
