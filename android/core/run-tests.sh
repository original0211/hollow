#!/bin/sh
# Canonical local test runner for the Android core (NP-1114-41).
# The two LOCK suites — core (golden vectors + transcript) and
# pairing (grammar fixtures + encoding scan) — read fixture files
# OUTSIDE the Go package graph, and Go's test cache does not track
# those reads: a fixture-only change can report a cached false green.
# Lock suites therefore ALWAYS run with -count=1 (cache disabled).
# The remaining suites keep normal caching; do not blanket-apply
# -count=1 — it slows every run for no integrity gain there.
set -e
cd "$(dirname "$0")"
echo "== lock suites (-count=1, cache off) =="
go test -count=1 ./core/ ./pairing/
echo "== remaining suites =="
go test ./ ./dns/ ./pump/ ./session/
