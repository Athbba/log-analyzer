#!/bin/bash
# One node of a distributed brute force: two guesses at dave's password. The
# lab runs this from five addresses (172.30.0.101-105), so no single source
# gets near the brute-force threshold.
# Expected (all five together): distributed brute force on dave (medium).
source /scenarios/lib.sh

for pass in 'dave2026' 'Dave!2026'; do
  try_password dave "$pass" >/dev/null 2>&1 || true
done
log done
