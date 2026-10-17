#!/bin/bash
# Password spraying from 172.30.0.88: one common password tried once against
# each of ten real accounts (people and system accounts alike), the way a
# spray avoids locking any single account out.
# Expected: password spray (medium). Ten failures in under a minute is also a
# brute force (medium), which is right too.
source /scenarios/lib.sh

readonly ACCOUNTS=(alice bob dave deploy backup www-data mail news proxy list)
log "one guess at each of ${#ACCOUNTS[@]} accounts"
for user in "${ACCOUNTS[@]}"; do
  try_password "$user" 'Autumn2026!' >/dev/null 2>&1 || true
done
log done
