#!/bin/bash
# Shared helpers for the scenarios. Sourcing this file refuses to continue
# unless the target is the lab's own SSH server: the scenarios guess
# passwords, and that must never reach any other host.
set -euo pipefail

readonly TARGET=lab-target
readonly LAB_SUBNET_PREFIX=172.30.0.

target_ip=$(getent hosts "$TARGET" | awk '{ print $1 }' || true)
case "$target_ip" in
  "$LAB_SUBNET_PREFIX"*) ;;
  *) echo "refusing to run: $TARGET resolves to '${target_ip:-nothing}', not the lab network" >&2; exit 64 ;;
esac

readonly SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
  -o ConnectTimeout=5 -o BatchMode=no)

# One password attempt; returns ssh's status (0 means it logged in).
# Usage: try_password USER PASSWORD [REMOTE COMMAND...]
try_password() {
  local user=$1 pass=$2
  shift 2
  sshpass -p "$pass" ssh "${SSH_OPTS[@]}" -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 "$user@$TARGET" "${@:-true}"
}

# A key login as a lab user whose key the target generated in /lab-keys.
# Usage: with_key USER REMOTE COMMAND...
with_key() {
  local user=$1
  shift
  install -m 0600 "/lab-keys/$user" "/tmp/$user.key"
  ssh "${SSH_OPTS[@]}" -o PreferredAuthentications=publickey -i "/tmp/$user.key" "$user@$TARGET" "$@"
}

log() { printf '[%s] %s\n' "$(basename "$0" .sh)" "$*"; }
