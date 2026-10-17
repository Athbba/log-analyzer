#!/bin/bash
# Normal admin work from the office workstation (172.30.0.20). Nothing here is
# an attack, but two things look like one: bob mistypes his password before
# logging in, and dave creates a user and gives her sudo.
# Expected: possible breach (low) for bob's typo; account change (low) for the
# new user and (medium) for the sudo grant; bob joining docker is ignored.
source /scenarios/lib.sh

log "alice logs in with her key and looks around"
with_key alice 'uptime; ls -la ~ >/dev/null'

log "bob mistypes his password, then gets it right"
try_password bob 'lab-bob-pas' || true
sleep 2
try_password bob 'lab-bob-pass' 'id; sleep 2'

log "dave onboards erin: new account, then sudo; adds bob to docker"
with_key dave "echo lab-dave-pass | sudo -S -p '' /usr/sbin/useradd -m -s /bin/bash erin
  sleep 2
  echo lab-dave-pass | sudo -S -p '' /usr/sbin/usermod -aG sudo erin
  sleep 2
  echo lab-dave-pass | sudo -S -p '' /usr/sbin/usermod -aG docker bob
  sleep 1"
log done
