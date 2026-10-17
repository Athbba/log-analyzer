#!/bin/sh
# Starts rsyslog, then sshd in the foreground. Login keys for alice and dave
# are generated on first start into the shared /lab-keys volume, where the
# client container picks up the private halves.
set -eu

ssh-keygen -A >/dev/null

for u in alice dave; do
  if [ ! -f "/lab-keys/$u" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "$u@lab" -f "/lab-keys/$u"
  fi
  install -m 0600 -o "$u" -g "$u" "/lab-keys/$u.pub" "/home/$u/.ssh/authorized_keys"
done
chmod 0644 /lab-keys/*

: > /var/log/auth.log
chown root:adm /var/log/auth.log
chmod 0640 /var/log/auth.log

rsyslogd
while [ ! -S /dev/log ]; do sleep 0.1; done

mkdir -p /run/sshd
exec /usr/sbin/sshd -D
