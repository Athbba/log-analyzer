#!/bin/bash
# Password guessing from 172.30.0.66: a short dictionary attack against root
# and common service-account names, four connections at a time. It never gets
# in. Expected: brute force (medium).
source /scenarios/lib.sh

readonly GUESSES=(
  'root 123456' 'admin admin' 'root password' 'test test' 'root root' 'oracle oracle'
  'ubuntu ubuntu' 'root toor' 'postgres postgres' 'guest guest' 'root qwerty' 'pi raspberry'
  'admin 12345' 'git git' 'root letmein' 'ftpuser ftpuser' 'root changeme' 'user user'
  'admin password1' 'root admin123'
)

log "${#GUESSES[@]} guesses"
for i in "${!GUESSES[@]}"; do
  read -r user pass <<<"${GUESSES[$i]}"
  try_password "$user" "$pass" >/dev/null 2>&1 &
  if (( i % 4 == 3 )); then wait; fi
done
wait
log done
