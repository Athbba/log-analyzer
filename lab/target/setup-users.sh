#!/bin/sh
# Creates the lab's accounts at image build time. These passwords exist only
# inside this disposable container; they are not secrets.
set -eu

groupadd --system docker

# alice: developer, key login only.
useradd -m -s /bin/bash alice
passwd -l alice

# bob: still on password login, and sometimes mistypes it.
useradd -m -s /bin/bash bob
echo 'bob:lab-bob-pass' | chpasswd

# dave: the admin. Key login; sudo with a password.
useradd -m -s /bin/bash -G sudo dave
echo 'dave:lab-dave-pass' | chpasswd

# deploy: a service account with sudo and a weak password from the
# attacker's word list. This is what the break-in scenario exploits.
useradd -m -s /bin/bash -G sudo deploy
echo 'deploy:Summer2026!' | chpasswd

for u in alice dave; do
  install -d -m 0700 -o "$u" -g "$u" "/home/$u/.ssh"
done
