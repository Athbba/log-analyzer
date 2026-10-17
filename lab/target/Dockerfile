# The lab's SSH server: OpenSSH 10 logging through rsyslog to
# /var/log/auth.log, as on a stock Debian 13 host. Lab-only users and
# passwords; never expose this container outside the lab network.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client rsyslog sudo passwd \
 && rm -rf /var/lib/apt/lists/* \
 # No kernel log inside a container; imklog would only print errors.
 && sed -i 's/^module(load="imklog"/# &/' /etc/rsyslog.conf

COPY sshd-lab.conf /etc/ssh/sshd_config.d/lab.conf
COPY setup-users.sh entrypoint.sh /usr/local/sbin/
RUN chmod 0755 /usr/local/sbin/setup-users.sh /usr/local/sbin/entrypoint.sh \
 && /usr/local/sbin/setup-users.sh

EXPOSE 22
HEALTHCHECK --interval=1s --timeout=2s --retries=30 CMD test -S /dev/log && test -s /run/sshd.pid
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
