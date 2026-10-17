# The lab's SSH clients: the attackers and the legitimate admins. Each compose
# service runs this image with its own fixed IP on the internal lab network.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*

COPY scenarios/ /scenarios/
RUN chmod 0755 /scenarios/*.sh
ENTRYPOINT ["/bin/bash"]
