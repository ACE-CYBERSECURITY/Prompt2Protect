FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates dnsutils iproute2 iputils-ping \
    openssh-server python3 \
  && rm -rf /var/lib/apt/lists/*

# SSH setup
RUN mkdir -p /var/run/sshd \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && useradd -m victim \
 && echo 'victim:victim' | chpasswd

# Simple entrypoint
RUN printf '%s\n' \
'#!/bin/bash' \
'set -e' \
'ssh-keygen -A' \
'/usr/sbin/sshd' \
'python3 -m http.server 80 --bind 0.0.0.0 >/tmp/http.log 2>&1 &' \
'sleep infinity' \
> /entrypoint.sh && chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
