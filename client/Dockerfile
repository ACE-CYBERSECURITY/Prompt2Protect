FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates dnsutils iproute2 iputils-ping \
  && rm -rf /var/lib/apt/lists/*

CMD ["bash", "-lc", "sleep infinity"]
