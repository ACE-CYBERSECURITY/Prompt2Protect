FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
  iptables ipset iproute2 \
  python3 python3-flask \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY adapter.py /app/adapter.py

EXPOSE 8080
CMD ["python3", "/app/adapter.py"]
