FROM node:20-bookworm-slim

ENV GEMINI_CLI_NO_UPDATE=1
ENV GEMINI_CLI_NO_SHELL=1

RUN apt-get update && apt-get install -y \
  curl jq dnsutils iputils-ping netcat-traditional procps \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @google/gemini-cli@0.5.4

RUN printf '#!/bin/sh\nexec /usr/bin/gemini --no-shell "$@"\n' > /usr/local/bin/gemini \
 && chmod +x /usr/local/bin/gemini

RUN useradd -m participant
USER participant
WORKDIR /home/participant

COPY .gemini /home/participant/.gemini
COPY mcp-server /home/participant/mcp-server
RUN cd mcp-server && npm install

CMD ["bash"]
