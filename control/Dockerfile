FROM node:20-bookworm-slim

ENV GEMINI_CLI_NO_UPDATE=1

RUN apt-get update && apt-get install -y \
  curl jq dnsutils iputils-ping netcat-traditional procps \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g @google/gemini-cli@0.5.4

# Create non-root user
RUN useradd -m participant

WORKDIR /home/participant

# Copy files owned by participant (this fixes node_modules permission)
COPY --chown=participant:participant .gemini /home/participant/.gemini
COPY --chown=participant:participant mcp-server /home/participant/mcp-server

USER participant

# Install deps as participant
RUN cd /home/participant/mcp-server && npm ci || npm install

CMD ["gemini"]
