FROM node:20-bookworm-slim

RUN npm install -g @google/gemini-cli

RUN mkdir -p /root/.gemini
COPY .gemini/settings.json /root/.gemini/settings.json

WORKDIR /workspace
COPY mcp-server /workspace/mcp-server
RUN cd /workspace/mcp-server && npm install

CMD ["bash", "-lc", "sleep infinity"]
