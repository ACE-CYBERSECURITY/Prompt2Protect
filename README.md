
# Prompt2Protect – Docker Images

A 3-container demo where **Gemini CLI** uses an **MCP server** to apply iptables rules inside a firewall container, and a separate **client container** is used to test if internet access is blocked/allowed.

## Docker images -

- **firewall** (`./firewall`)
  - Runs `iptables` + a tiny HTTP API (Flask) on port **8080**
  - Endpoints: `/lockdown`, `/allow_dns`, `/allow_https`, `/reset`, `/status`, `/health`

- **control** (`./control`)
  - Runs **Gemini CLI** + an **MCP server**
  - Gemini CLI discovers MCP tools (via `control/.gemini/settings.json`) and calls them to control the firewall

- **client** (`./client`)
  - A testing container (has `curl`, `dig`, etc.)
  - Shares the firewall container’s network stack so firewall rules actually affect client traffic

    

