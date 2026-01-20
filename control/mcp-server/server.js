import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const FIREWALL_URL = process.env.FIREWALL_URL || "http://firewall:8080";

async function httpPost(path) {
  const res = await fetch(`${FIREWALL_URL}${path}`, { method: "POST" });
  const body = await res.text();
  return { ok: res.ok, status: res.status, body };
}

async function httpGet(path) {
  const res = await fetch(`${FIREWALL_URL}${path}`);
  const body = await res.text();
  return { ok: res.ok, status: res.status, body };
}

const server = new McpServer({ name: "workshop-firewall", version: "1.0.0" });

server.registerTool(
  "firewall_status",
  {
    title: "Firewall status",
    description: "Show current iptables rules (iptables -S).",
    inputSchema: z.object({})
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await httpGet("/status"), null, 2) }]
  })
);

server.registerTool(
  "firewall_lockdown",
  {
    title: "Lock down egress",
    description: "Default-deny OUTPUT (client loses internet until allow rules are added).",
    inputSchema: z.object({})
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await httpPost("/lockdown"), null, 2) }]
  })
);

server.registerTool(
  "firewall_allow_dns",
  {
    title: "Allow DNS",
    description: "Allow outbound DNS (udp/tcp 53).",
    inputSchema: z.object({})
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await httpPost("/allow_dns"), null, 2) }]
  })
);

server.registerTool(
  "firewall_allow_https",
  {
    title: "Allow HTTPS",
    description: "Allow outbound HTTPS (tcp 443).",
    inputSchema: z.object({})
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await httpPost("/allow_https"), null, 2) }]
  })
);

server.registerTool(
  "firewall_reset",
  {
    title: "Reset firewall",
    description: "Flush rules and allow all outbound traffic.",
    inputSchema: z.object({})
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(await httpPost("/reset"), null, 2) }]
  })
);

await server.connect(new StdioServerTransport());
