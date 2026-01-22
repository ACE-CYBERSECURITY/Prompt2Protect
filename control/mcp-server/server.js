import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const FIREWALL = process.env.FIREWALL_URL;

async function post(path) {
  const r = await fetch(`${FIREWALL}${path}`, { method: "POST" });
  return await r.json();
}

async function get(path) {
  const r = await fetch(`${FIREWALL}${path}`);
  return await r.json();
}

const server = new McpServer({ name: "firewall-mcp", version: "2.0" });

function tool(name, desc, path) {
  server.registerTool(
    name,
    { title: name, description: desc, inputSchema: z.object({}) },
    async () => ({
      content: [{ type: "text", text: JSON.stringify(await post(path), null, 2) }]
    })
  );
}

server.registerTool("firewall_status", {
  title: "Firewall status",
  description: "Show iptables rules. MCP-only control.",
  inputSchema: z.object({})
}, async () => ({
  content: [{ type: "text", text: JSON.stringify(await get("/status"), null, 2) }]
}));

tool("lockdown_output", "Default deny outbound traffic", "/output/lockdown");
tool("allow_all_output", "Allow all outbound traffic", "/output/allow_all");
tool("allow_dns", "Allow DNS egress", "/output/allow_dns");
tool("allow_https", "Allow HTTPS egress", "/output/allow_https");
tool("block_output_icmp", "Block outbound ICMP", "/output/block_icmp");

tool("block_ssh", "Block inbound SSH", "/input/block_ssh");
tool("block_input_icmp", "Block inbound ICMP", "/input/block_icmp");

await server.connect(new StdioServerTransport());
