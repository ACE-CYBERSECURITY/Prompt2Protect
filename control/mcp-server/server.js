import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const FIREWALL = process.env.FIREWALL_URL;
if (!FIREWALL) throw new Error("FIREWALL_URL is not set");

async function postJson(path, body) {
  const r = await fetch(`${FIREWALL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) return { ok: false, status: r.status, ...data };
  return data;
}

async function post(path) {
  return postJson(path, {});
}

async function get(path) {
  const r = await fetch(`${FIREWALL}${path}`);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) return { ok: false, status: r.status, ...data };
  return data;
}

const server = new McpServer({ name: "firewall-mcp", version: "2.0" });

function toolNoInput(name, desc, path, method = "POST") {
  server.registerTool(
    name,
    { title: name, description: desc, inputSchema: z.object({}) },
    async () => ({
      content: [{ type: "text", text: JSON.stringify(method === "POST" ? await post(path) : await get(path), null, 2) }]
    })
  );
}

server.registerTool("firewall_status", {
  title: "Firewall status",
  description: "Show firewall state (iptables + ipset). MCP-only control.",
  inputSchema: z.object({})
}, async () => ({
  content: [{ type: "text", text: JSON.stringify(await get("/status"), null, 2) }]
}));

toolNoInput("firewall_reset", "Reset to baseline (ACCEPT all + clean sets).", "/reset");
toolNoInput("lockdown_output", "Default deny outbound traffic (OUTPUT policy DROP).", "/output/lockdown");
toolNoInput("allow_all_output", "Allow all outbound traffic (OUTPUT policy ACCEPT).", "/output/allow_all");
toolNoInput("allow_dns", "Allow DNS egress (tcp/udp 53).", "/output/allow_dns");
toolNoInput("allow_https", "Allow HTTPS egress (tcp 443).", "/output/allow_https");
toolNoInput("block_output_icmp", "Block outbound ICMP.", "/output/block_icmp");

toolNoInput("block_ssh", "Block inbound SSH (tcp 22).", "/input/block_ssh");
toolNoInput("block_input_icmp", "Block inbound ICMP.", "/input/block_icmp");

// Param tools
server.registerTool("output_allow_port", {
  title: "Allow outbound port",
  description: "Allow outbound traffic to a destination port/protocol.",
  inputSchema: z.object({
    port: z.number().int().min(1).max(65535),
    protocol: z.enum(["tcp", "udp", "icmp"])
  })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/allow_port", args), null, 2) }]
}));

server.registerTool("output_block_port", {
  title: "Block outbound port",
  description: "Block outbound traffic to a destination port/protocol.",
  inputSchema: z.object({
    port: z.number().int().min(1).max(65535),
    protocol: z.enum(["tcp", "udp", "icmp"])
  })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/block_port", args), null, 2) }]
}));

server.registerTool("output_whitelist_ip", {
  title: "Whitelist outbound destination IP",
  description: "Always allow outbound traffic to this destination IP (ipset allowlist).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/whitelist_ip", args), null, 2) }]
}));

server.registerTool("output_blacklist_ip", {
  title: "Blacklist outbound destination IP",
  description: "Always block outbound traffic to this destination IP (ipset blocklist).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/blacklist_ip", args), null, 2) }]
}));

server.registerTool("output_unwhitelist_ip", {
  title: "Remove outbound whitelist IP",
  description: "Remove a destination IP from outbound allowlist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/unwhitelist_ip", args), null, 2) }]
}));

server.registerTool("output_unblacklist_ip", {
  title: "Remove outbound blacklist IP",
  description: "Remove a destination IP from outbound blocklist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/output/unblacklist_ip", args), null, 2) }]
}));

server.registerTool("input_allow_port", {
  title: "Allow inbound port",
  description: "Allow inbound traffic to a local port/protocol.",
  inputSchema: z.object({
    port: z.number().int().min(1).max(65535),
    protocol: z.enum(["tcp", "udp", "icmp"])
  })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/allow_port", args), null, 2) }]
}));

server.registerTool("input_block_port", {
  title: "Block inbound port",
  description: "Block inbound traffic to a local port/protocol.",
  inputSchema: z.object({
    port: z.number().int().min(1).max(65535),
    protocol: z.enum(["tcp", "udp", "icmp"])
  })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/block_port", args), null, 2) }]
}));

server.registerTool("input_whitelist_ip", {
  title: "Whitelist inbound source IP",
  description: "Always allow inbound traffic from this source IP (ipset allowlist).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/whitelist_ip", args), null, 2) }]
}));

server.registerTool("input_blacklist_ip", {
  title: "Blacklist inbound source IP",
  description: "Always block inbound traffic from this source IP (ipset blocklist).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/blacklist_ip", args), null, 2) }]
}));

server.registerTool("input_unwhitelist_ip", {
  title: "Remove inbound whitelist IP",
  description: "Remove a source IP from inbound allowlist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/unwhitelist_ip", args), null, 2) }]
}));

server.registerTool("input_unblacklist_ip", {
  title: "Remove inbound blacklist IP",
  description: "Remove a source IP from inbound blocklist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({
  content: [{ type: "text", text: JSON.stringify(await postJson("/input/unblacklist_ip", args), null, 2) }]
}));

await server.connect(new StdioServerTransport());
