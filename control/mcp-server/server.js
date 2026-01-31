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

async function post(path) { return postJson(path, {}); }

async function get(path) {
  const r = await fetch(`${FIREWALL}${path}`);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) return { ok: false, status: r.status, ...data };
  return data;
}

const server = new McpServer({ name: "firewall-mcp", version: "4.0" });

function toolNoInput(name, desc, path, method = "POST") {
  server.registerTool(
    name,
    { title: name, description: desc, inputSchema: z.object({}) },
    async () => ({
      content: [{ type: "text", text: JSON.stringify(method === "POST" ? await post(path) : await get(path), null, 2) }]
    })
  );
}

// ========== FIXED: Dynamic firewall_status ==========
server.registerTool("firewall_status", {
  title: "Firewall status",
  description: "Human-readable firewall state (participant changes only): policies, ports, ICMP, IP sets, time window, ssh protect, tc.",
  inputSchema: z.object({})
}, async () => {
  const s = await get("/status/summary");
  const fmtPorts = (arr) => (arr?.length ? arr.map(x => `${x.protocol}/${x.port}`).join(", ") : "(none)");
  const fmtIPs = (arr) => (arr?.length ? arr.join(", ") : "(none)");
  
  // Build IP sets section DYNAMICALLY
  let ipsetsText = "IP sets (members):\n";
  
  // Known baseline sets (always show in specific order)
  const baselineSets = [
    { key: "p2p_in_allow_src", label: "IN allow (src)" },
    { key: "p2p_in_block_src", label: "IN block (src)" },
    { key: "p2p_out_allow_dst", label: "OUT allow (dst)" },
    { key: "p2p_out_block_dst", label: "OUT block (dst)" },
    { key: "p2p_quarantine_src", label: "Quarantine (src drop)" },
    { key: "p2p_ssh_ban_src", label: "SSH ban (src drop)" }
  ];
  
  for (const { key, label } of baselineSets) {
    const members = s.ipsets?.[key]?.members || [];
    ipsetsText += `- ${label}: ${fmtIPs(members)}\n`;
  }
  
  // Add any CUSTOM ipsets that aren't baseline
  if (s.ipsets) {
    const baselineKeys = baselineSets.map(x => x.key);
    const customSets = Object.keys(s.ipsets).filter(k => !baselineKeys.includes(k)).sort();
    
    if (customSets.length > 0) {
      ipsetsText += "\nCustom IP sets:\n";
      for (const setName of customSets) {
        const members = s.ipsets[setName].members || [];
        ipsetsText += `- ${setName}: ${fmtIPs(members)}\n`;
      }
    }
  }
  
  const text =
`Firewall status (participant changes only)

Policies:
- INPUT:  ${s.policies?.INPUT ?? "?"}
- OUTPUT: ${s.policies?.OUTPUT ?? "?"}

ICMP:
- Inbound ICMP blocked:  ${s.icmp?.input_blocked ? "yes" : "no"}
- Outbound ICMP blocked: ${s.icmp?.output_blocked ? "yes" : "no"}

Ports (explicit rules):
- INPUT allow:  ${fmtPorts(s.ports?.input_allow)}
- INPUT block:  ${fmtPorts(s.ports?.input_block)}
- OUTPUT allow: ${fmtPorts(s.ports?.output_allow)}
- OUTPUT block: ${fmtPorts(s.ports?.output_block)}

${ipsetsText}
Time window (for next time-aware rule):
- start: ${s.time_window?.start ?? "(unset)"}
- stop:  ${s.time_window?.stop ?? "(unset)"}
- tz:    ${s.time_window?.tz ?? "kerneltz"}

SSH protection:
- enabled: ${s.ssh_protect?.enabled ? "yes" : "no"}
- window_seconds: ${s.ssh_protect?.window_seconds ?? "?"}
- per_minute: ${s.ssh_protect?.per_minute ?? "?"}
- burst: ${s.ssh_protect?.burst ?? "?"}
- ban_seconds: ${s.ssh_protect?.ban_seconds ?? "?"}
- ban_set: ${s.ssh_protect?.ban_set ?? "?"}

TC shaping:
- profiles: ${Object.keys(s.tc_profiles ?? {}).length ? JSON.stringify(s.tc_profiles) : "(none)"}
- active schedule: ${s.tc_active?.name ? JSON.stringify(s.tc_active) : "(none)"}
`;
  
  return { content: [{ type: "text", text }] };
});

// Admin / baseline
toolNoInput("firewall_reset", "Reset to baseline firewall state.", "/reset");

// Policies
toolNoInput("set_input_policy_drop", "Set INPUT default policy DROP.", "/policy/input_drop");
toolNoInput("set_input_policy_accept", "Set INPUT default policy ACCEPT.", "/policy/input_accept");
toolNoInput("set_output_policy_drop", "Set OUTPUT default policy DROP.", "/policy/output_drop");
toolNoInput("set_output_policy_accept", "Set OUTPUT default policy ACCEPT.", "/policy/output_accept");

// Existing compatibility tools
toolNoInput("lockdown_output", "Default deny outbound traffic (OUTPUT policy DROP).", "/output/lockdown");
toolNoInput("allow_all_output", "Allow all outbound traffic (OUTPUT policy ACCEPT).", "/output/allow_all");
toolNoInput("allow_dns", "Allow DNS egress (tcp/udp 53).", "/output/allow_dns");
toolNoInput("allow_https", "Allow HTTPS egress (tcp 443).", "/output/allow_https");
toolNoInput("block_output_icmp", "Block outbound ICMP.", "/output/block_icmp");
toolNoInput("block_ssh", "Block inbound SSH (tcp 22).", "/input/block_ssh");
toolNoInput("block_input_icmp", "Block inbound ICMP.", "/input/block_icmp");

// Port primitives
server.registerTool("output_allow_port", {
  title: "Allow outbound port",
  description: "Allow outbound traffic to a destination port/protocol.",
  inputSchema: z.object({ port: z.number().int().min(1).max(65535), protocol: z.enum(["tcp", "udp", "icmp"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/allow_port", args), null, 2) }] }));

server.registerTool("output_block_port", {
  title: "Block outbound port",
  description: "Block outbound traffic to a destination port/protocol.",
  inputSchema: z.object({ port: z.number().int().min(1).max(65535), protocol: z.enum(["tcp", "udp", "icmp"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/block_port", args), null, 2) }] }));

server.registerTool("input_allow_port", {
  title: "Allow inbound port",
  description: "Allow inbound traffic to a local port/protocol.",
  inputSchema: z.object({ port: z.number().int().min(1).max(65535), protocol: z.enum(["tcp", "udp", "icmp"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/allow_port", args), null, 2) }] }));

server.registerTool("input_block_port", {
  title: "Block inbound port",
  description: "Block inbound traffic to a local port/protocol.",
  inputSchema: z.object({ port: z.number().int().min(1).max(65535), protocol: z.enum(["tcp", "udp", "icmp"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/block_port", args), null, 2) }] }));

// IP list primitives
server.registerTool("output_whitelist_ip", {
  title: "Whitelist outbound destination IP",
  description: "Always allow outbound traffic to this destination IP (p2p_out_allow_dst).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/whitelist_ip", args), null, 2) }] }));

server.registerTool("output_blacklist_ip", {
  title: "Blacklist outbound destination IP",
  description: "Always block outbound traffic to this destination IP (p2p_out_block_dst).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/blacklist_ip", args), null, 2) }] }));

server.registerTool("output_unwhitelist_ip", {
  title: "Remove outbound whitelist IP",
  description: "Remove a destination IP from outbound allowlist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/unwhitelist_ip", args), null, 2) }] }));

server.registerTool("output_unblacklist_ip", {
  title: "Remove outbound blacklist IP",
  description: "Remove a destination IP from outbound blocklist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/unblacklist_ip", args), null, 2) }] }));

server.registerTool("input_whitelist_ip", {
  title: "Whitelist inbound source IP",
  description: "Always allow inbound traffic from this source IP (p2p_in_allow_src).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/whitelist_ip", args), null, 2) }] }));

server.registerTool("input_blacklist_ip", {
  title: "Blacklist inbound source IP",
  description: "Always block inbound traffic from this source IP (p2p_in_block_src).",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/blacklist_ip", args), null, 2) }] }));

server.registerTool("input_unwhitelist_ip", {
  title: "Remove inbound whitelist IP",
  description: "Remove a source IP from inbound allowlist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/unwhitelist_ip", args), null, 2) }] }));

server.registerTool("input_unblacklist_ip", {
  title: "Remove inbound blacklist IP",
  description: "Remove a source IP from inbound blocklist.",
  inputSchema: z.object({ ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/unblacklist_ip", args), null, 2) }] }));

// ========== IP RANGE PRIMITIVES (For Challenge 9) ==========
server.registerTool("input_blacklist_ip_range", {
  title: "Blacklist inbound source IP range",
  description: "Block traffic from a range of source IPs (e.g., 192.168.50.100 to 192.168.50.103). Use for Challenge 9 to block specific IP ranges.",
  inputSchema: z.object({ start_ip: z.string(), end_ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/blacklist_ip_range", args), null, 2) }] }));

server.registerTool("input_whitelist_ip_range", {
  title: "Whitelist inbound source IP range",
  description: "Allow traffic from a range of source IPs (e.g., 192.168.50.1 to 192.168.50.99).",
  inputSchema: z.object({ start_ip: z.string(), end_ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/whitelist_ip_range", args), null, 2) }] }));

server.registerTool("output_blacklist_ip_range", {
  title: "Blacklist outbound destination IP range",
  description: "Block traffic to a range of destination IPs.",
  inputSchema: z.object({ start_ip: z.string(), end_ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/blacklist_ip_range", args), null, 2) }] }));

server.registerTool("output_whitelist_ip_range", {
  title: "Whitelist outbound destination IP range",
  description: "Allow traffic to a range of destination IPs.",
  inputSchema: z.object({ start_ip: z.string(), end_ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/whitelist_ip_range", args), null, 2) }] }));

// ========== IPSET PRIMITIVES (Enhanced for Challenge 13 & 15) ==========
server.registerTool("ipset_create", {
  title: "Create/ensure an ipset",
  description: "Ensure an ipset exists (hash:ip). Optional default timeout in seconds. Use this for challenges requiring ipsets with timeouts.",
  inputSchema: z.object({ name: z.string(), timeout_seconds: z.number().int().min(0).optional() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ipset/create", args), null, 2) }] }));

server.registerTool("ipset_add_ip", {
  title: "Add IP to ipset",
  description: "Add an IP to an ipset. Optional per-entry timeout (seconds). For allowlists with timeout (Challenge 13), add IP with timeout then bind set to ACCEPT.",
  inputSchema: z.object({ name: z.string(), ip: z.string(), timeout_seconds: z.number().int().min(0).optional() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ipset/add_ip", args), null, 2) }] }));

server.registerTool("ipset_remove_ip", {
  title: "Remove IP from ipset",
  description: "Remove an IP from an ipset.",
  inputSchema: z.object({ name: z.string(), ip: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ipset/remove_ip", args), null, 2) }] }));

// ========== BIND SET TO ENFORCEMENT (Enhanced) ==========
server.registerTool("input_drop_if_src_in_set", {
  title: "Drop inbound if src in set",
  description: "Bind an ipset so any packet whose source IP is in the set is DROPPED in INPUT. Use for blocking sources.",
  inputSchema: z.object({ set_name: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/bind/input_drop_src_set", args), null, 2) }] }));

server.registerTool("output_drop_if_dst_in_set", {
  title: "Drop outbound if dst in set",
  description: "Bind an ipset so any packet whose destination IP is in the set is DROPPED in OUTPUT. Use for Challenge 15 (quarantine).",
  inputSchema: z.object({ set_name: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/bind/output_drop_dst_set", args), null, 2) }] }));

server.registerTool("output_accept_if_dst_in_set", {
  title: "Accept outbound if dst in set",
  description: "Bind an ipset so any packet whose destination IP is in the set is ACCEPTED in OUTPUT. Use for Challenge 13 (temp allowlist with timeout).",
  inputSchema: z.object({ set_name: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/bind/output_accept_dst_set", args), null, 2) }] }));

server.registerTool("input_accept_if_src_in_set", {
  title: "Accept inbound if src in set",
  description: "Bind an ipset so any packet whose source IP is in the set is ACCEPTED in INPUT. Use for allowlists with timeout.",
  inputSchema: z.object({ set_name: z.string() })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/bind/input_accept_src_set", args), null, 2) }] }));

// ========== SUBNET FILTERING (For Challenge 9) ==========
server.registerTool("input_allow_port_from_subnet", {
  title: "Allow inbound port from subnet",
  description: "Allow INPUT from a CIDR subnet to a specific port. Use for Challenge 9 to allow specific subnet ranges.",
  inputSchema: z.object({ 
    port: z.number().int().min(1).max(65535), 
    protocol: z.enum(["tcp", "udp"]),
    subnet: z.string()
  })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/allow_port_from_subnet", args), null, 2) }] }));

server.registerTool("input_block_port_from_subnet", {
  title: "Block inbound port from subnet",
  description: "Block INPUT from a CIDR subnet to a specific port (inserted at top for priority). Use for Challenge 9 to block specific IPs within allowed ranges.",
  inputSchema: z.object({ 
    port: z.number().int().min(1).max(65535), 
    protocol: z.enum(["tcp", "udp"]),
    subnet: z.string()
  })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/input/block_port_from_subnet", args), null, 2) }] }));

// time window + time-aware allow
server.registerTool("time_window_set", {
  title: "Set time window",
  description: "Set the time window used by the next time-aware rule.",
  inputSchema: z.object({ start_hhmm: z.string(), stop_hhmm: z.string(), tz: z.enum(["kerneltz", "utc"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/time_window/set", args), null, 2) }] }));

server.registerTool("input_allow_port_with_time_window", {
  title: "Allow inbound port only in time window",
  description: "Allow INPUT to port/protocol only during the configured time window.",
  inputSchema: z.object({ port: z.number().int().min(1).max(65535), protocol: z.enum(["tcp", "udp", "icmp"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/time_window/input_allow_port", args), null, 2) }] }));

server.registerTool("output_allow_port_to_ip", {
  title: "Allow outbound port to specific IP",
  description: "Allow OUTPUT to specific destination IP:port combination. Use for Challenge 14 (DNS to specific servers).",
  inputSchema: z.object({ 
    port: z.number().int().min(1).max(65535), 
    protocol: z.enum(["tcp", "udp"]),
    ip: z.string()
  })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/allow_port_to_ip", args), null, 2) }] }));

server.registerTool("output_block_port_to_others", {
  title: "Block outbound port to all others",
  description: "Block OUTPUT to a port for destinations not explicitly allowed (catch-all). Use after allowing specific IPs.",
  inputSchema: z.object({ 
    port: z.number().int().min(1).max(65535), 
    protocol: z.enum(["tcp", "udp"])
  })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/output/block_port_to_others", args), null, 2) }] }));

// SSH rate/ban
server.registerTool("ssh_rate_window_set", {
  title: "SSH rate window",
  description: "Set the SSH attempt tracking window (seconds).",
  inputSchema: z.object({ window_seconds: z.number().int().min(1).max(3600) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ssh_rate/window", args), null, 2) }] }));

server.registerTool("ssh_rate_limit_set", {
  title: "SSH rate limit",
  description: "Set SSH rate limit (per_minute + burst).",
  inputSchema: z.object({ per_minute: z.number().int().min(1).max(600), burst: z.number().int().min(1).max(600) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ssh_rate/limit", args), null, 2) }] }));

server.registerTool("ssh_ban_set_config", {
  title: "SSH ban config",
  description: "Configure ban ipset and ban duration in seconds.",
  inputSchema: z.object({ set_name: z.string(), ban_seconds: z.number().int().min(1).max(86400) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/ssh_ban/config", args), null, 2) }] }));

server.registerTool("ssh_protection_enable", {
  title: "Enable SSH protection",
  description: "Enable SSH rate limiting; violators added to ban set for ban_seconds and dropped.",
  inputSchema: z.object({})
}, async () => ({ content: [{ type: "text", text: JSON.stringify(await post("/ssh_protection/enable"), null, 2) }] }));

// tc shaping
server.registerTool("tc_set_rate_profile", {
  title: "Set tc rate profile",
  description: "Define a named traffic shaping profile (rate in kbit/s).",
  inputSchema: z.object({ name: z.string(), rate_kbit: z.number().int().min(1) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/tc/profile_set", args), null, 2) }] }));

server.registerTool("tc_apply_profile_time_window", {
  title: "Apply tc profile in time window",
  description: "Apply a named tc profile during a time window (applies immediately if currently inside window).",
  inputSchema: z.object({ name: z.string(), start_hhmm: z.string(), stop_hhmm: z.string(), tz: z.enum(["local", "utc"]) })
}, async (args) => ({ content: [{ type: "text", text: JSON.stringify(await postJson("/tc/apply_time_window", args), null, 2) }] }));

await server.connect(new StdioServerTransport());
console.error("🚀 Firewall MCP Server Started (v4.0 - Enhanced for Challenges 9, 13, 15)");
