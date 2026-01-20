#!/usr/bin/env node
import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

/* ================= INTERNAL EXECUTOR ================= */
const ipt = (args) => {
  try {
    return execSync(`sudo iptables ${args}`, { stdio: "pipe" }).toString();
  } catch (e) {
    return e.stderr?.toString() || e.message;
  }
};

/* ================= ROLLBACK STATE ================= */
let ruleHistory = [];

/* ================= MCP SERVER ================= */
const server = new Server(
  { name: "firewall-tool", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

/* ================= TOOL LIST ================= */
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "add_firewall_rule",
      description: "Add firewall rule (natural language friendly)",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            enum: ["accept", "allow", "drop", "block", "reject"]
          },
          protocol: {
            enum: ["tcp", "udp", "all"]
          },
          port: { type: "number" },
          source: { type: "string" },
          direction: {
            enum: ["in", "out", "inbound", "outbound"]
          }
        },
        required: ["action", "protocol", "port"],
        additionalProperties: false
      }
    },
    {
      name: "rollback_last_rule",
      description: "Rollback last firewall rule",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "reset_firewall",
      description: "Flush all firewall rules",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "resolve_firewall_intent",
      description: "Handle ambiguous firewall prompts",
      inputSchema: {
        type: "object",
        properties: {
          intent: { type: "string" }
        },
        required: ["intent"]
      }
    },
    {
      name: "iptables_exec",
      description: "Execute raw iptables args (last resort)",
      inputSchema: {
        type: "object",
        properties: {
          args: { type: "string" }
        },
        required: ["args"]
      }
    },
    {
      name: "list_available_tools",
      description: "List available firewall tools",
      inputSchema: { type: "object", properties: {} }
    }
  ]
}));

/* ================= TOOL HANDLERS ================= */
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a = {} } = req.params;

  /* ---- ADD FIREWALL RULE ---- */
  if (name === "add_firewall_rule") {
    const actionMap = {
      accept: "ACCEPT",
      allow: "ACCEPT",
      drop: "DROP",
      block: "DROP",
      reject: "REJECT"
    };

    const dirMap = {
      in: "INPUT",
      inbound: "INPUT",
      out: "OUTPUT",
      outbound: "OUTPUT"
    };

    const action = actionMap[a.action];
    const chain = dirMap[a.direction || "inbound"];
    const proto = a.protocol === "all" ? "" : `-p ${a.protocol}`;
    const src = a.source ? `-s ${a.source}` : "";

    // sane defaults
    ipt("-P INPUT DROP");
    ipt("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    ipt(`-A ${chain} ${proto} --dport ${a.port} ${src} -j ${action}`);

    // get rule number for rollback
    const rules = ipt(`-L ${chain} --line-numbers -n`).trim().split("\n");
    const lastLine = rules[rules.length - 1];
    const ruleNumber = lastLine.split(/\s+/)[0];

    ruleHistory.push({ chain, ruleNumber });

    return {
      content: [{ type: "text", text: `Rule added (rule #${ruleNumber})` }]
    };
  }

  /* ---- ROLLBACK ---- */
  if (name === "rollback_last_rule") {
    const last = ruleHistory.pop();
    if (!last) {
      return { content: [{ type: "text", text: "No rule to rollback" }] };
    }
    ipt(`-D ${last.chain} ${last.ruleNumber}`);
    return { content: [{ type: "text", text: "Last rule rolled back" }] };
  }

  /* ---- RESET ---- */
  if (name === "reset_firewall") {
    ipt("-F");
    ipt("-X");
    ipt("-P INPUT ACCEPT");
    ipt("-P OUTPUT ACCEPT");
    ruleHistory = [];
    return { content: [{ type: "text", text: "Firewall reset" }] };
  }

  /* ---- AMBIGUOUS HANDLER ---- */
  if (name === "resolve_firewall_intent") {
    return {
      content: [{
        type: "text",
        text:
          "Supported actions:\n" +
          "- add_firewall_rule\n" +
          "- rollback_last_rule\n" +
          "- reset_firewall\n" +
          "- iptables_exec (advanced)"
      }]
    };
  }

  /* ---- GENERIC EXECUTOR ---- */
  if (name === "iptables_exec") {
    return {
      content: [{ type: "text", text: ipt(a.args) || "OK" }]
    };
  }

  /* ---- TOOL LIST ---- */
  if (name === "list_available_tools") {
    return {
      content: [{
        type: "text",
        text:
          "add_firewall_rule\n" +
          "rollback_last_rule\n" +
          "reset_firewall\n" +
          "resolve_firewall_intent\n" +
          "iptables_exec\n" +
          "list_available_tools"
      }]
    };
  }

  return { content: [{ type: "text", text: "Unknown tool" }] };
});


await server.connect(new StdioServerTransport());
console.error("Firewall MCP running (FULL + FIXED)");
