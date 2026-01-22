#!/usr/bin/env node
import { exec } from "child_process";
import { promisify } from "util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const execAsync = promisify(exec);

/* ================= INTERNAL EXECUTOR ================= */
// Added -w 5 to wait up to 5 seconds for the xtables lock
const ipt = async (args) => {
  try {
    const { stdout, stderr } = await execAsync(`sudo iptables -w 5 ${args}`);
    return stdout.toString() || stderr.toString() || "Success (no output)";
  } catch (e) {
    return `Error: ${e.stderr?.toString() || e.message}`;
  }
};

let ruleHistory = [];

/* ================= MCP SERVER ================= */
const server = new Server(
  { name: "firewall-tool", version: "2.1.0" },
  { capabilities: { tools: {} } }
);

/* ================= TOOL LIST ================= */
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "add_firewall_rule",
      description: "Directly execute an iptables command. Use this for blocking/allowing ports.",
      inputSchema: {
        type: "object",
        properties: {
          args: { 
            type: "string", 
            description: "The full iptables arguments, e.g., '-A INPUT -p tcp --dport 80 -j DROP'" 
          }
        },
        required: ["args"]
      }
    },
    {
      name: "rollback_last_rule",
      description: "Undo the very last iptables rule added in this session.",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "reset_firewall",
      description: "Flush all rules and set default policies to ACCEPT.",
      inputSchema: { type: "object", properties: {} }
    }
  ]
}));

/* ================= TOOL HANDLERS ================= */
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a = {} } = req.params;

  try {
    if (name === "add_firewall_rule") {
      const output = await ipt(a.args);

      // Rollback Logic: Capture info if it's an append command
      const match = a.args.match(/-A\s+(INPUT|OUTPUT|FORWARD)/);
      if (match) {
        const chain = match[1];
        // Fetch current state to find the line number
        const listOutput = await ipt(`-L ${chain} --line-numbers -n`);
        const lines = listOutput.trim().split("\n");
        const lastLine = lines[lines.length - 1];
        const ruleNumber = lastLine.trim().split(/\s+/)[0];
        
        if (!isNaN(ruleNumber)) {
          ruleHistory.push({ chain, ruleNumber });
        }
      }

      return {
        content: [{ type: "text", text: `Status: ${output}` }]
      };
    }

    if (name === "rollback_last_rule") {
      const last = ruleHistory.pop();
      if (!last) {
        return { content: [{ type: "text", text: "No history found to rollback." }] };
      }
      const output = await ipt(`-D ${last.chain} ${last.ruleNumber}`);
      return { content: [{ type: "text", text: `Rolled back rule ${last.ruleNumber} from ${last.chain}. Result: ${output}` }] };
    }

    if (name === "reset_firewall") {
      await ipt("-F");
      await ipt("-X");
      await ipt("-P INPUT ACCEPT");
      await ipt("-P OUTPUT ACCEPT");
      ruleHistory = [];
      return { content: [{ type: "text", text: "Firewall completely reset to default ACCEPT." }] };
    }

    return { content: [{ type: "text", text: "Unknown tool" }], isError: true };
  } catch (error) {
    return { content: [{ type: "text", text: `Runtime Error: ${error.message}` }], isError: true };
  }
});

/* ================= START ================= */
const transport = new StdioServerTransport();
await server.connect(transport);

// Use console.error for logging so it doesn't break the STDIO JSON pipe
console.error("🚀 Firewall MCP Server Started (Async Mode)");