
# Prompt2Protect – Firewall Challenge Lab

Prompt2Protect is a containerized firewall lab where you solve realistic network security scenarios using an AI assistant that talks to a firewall via an MCP server. The evaluator container verifies your firewall configuration for each challenge and prints a flag when you succeed. 

Designed for workshops and CTF-style practice, the lab runs entirely inside Docker, so participants only need Docker Desktop and a browser for Gemini login. 

---

## Challenge set

When you start the evaluator, you will see a menu like:

```text
=== Prompt2Protect Evaluator ===
  1) The Board Meeting
  2) Broken Name Resolution
  3) The Insider Threat
  4) Selective Partner Access
  5) The DNS Hijacking
  6) The Brute Force Storm
  7) The ICMP Flood
  8) After Hours Lockout
  9) Trusted Partner Subnet
  10) SSH Fort Knox
  11) The Malware Beacon
  12) GDPR Violation Alert
  13) The Two-Hour Exception
  14) DNS Tunneling Defense
  15) Automated Threat Intelligence
```

Each challenge has a clear goal (e.g. “block outbound ICMP, keep HTTPS working”) and a set of checks that must pass before the evaluator reveals the flag. 

---

## Quick start (Windows + Docker Desktop)

These steps are what participants should follow.

### 1. Prerequisites

- Windows 10/11
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running (WSL2 backend recommended)
- Git installed (Git for Windows or Git inside WSL)

You do not need to install Python or Node on your host; all services run in containers.

### 2. Clone the repository and switch branch

Open PowerShell, CMD, or a WSL terminal:

```bash
git clone https://github.com/ACE-CYBERSECURITY/Prompt2Protect.git
cd Prompt2Protect

# Switch to the lab branch that contains the MCP server + evaluator
git checkout mcpserver
git pull
```

The `mcpserver` branch contains the updated firewall adapter, MCP server, evaluator, and challenge definitions. 

### 3. Start the lab with Docker Desktop

With Docker Desktop running, from the `Prompt2Protect` directory:

```bash
docker compose build
docker compose up
```

This builds and starts four services defined in `compose.yaml`: 

- `firewall` – iptables/ipset + Flask HTTP API on port 8080 
- `client` – a utility container sharing the firewall’s network namespace 
- `control` – the MCP server (`firewall-mcp`) and Gemini CLI environment 
- `evaluator` – the Python challenge evaluator (`server.py`) 

Keep this terminal open; it streams logs from all containers.

---

## Using the lab

### 4. Log in to Gemini inside `control`

Open a second terminal and attach to the `control` container:

```bash
docker compose exec control bash
```

Inside the container, run Gemini CLI to perform a one-time login:

```bash
gemini
```

- Choose **Login with Google** when prompted and complete the browser flow.
- After this, Gemini CLI inside `control` is authenticated and can call the already-running `firewall-mcp` MCP server. 
You do not need to start `node server.js` yourself; the server is started automatically by the container. 

### 5. Start the evaluator and select a challenge

Open a third terminal and attach to the `evaluator` container:

```bash
docker compose exec evaluator bash
```

Inside:

```bash
python3 server.py
```

You will see the challenge menu:

```text
=== Prompt2Protect Evaluator ===
  1) The Board Meeting
  2) Broken Name Resolution
  ...
  15) Automated Threat Intelligence
  q) Quit
```

Flow per challenge: 

1. Enter the challenge number (for example `1`).
2. The evaluator:
   - Resets the firewall to a clean baseline. 
   - Prints the challenge title and **Goal**.
   - Asks if you want to start now (`y/n`).
3. Type `y` to begin solving. The evaluator will then run checks when you instruct it to proceed.

If all checks for that challenge pass, the evaluator prints a flag derived from `FLAG_SECRET` and the encrypted `flag_inner_xor_hex` field for that challenge. 

### 6. Solving challenges via MCP tools

While the evaluator waits, you work from the `control` container using Gemini + MCP:

- Gemini connects to the `firewall-mcp` server inside `control`.
- Tools exposed by `firewall-mcp` call the HTTP API on the `firewall` container (via `FIREWALL_URL=http://firewall:8080`).

Key tools include: 

- **Status & reset**
  - `firewall_status` – human-readable summary of:
    - INPUT/OUTPUT policies
    - Explicit port allow/block rules
    - ICMP block state
    - IP set contents (baseline + custom)
    - Time window
    - SSH protection settings
    - Traffic shaping (tc) profiles and active schedule
  - `firewall_reset` – reset firewall to baseline (same bootstrap used by evaluator before each challenge) 

- **Policy and ports**
  - `set_input_policy_drop`, `set_input_policy_accept`
  - `set_output_policy_drop`, `set_output_policy_accept`
  - `lockdown_output`, `allow_all_output`
  - `allow_dns` (TCP/UDP 53), `allow_https` (TCP 443)
  - `block_output_icmp`, `block_input_icmp`, `block_ssh` 
  - `input_allow_port`, `input_block_port`
  - `output_allow_port`, `output_block_port` 

- **IP / ipset primitives**
  - Inbound:
    - `input_whitelist_ip`, `input_blacklist_ip`
    - `input_unwhitelist_ip`, `input_unblacklist_ip` 
  - Outbound:
    - `output_whitelist_ip`, `output_blacklist_ip`
    - `output_unwhitelist_ip`, `output_unblacklist_ip` 
  - Ranges and subnets (e.g. for partner / scanner challenges):
    - `input_blacklist_iprange`, `input_whitelist_iprange`
    - `output_blacklist_iprange`, `output_whitelist_iprange`
    - `input_allow_port_from_subnet`, `input_block_port_from_subnet` 
  - Generic ipset management:
    - `ipset_create`, `ipset_add_ip`, `ipset_remove_ip` 
    - `input_drop_if_src_in_set`, `input_accept_if_src_in_set`
    - `output_drop_if_dst_in_set`, `output_accept_if_dst_in_set` 

- **Time windows and traffic shaping**
  - `timewindow_set` – configure a time window (`start`, `stop`, `tz`) used by the next time-aware rule 
  - `input_allow_port_with_timewindow` – allow INPUT only during the configured window 
  - `tc_set_rate_profile` – define tc egress profiles in kbit/s
  - `tc_apply_profile_timewindow` – activate a tc profile during a time window 

- **SSH protection and scanning**
  - `ssh_rate_window_set`, `ssh_rate_limit_set`
  - `ssh_ban_set_config`, `ssh_protection_enable` 

Use these tools (through Gemini) to implement the goal described by the evaluator. Then return to the evaluator terminal to run the checks and see if the configuration passes. 

### 7. Optional: manual testing with `client`

If you want to manually inspect connectivity, you can also open a shell in the `client` container.

```bash
docker compose exec client bash
```

This container shares the firewall’s network stack, so any `curl`/`dig` commands you run here are subject to the iptables/ipset rules in `firewall`. 

---

## Internals (for organizers / maintainers)

Participants do not need these details, but they are useful for anyone maintaining or extending the lab.

### Docker architecture

`compose.yaml` wires the containers together: 

- `firewall`
  - Built from `./firewall` with `NET_ADMIN` capability. 
  - Runs `adapter.py` (Flask) exposing endpoints like `/status`, `/status/summary`, `/reset`, `/policy/*`, `/input/*`, `/output/*`, `/eval/*`. 
  - Manages:
    - iptables baseline and participant changes
    - ipsets for allow/block, quarantine, SSH bans
    - tc egress shaping

- `control`
  - Built from `./control`. 
  - Runs `server.js` (MCP server) on stdio, plus Gemini CLI. 
  - Uses `FIREWALL_URL=http://firewall:8080` to control the firewall via HTTP. 

- `evaluator`
  - Built from `./evaluator`. 
  - Loads challenges from `/app/challenges.json`. 
  - Uses two firewall views:
    - `/status` for raw iptables/ipset output
    - `/status/summary` for parsed policies, ports, ipsets, time window, etc. 
  - Executes checks such as:
    - `assert_iptables_policy`, `assert_iptables_rule_exists`
    - `assert_ipset_exists`, `assert_ipset_contains`, `assert_ipset_contains_with_timeout` 
    - `probe_tcp_out`, `probe_tcp_in`, `probe_tcp_in_from_source`, `probe_tcp_in_at_time`, `probe_udp_out`
    - `probe_dns_out`, `probe_icmp_out`
    - Time-window, SSH protection, tc-profile checks 

- `client`
  - Built from `./client`, uses `network_mode: "service:firewall"`. 
  - Meant for manual testing by organizers or advanced participants. 

### Challenge and flag design

Challenges are defined in `challenges.json` with the following structure: 

- `number` – menu index
- `id` and `title`
- `goal` – human-readable description shown to participants
- `flag_inner_xor_hex` – encrypted flag payload
- `checks` – list of check objects specifying what must be true

Flag generation in `server.py`: 

- `decrypt_flag_base()`:
  - Decodes `flag_inner_xor_hex` from hex
  - XORs it with `FLAG_SECRET` bytes
  - Produces a base flag string
- `make_flag()` wraps the base into a `FLAG_SECRET{...}` form and adds an HMAC-based signature (truncated). 

The evaluator prints the result of `make_flag()` only when every check for a challenge returns success. 

---

## Stopping and restarting

To stop all containers:

```bash
docker compose down
```

To start again later:

```bash
docker compose up
```

Your git branch and any local changes remain; containers are recreated on demand.
```
MADE WITH ❤️ BY ACE CYBERSECURITY CLUSTER - SASTRA UNIVERSITY
