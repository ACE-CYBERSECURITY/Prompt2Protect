from flask import Flask, jsonify, request
import subprocess, ipaddress, os, socket, re, shlex
from datetime import datetime

app = Flask(__name__)

API_PORT = 8080
EVAL_TOKEN = os.environ.get("EVAL_TOKEN", "")

# existing sets (kept for evaluator compatibility)
IN_ALLOW = "p2p_in_allow_src"
IN_BLOCK = "p2p_in_block_src"
OUT_ALLOW = "p2p_out_allow_dst"
OUT_BLOCK = "p2p_out_block_dst"

# new sets for primitives
QUARANTINE_SRC = "p2p_quarantine_src"
SSH_BAN_SRC = "p2p_ssh_ban_src"

# time-window state used by the next time-aware rule
TIME_WINDOW = {"start": None, "stop": None, "tz": "kerneltz"}  # tz: kerneltz|utc

# tc state
TC_PROFILES = {}  # name -> rate_kbit
TC_ACTIVE = {"name": None, "start": None, "stop": None, "tz": "local"}  # stored config only

# ssh protection state
SSH_PROTECT = {
    "window_seconds": 60,
    "per_minute": 3,
    "burst": 3,
    "ban_set": SSH_BAN_SRC,
    "ban_seconds": 1800,
    "enabled": False,
}

BASELINE_RULE_FINGERPRINTS = [
    "-A INPUT -i lo -j ACCEPT",
    f"-A INPUT -p tcp --dport {API_PORT} -j ACCEPT",
    "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "-A OUTPUT -o lo -j ACCEPT",

    f"-A INPUT -m set --match-set {IN_ALLOW} src -j ACCEPT",
    f"-A INPUT -m set --match-set {IN_BLOCK} src -j DROP",
    f"-A OUTPUT -m set --match-set {OUT_ALLOW} dst -j ACCEPT",
    f"-A OUTPUT -m set --match-set {OUT_BLOCK} dst -j DROP",

    # baseline for new sets (we present members separately)
    f"-A INPUT -m set --match-set {QUARANTINE_SRC} src -j DROP",
    f"-A INPUT -m set --match-set {SSH_BAN_SRC} src -j DROP",
]

def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)

def ok(msg=None, **extra):
    payload = {"ok": True}
    if msg:
        payload["msg"] = msg
    payload.update(extra)
    return jsonify(payload)

def fail(message, code=400, **extra):
    payload = {"ok": False, "error": message}
    payload.update(extra)
    return jsonify(payload), code

def require_eval():
    token = request.headers.get("X-EVAL-TOKEN", "")
    return bool(EVAL_TOKEN) and token == EVAL_TOKEN

def ensure_ipset(name: str, timeout_seconds: int | None = None):
    """Ensure an ipset exists. If it already exists, do nothing (idempotent)."""
    try:
        run(["ipset", "list", name])
        # if set exists, we won't re-create; timeout changes are not applied retroactively
        return
    except subprocess.CalledProcessError:
        pass
    
    cmd = ["ipset", "create", name, "hash:ip"]
    if timeout_seconds is not None:
        cmd += ["timeout", str(int(timeout_seconds))]
    
    # Handle race condition - set might be created between check and create
    try:
        run(cmd)
    except subprocess.CalledProcessError:
        # Set already exists (created by concurrent request) - ignore error
        pass


def ip_norm(s: str) -> str:
    return str(ipaddress.ip_address(s))

def proto_norm(p: str) -> str:
    p = (p or "").lower()
    if p not in ("tcp", "udp", "icmp"):
        raise ValueError("protocol must be tcp|udp|icmp")
    return p

def port_norm(x) -> int:
    v = int(x)
    if v < 1 or v > 65535:
        raise ValueError("port out of range")
    if v == API_PORT:
        raise ValueError("refusing to modify API port")
    return v

def hhmm_norm(x: str) -> str:
    if not isinstance(x, str) or not re.match(r"^\d{2}:\d{2}$", x):
        raise ValueError("time must be HH:MM")
    hh = int(x[0:2]); mm = int(x[3:5])
    if hh < 0 or hh > 23 or mm < 0 or mm > 59:
        raise ValueError("time must be valid HH:MM")
    return f"{hh:02d}:{mm:02d}"

def ensure_ipset(name: str, timeout_seconds: int | None = None):
    try:
        run(["ipset", "list", name])
        # if set exists, we won't re-create; timeout changes are not applied retroactively
        return
    except subprocess.CalledProcessError:
        pass

    cmd = ["ipset", "create", name, "hash:ip"]
    if timeout_seconds is not None:
        cmd += ["timeout", str(int(timeout_seconds))]
    run(cmd)

def ipset_add(name: str, ip: str, timeout_seconds: int | None = None):
    ensure_ipset(name)
    cmd = ["ipset", "add", name, ip, "-exist"]
    if timeout_seconds is not None:
        cmd += ["timeout", str(int(timeout_seconds))]
    run(cmd)

def ipset_del(name: str, ip: str):
    ensure_ipset(name)
    try:
        run(["ipset", "del", name, ip])
    except subprocess.CalledProcessError:
        pass

def ensure_rule(chain: str, rule_args: list[str]):
    try:
        run(["iptables", "-C", chain, *rule_args])
    except subprocess.CalledProcessError:
        run(["iptables", "-A", chain, *rule_args])

def insert_rule_top(chain: str, rule_args: list[str]):
    try:
        run(["iptables", "-C", chain, *rule_args])
    except subprocess.CalledProcessError:
        run(["iptables", "-I", chain, "1", *rule_args])

def delete_rule(chain: str, rule_args: list[str]):
    # delete if exists; ignore if absent
    try:
        run(["iptables", "-D", chain, *rule_args])
    except subprocess.CalledProcessError:
        pass

def bootstrap():
    # ------------------------
    # Clear previous state
    # ------------------------
    run(["iptables", "-F"])
    run(["iptables", "-X"])

    # default policies
    run(["iptables", "-P", "INPUT", "ACCEPT"])
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    run(["iptables", "-P", "FORWARD", "ACCEPT"])

    # destroy sets
    for s in [IN_ALLOW, IN_BLOCK, OUT_ALLOW, OUT_BLOCK, QUARANTINE_SRC, SSH_BAN_SRC]:
        try:
            run(["ipset", "destroy", s])
        except subprocess.CalledProcessError:
            pass

    # recreate sets
    for s in [IN_ALLOW, IN_BLOCK, OUT_ALLOW, OUT_BLOCK, QUARANTINE_SRC]:
        run(["ipset", "create", s, "hash:ip"])
    run(["ipset", "create", SSH_BAN_SRC, "hash:ip", "timeout", "1800"])

    # ------------------------
    # INPUT chain (corrected order)
    # ------------------------
    run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(API_PORT), "-j", "ACCEPT"])
    run(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # **ALLOW first** to avoid blocking legitimate traffic
    run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", IN_ALLOW, "src", "-j", "ACCEPT"])

    # then drop sets
    run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", IN_BLOCK, "src", "-j", "DROP"])
    run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", QUARANTINE_SRC, "src", "-j", "DROP"])
    run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", SSH_BAN_SRC, "src", "-j", "DROP"])

    # ------------------------
    # OUTPUT chain
    # ------------------------
    run(["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    # sets in correct order (ALLOW before DROP)
    run(["iptables", "-A", "OUTPUT", "-m", "set", "--match-set", OUT_ALLOW, "dst", "-j", "ACCEPT"])
    run(["iptables", "-A", "OUTPUT", "-m", "set", "--match-set", OUT_BLOCK, "dst", "-j", "DROP"])

    # default policy is ACCEPT, so no catch-all needed

    # ------------------------
    # Reset states
    # ------------------------
    TIME_WINDOW["start"] = None
    TIME_WINDOW["stop"] = None
    TIME_WINDOW["tz"] = "kerneltz"
    SSH_PROTECT["enabled"] = False
    tc_clear_best_effort()



def parse_ipset_members(ipset_list_text: str) -> dict:
    sets = {}
    cur = None
    for line in ipset_list_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Name:"):
            cur = line.split("Name: ", 1)[1].strip()
            sets[cur] = []
            continue
        if line.startswith("Header:"):
            continue
        if cur:
            ip = line.split()[0]  # first token is IP
            sets[cur].append(ip)
    return sets

def parse_participant_changes(iptables_s: str) -> dict:
    in_policy = None
    out_policy = None
    out_allow_ports, out_block_ports = [], []
    in_allow_ports, in_block_ports = [], []
    out_icmp_block = False
    in_icmp_block = False
    time_rules = []  # capture rules that include -m time

    for line in iptables_s.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse policies
        if line.startswith("-P INPUT "):
            in_policy = line.split()[-1]
            continue
        if line.startswith("-P OUTPUT "):
            out_policy = line.split()[-1]
            continue

        # Skip baseline infrastructure rules
        if any(line == fp for fp in BASELINE_RULE_FINGERPRINTS):
            continue

        # Capture time-based rules
        if "-m time" in line:
            time_rules.append(line)

        # ICMP blocking
        if line.startswith("-A OUTPUT ") and "-p icmp" in line and "-j DROP" in line:
            out_icmp_block = True
            continue
        if line.startswith("-A INPUT ") and "-p icmp" in line and "-j DROP" in line:
            in_icmp_block = True
            continue

        # PORT RULES - More flexible regex
        # Matches: -A INPUT/OUTPUT ... -p tcp/udp ... --dport PORT ... -j ACCEPT/DROP
        # Handles variations like: -m conntrack, -m time, etc. between components
        m = re.search(r'^-A\s+(INPUT|OUTPUT)\s+.*?-p\s+(tcp|udp)\s+.*?--dport\s+(\d+)\s+.*?-j\s+(ACCEPT|DROP)', line)
        if m:
            chain, proto, port, target = m.group(1), m.group(2), int(m.group(3)), m.group(4)
            
            # Skip API port protection rule (already in baseline)
            if port == API_PORT:
                continue
            
            entry = {"protocol": proto, "port": port}
            
            if chain == "OUTPUT" and target == "ACCEPT":
                out_allow_ports.append(entry)
            elif chain == "OUTPUT" and target == "DROP":
                out_block_ports.append(entry)
            elif chain == "INPUT" and target == "ACCEPT":
                in_allow_ports.append(entry)
            elif chain == "INPUT" and target == "DROP":
                in_block_ports.append(entry)
            continue

    def uniq(items):
        seen = set()
        out = []
        for x in items:
            k = (x["protocol"], x["port"])
            if k in seen:
                continue
            seen.add(k)
            out.append(x)
        return out

    return {
        "policies": {"INPUT": in_policy, "OUTPUT": out_policy},
        "ports": {
            "input_allow": uniq(in_allow_ports),
            "input_block": uniq(in_block_ports),
            "output_allow": uniq(out_allow_ports),
            "output_block": uniq(out_block_ports),
        },
        "icmp": {"input_blocked": in_icmp_block, "output_blocked": out_icmp_block},
        "time_rules": time_rules,
    }


    def uniq(items):
        seen = set()
        out = []
        for x in items:
            k = (x["protocol"], x["port"])
            if k in seen:
                continue
            seen.add(k)
            out.append(x)
        return out

    return {
        "policies": {"INPUT": in_policy, "OUTPUT": out_policy},
        "ports": {
            "input_allow": uniq(in_allow_ports),
            "input_block": uniq(in_block_ports),
            "output_allow": uniq(out_allow_ports),
            "output_block": uniq(out_block_ports),
        },
        "icmp": {"input_blocked": in_icmp_block, "output_blocked": out_icmp_block},
        "time_rules": time_rules,
    }

def get_default_iface():
    # choose default route interface; fallback to "eth0"
    try:
        out = run(["bash", "-lc", "ip route show default 2>/dev/null | head -n1"])
        parts = out.strip().split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"

def tc_clear_best_effort():
    iface = get_default_iface()
    try:
        run(["bash", "-lc", f"tc qdisc del dev {shlex.quote(iface)} root 2>/dev/null || true"])
    except Exception:
        pass

def tc_apply_rate_kbit(rate_kbit: int):
    iface = get_default_iface()
    # Use tbf for simple egress limiting
    # burst/latency tuned conservatively
    run(["bash", "-lc", f"tc qdisc del dev {shlex.quote(iface)} root 2>/dev/null || true"])
    run(["bash", "-lc", f"tc qdisc add dev {shlex.quote(iface)} root tbf rate {int(rate_kbit)}kbit burst 32kbit latency 400ms"])

def tc_should_be_active_now(start_hhmm: str, stop_hhmm: str, tz: str) -> bool:
    if tz == "utc":
        now = datetime.utcnow()
    else:
        now = datetime.now()
    now_mins = now.hour * 60 + now.minute
    s = int(start_hhmm[0:2]) * 60 + int(start_hhmm[3:5])
    e = int(stop_hhmm[0:2]) * 60 + int(stop_hhmm[3:5])
    if s == e:
        return True
    if s < e:
        return s <= now_mins < ry
    # window wraps midnight
    return now_mins >= s or now_mins < e

bootstrap()

@app.get("/health")
def health():
    return ok("healthy")

@app.get("/status")
def status():
    rules = run(["iptables", "-S"])
    sets = run(["ipset", "list"])
    return jsonify(ok=True, iptables=rules, ipset=sets)

@app.get("/status/summary")
def status_summary():
    ipt = run(["iptables", "-S"])
    ips = run(["ipset", "list"])

    ipt_summary = parse_participant_changes(ipt)
    ipset_members = parse_ipset_members(ips)

    # ---- INLINE timeout parsing (no new function) ----
    ipset_timeouts = {}
    current = None
    for line in ips.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            current = line.split("Name:")[1].strip()
        elif current and line.startswith("Header:") and "timeout" in line:
            parts = line.split()
            if "timeout" in parts:
                idx = parts.index("timeout")
                if idx + 1 < len(parts):
                    try:
                        ipset_timeouts[current] = int(parts[idx + 1])
                    except ValueError:
                        pass
    # --------------------------------------------------

    ipsets_output = {}

    baseline_sets = [
        IN_ALLOW, IN_BLOCK, OUT_ALLOW, OUT_BLOCK,
        QUARANTINE_SRC, SSH_BAN_SRC
    ]

    for set_name in baseline_sets:
        ipsets_output[set_name] = {
            "name": set_name,
            "members": ipset_members.get(set_name, []),
            "timeout": ipset_timeouts.get(set_name)
        }

    for set_name, members in ipset_members.items():
        if set_name not in baseline_sets:
            ipsets_output[set_name] = {
                "name": set_name,
                "members": members,
                "timeout": ipset_timeouts.get(set_name)
            }

    return jsonify(
        ok=True,
        policies=ipt_summary["policies"],
        icmp=ipt_summary["icmp"],
        ports=ipt_summary["ports"],
        time_rules=ipt_summary["time_rules"],
        time_window=TIME_WINDOW,
        ssh_protect=SSH_PROTECT,
        tc_profiles=TC_PROFILES,
        tc_active=TC_ACTIVE,
        ipsets=ipsets_output,
        note="Participant changes only"
    )

@app.post("/reset")
def reset():
    bootstrap()
    return ok("reset")

# ------------------------
# Policies (primitives)
# ------------------------
@app.post("/policy/input_drop")
def set_input_policy_drop():
    run(["iptables", "-P", "INPUT", "DROP"])
    return ok("INPUT policy DROP")

@app.post("/policy/input_accept")
def set_input_policy_accept():
    run(["iptables", "-P", "INPUT", "ACCEPT"])
    return ok("INPUT policy ACCEPT")

@app.post("/policy/output_drop")
def set_output_policy_drop():
    run(["iptables", "-P", "OUTPUT", "DROP"])
    return ok("OUTPUT policy DROP")

@app.post("/policy/output_accept")
def set_output_policy_accept():
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    return ok("OUTPUT policy ACCEPT")

# ------------------------
# Existing OUTPUT endpoints (kept)
# ------------------------
@app.post("/output/lockdown")
def output_lockdown():
    run(["iptables", "-P", "OUTPUT", "DROP"])
    return ok("output default DROP")

@app.post("/output/allow_all")
def output_allow_all():
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    return ok("output default ACCEPT")

@app.post("/output/allow_dns")
def allow_dns():
    ensure_rule("OUTPUT", ["-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    ensure_rule("OUTPUT", ["-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    return ok("allowed DNS")

@app.post("/output/allow_https")
def allow_https():
    ensure_rule("OUTPUT", ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"])
    return ok("allowed HTTPS")

@app.post("/output/block_icmp")
def block_icmp():
    ensure_rule("OUTPUT", ["-p", "icmp", "-j", "DROP"])
    return ok("blocked outbound ICMP")

@app.post("/output/allow_port")
def output_allow_port():
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
    except Exception as e:
        return fail(str(e))
    ensure_rule("OUTPUT", ["-p", proto, "--dport", str(port), "-j", "ACCEPT"])
    return ok("allowed output port", port=port, protocol=proto)

@app.post("/output/block_port")
def output_block_port():
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
    except Exception as e:
        return fail(str(e))
    ensure_rule("OUTPUT", ["-p", proto, "--dport", str(port), "-j", "DROP"])
    return ok("blocked output port", port=port, protocol=proto)

@app.post("/output/whitelist_ip")
def output_whitelist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_add(OUT_ALLOW, ip)
    return ok("whitelisted output dst ip", ip=ip)

@app.post("/output/blacklist_ip")
def output_blacklist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_add(OUT_BLOCK, ip)
    return ok("blacklisted output dst ip", ip=ip)

@app.post("/output/unwhitelist_ip")
def output_unwhitelist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_del(OUT_ALLOW, ip)
    return ok("removed from output allowlist", ip=ip)

@app.post("/output/unblacklist_ip")
def output_unblacklist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_del(OUT_BLOCK, ip)
    return ok("removed from output blocklist", ip=ip)

# ------------------------
# IP range primitives (for Challenge 9)
# ------------------------
@app.post("/input/blacklist_ip_range")
def input_blacklist_ip_range():
    """Add a range of IPs to input blocklist"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        start_ip = ip_norm(data.get("start_ip"))
        end_ip = ip_norm(data.get("end_ip"))
        
        # Convert to IP addresses for iteration
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start > end:
            return fail("start_ip must be <= end_ip")
        
        # Add each IP in range to blocklist
        added = []
        current = start
        while current <= end:
            ipset_add(IN_BLOCK, str(current))
            added.append(str(current))
            current += 1
            
        return ok(f"added {len(added)} IPs to input blocklist", start_ip=start_ip, end_ip=end_ip, count=len(added), ips=added)
    except Exception as e:
        return fail(str(e))

@app.post("/output/blacklist_ip_range")
def output_blacklist_ip_range():
    """Add a range of IPs to output blocklist"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        start_ip = ip_norm(data.get("start_ip"))
        end_ip = ip_norm(data.get("end_ip"))
        
        # Convert to IP addresses for iteration
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start > end:
            return fail("start_ip must be <= end_ip")
        
        # Add each IP in range to blocklist
        added = []
        current = start
        while current <= end:
            ipset_add(OUT_BLOCK, str(current))
            added.append(str(current))
            current += 1
            
        return ok(f"added {len(added)} IPs to output blocklist", start_ip=start_ip, end_ip=end_ip, count=len(added), ips=added)
    except Exception as e:
        return fail(str(e))

@app.post("/input/whitelist_ip_range")
def input_whitelist_ip_range():
    """Add a range of IPs to input allowlist"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        start_ip = ip_norm(data.get("start_ip"))
        end_ip = ip_norm(data.get("end_ip"))
        
        # Convert to IP addresses for iteration
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start > end:
            return fail("start_ip must be <= end_ip")
        
        # Add each IP in range to allowlist
        added = []
        current = start
        while current <= end:
            ipset_add(IN_ALLOW, str(current))
            added.append(str(current))
            current += 1
            
        return ok(f"added {len(added)} IPs to input allowlist", start_ip=start_ip, end_ip=end_ip, count=len(added), ips=added)
    except Exception as e:
        return fail(str(e))

@app.post("/output/whitelist_ip_range")
def output_whitelist_ip_range():
    """Add a range of IPs to output allowlist"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        start_ip = ip_norm(data.get("start_ip"))
        end_ip = ip_norm(data.get("end_ip"))
        
        # Convert to IP addresses for iteration
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        
        if start > end:
            return fail("start_ip must be <= end_ip")
        
        # Add each IP in range to allowlist
        added = []
        current = start
        while current <= end:
            ipset_add(OUT_ALLOW, str(current))
            added.append(str(current))
            current += 1
            
        return ok(f"added {len(added)} IPs to output allowlist", start_ip=start_ip, end_ip=end_ip, count=len(added), ips=added)
    except Exception as e:
        return fail(str(e))


@app.post("/output/allow_port_to_ip")
def output_allow_port_to_ip():
    """Allow OUTPUT to specific IP:port combination"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
        ip = ip_norm(data.get("ip"))
        
        ensure_rule("OUTPUT", [
            "-d", ip,
            "-p", proto,
            "--dport", str(port),
            "-j", "ACCEPT"
        ])
        return ok(f"allowed OUTPUT {proto}/{port} to {ip}", ip=ip, port=port, protocol=proto)
    except Exception as e:
        return fail(str(e))


@app.post("/output/block_port_to_others")
def output_block_port_to_others():
    """Block OUTPUT to a port for all destinations not explicitly allowed"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
        
        ensure_rule("OUTPUT", [
            "-p", proto,
            "--dport", str(port),
            "-j", "DROP"
        ])
        return ok(f"blocked OUTPUT {proto}/{port} to all others", port=port, protocol=proto)
    except Exception as e:
        return fail(str(e))

# ------------------------
# Existing INPUT endpoints (kept)
# ------------------------
@app.post("/input/block_ssh")
def block_ssh():
    ensure_rule("INPUT", ["-p", "tcp", "--dport", "22", "-j", "DROP"])
    return ok("blocked inbound SSH")

@app.post("/input/block_icmp")
def block_input_icmp():
    ensure_rule("INPUT", ["-p", "icmp", "-j", "DROP"])
    return ok("blocked inbound ICMP")

@app.post("/input/allow_port")
def input_allow_port():
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
    except Exception as e:
        return fail(str(e))
    ensure_rule("INPUT", ["-p", proto, "--dport", str(port), "-j", "ACCEPT"])
    return ok("allowed input port", port=port, protocol=proto)

@app.post("/input/block_port")
def input_block_port():
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
    except Exception as e:
        return fail(str(e))
    ensure_rule("INPUT", ["-p", proto, "--dport", str(port), "-j", "DROP"])
    return ok("blocked input port", port=port, protocol=proto)

@app.post("/input/whitelist_ip")
def input_whitelist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_add(IN_ALLOW, ip)
    return ok("whitelisted source ip", ip=ip)

@app.post("/input/blacklist_ip")
def input_blacklist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_add(IN_BLOCK, ip)
    return ok("blacklisted source ip", ip=ip)

@app.post("/input/unwhitelist_ip")
def input_unwhitelist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_del(IN_ALLOW, ip)
    return ok("removed from input allowlist", ip=ip)

@app.post("/input/unblacklist_ip")
def input_unblacklist_ip():
    data = request.get_json(force=True, silent=True) or {}
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_del(IN_BLOCK, ip)
    return ok("removed from input blocklist", ip=ip)

# ------------------------
# ipset primitives (new)
# ------------------------
@app.post("/ipset/create")
def api_ipset_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or not re.match(r"^[a-zA-Z0-9_\-:]+$", name):
        return fail("bad set name")
    timeout = data.get("timeout_seconds", None)
    if timeout is not None:
        timeout = int(timeout)
        if timeout < 0:
            return fail("timeout_seconds must be >= 0")
    ensure_ipset(name, timeout_seconds=timeout if timeout != 0 else None)
    return ok("ipset ensured", name=name, timeout_seconds=timeout)

@app.post("/ipset/add_ip")
def api_ipset_add_ip():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    timeout = data.get("timeout_seconds", None)
    if timeout is not None:
        timeout = int(timeout)
        if timeout < 0:
            return fail("timeout_seconds must be >= 0")
    ipset_add(name, ip, timeout_seconds=timeout)
    return ok("ip added", name=name, ip=ip, timeout_seconds=timeout)

@app.post("/ipset/remove_ip")
def api_ipset_remove_ip():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    try:
        ip = ip_norm(data.get("ip"))
    except Exception as e:
        return fail(str(e))
    ipset_del(name, ip)
    return ok("ip removed", name=name, ip=ip)

@app.post("/input/allow_port_from_subnet")
def input_allow_port_from_subnet():
    """Allow INPUT from a subnet to a specific port"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
        subnet = data.get("subnet")  # e.g., "192.168.50.0/24"
        
        # Validate CIDR
        ipaddress.ip_network(subnet)
        
        ensure_rule("INPUT", [
            "-s", subnet,
            "-p", proto,
            "--dport", str(port),
            "-j", "ACCEPT"
        ])
        return ok(f"allowed INPUT from {subnet} to {proto}/{port}", subnet=subnet, port=port, protocol=proto)
    except Exception as e:
        return fail(str(e))


@app.post("/input/block_port_from_subnet")
def input_block_port_from_subnet():
    """Block INPUT from a subnet to a specific port"""
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
        subnet = data.get("subnet")  # e.g., "192.168.50.100/30"
        
        # Validate CIDR
        ipaddress.ip_network(subnet)
        
        # INSERT at top (before allow rules)
        insert_rule_top("INPUT", [
            "-s", subnet,
            "-p", proto,
            "--dport", str(port),
            "-j", "DROP"
        ])
        return ok(f"blocked INPUT from {subnet} to {proto}/{port}", subnet=subnet, port=port, protocol=proto)
    except Exception as e:
        return fail(str(e))

# ------------------------
# Bind sets to enforcement (new primitives)
# ------------------------
@app.post("/bind/input_drop_src_set")
def bind_input_drop_src_set():
    data = request.get_json(force=True, silent=True) or {}
    set_name = (data.get("set_name") or "").strip()
    if not set_name:
        return fail("missing set_name")
    ensure_ipset(set_name)
    ensure_rule("INPUT", ["-m", "set", "--match-set", set_name, "src", "-j", "DROP"])
    return ok("bound INPUT drop by src set", set_name=set_name)

@app.post("/bind/output_drop_dst_set")
def bind_output_drop_dst_set():
    data = request.get_json(force=True, silent=True) or {}
    set_name = (data.get("set_name") or "").strip()
    if not set_name:
        return fail("missing set_name")
    ensure_ipset(set_name)
    ensure_rule("OUTPUT", ["-m", "set", "--match-set", set_name, "dst", "-j", "DROP"])
    return ok("bound OUTPUT drop by dst set", set_name=set_name)

@app.post("/bind/output_accept_dst_set")
def bind_output_accept_dst_set():
    """Bind ipset so packets to IPs in the set are ACCEPTED in OUTPUT"""
    data = request.get_json(force=True, silent=True) or {}
    set_name = (data.get("set_name") or "").strip()
    if not set_name:
        return fail("missing set_name")
    ensure_ipset(set_name)
    # Insert at top to take precedence
    insert_rule_top("OUTPUT", ["-m", "set", "--match-set", set_name, "dst", "-j", "ACCEPT"])
    return ok("bound OUTPUT accept by dst set", set_name=set_name)

@app.post("/bind/input_accept_src_set")
def bind_input_accept_src_set():
    """Bind ipset so packets from IPs in the set are ACCEPTED in INPUT"""
    data = request.get_json(force=True, silent=True) or {}
    set_name = (data.get("set_name") or "").strip()
    if not set_name:
        return fail("missing set_name")
    ensure_ipset(set_name)
    # Insert at top to take precedence
    insert_rule_top("INPUT", ["-m", "set", "--match-set", set_name, "src", "-j", "ACCEPT"])
    return ok("bound INPUT accept by src set", set_name=set_name)

# ------------------------
# Time-window primitives (new)
# ------------------------
@app.post("/time_window/set")
def time_window_set():
    data = request.get_json(force=True, silent=True) or {}
    try:
        start = hhmm_norm(data.get("start_hhmm"))
        stop = hhmm_norm(data.get("stop_hhmm"))
    except Exception as e:
        return fail(str(e))
    tz = (data.get("tz") or "kerneltz").lower()
    if tz not in ("kerneltz", "utc"):
        return fail("tz must be kerneltz|utc")
    TIME_WINDOW["start"] = start
    TIME_WINDOW["stop"] = stop
    TIME_WINDOW["tz"] = tz
    return ok("time window set", start=start, stop=stop, tz=tz)

def time_match_args():
    if not TIME_WINDOW["start"] or not TIME_WINDOW["stop"]:
        raise ValueError("time window not set")
    args = ["-m", "time", "--timestart", TIME_WINDOW["start"], "--timestop", TIME_WINDOW["stop"]]
    if TIME_WINDOW["tz"] == "utc":
        args += ["--utc"]
    else:
        args += ["--kerneltz"]
    return args

@app.post("/time_window/input_allow_port")
def input_allow_port_with_time_window():
    data = request.get_json(force=True, silent=True) or {}
    try:
        port = port_norm(data.get("port"))
        proto = proto_norm(data.get("protocol"))
    except Exception as e:
        return fail(str(e))
    try:
        tm = time_match_args()
    except Exception as e:
        return fail(str(e))
    ensure_rule("INPUT", ["-p", proto, *tm, "--dport", str(port), "-j", "ACCEPT"])
    return ok("allowed input port in time window", port=port, protocol=proto, time_window=TIME_WINDOW)

# ------------------------
# SSH rate limit + ban (new)
# ------------------------
@app.post("/ssh_rate/window")
def ssh_rate_window_set():
    data = request.get_json(force=True, silent=True) or {}
    try:
        w = int(data.get("window_seconds"))
        if w < 1 or w > 3600:
            return fail("window_seconds must be 1..3600")
    except Exception:
        return fail("bad parameters")
    SSH_PROTECT["window_seconds"] = w
    return ok("ssh window set", window_seconds=w)

@app.post("/ssh_rate/limit")
def ssh_rate_limit_set():
    data = request.get_json(force=True, silent=True) or {}
    try:
        per_minute = int(data.get("per_minute"))
        burst = int(data.get("burst"))
        if per_minute < 1 or per_minute > 600:
            return fail("per_minute must be 1..600")
        if burst < 1 or burst > 600:
            return fail("burst must be 1..600")
    except Exception:
        return fail("bad parameters")
    SSH_PROTECT["per_minute"] = per_minute
    SSH_PROTECT["burst"] = burst
    return ok("ssh rate set", per_minute=per_minute, burst=burst)

@app.post("/ssh_ban/config")
def ssh_ban_set_config():
    data = request.get_json(force=True, silent=True) or {}
    set_name = (data.get("set_name") or "").strip() or SSH_BAN_SRC
    try:
        ban_seconds = int(data.get("ban_seconds"))
        if ban_seconds < 1 or ban_seconds > 86400:
            return fail("ban_seconds must be 1..86400")
    except Exception:
        return fail("bad parameters")
    SSH_PROTECT["ban_set"] = set_name
    SSH_PROTECT["ban_seconds"] = ban_seconds
    ensure_ipset(set_name, timeout_seconds=ban_seconds)
    # Ensure enforcement exists
    ensure_rule("INPUT", ["-m", "set", "--match-set", set_name, "src", "-j", "DROP"])
    return ok("ssh ban configured", set_name=set_name, ban_seconds=ban_seconds)

@app.post("/ssh_protection/enable")
def ssh_protection_enable():
    # Use hashlimit to rate limit NEW connections; on exceed -> add to ipset with timeout then drop.
    #
    # This is still “primitive enough” because parameters are configured separately.
    #
    # Requires: xt_hashlimit + xt_set kernel support.
    per_minute = SSH_PROTECT["per_minute"]
    burst = SSH_PROTECT["burst"]
    ban_set = SSH_PROTECT["ban_set"]
    ban_seconds = SSH_PROTECT["ban_seconds"]

    ensure_ipset(ban_set, timeout_seconds=ban_seconds)
    ensure_rule("INPUT", ["-m", "set", "--match-set", ban_set, "src", "-j", "DROP"])

    # If under limit: accept NEW ssh
    accept_rule = [
        "-p", "tcp", "--dport", "22",
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "hashlimit",
        "--hashlimit", f"{per_minute}/minute",
        "--hashlimit-burst", str(burst),
        "--hashlimit-mode", "srcip",
        "--hashlimit-name", "p2p_ssh",
        "-j", "ACCEPT"
    ]
    ensure_rule("INPUT", accept_rule)

    # If over limit: add to ban_set with timeout then drop
    over_rule = [
        "-p", "tcp", "--dport", "22",
        "-m", "conntrack", "--ctstate", "NEW",
        "-j", "SET", "--add-set", ban_set, "src", "--timeout", str(ban_seconds)
    ]
    ensure_rule("INPUT", over_rule)

    drop_rule = [
        "-p", "tcp", "--dport", "22",
        "-m", "conntrack", "--ctstate", "NEW",
        "-j", "DROP"
    ]
    ensure_rule("INPUT", drop_rule)

    SSH_PROTECT["enabled"] = True
    return ok("ssh protection enabled", ssh_protect=SSH_PROTECT)

# ------------------------
# tc primitives (new)
# ------------------------
@app.post("/tc/profile_set")
def tc_set_rate_profile():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return fail("missing name")
    try:
        rate_kbit = int(data.get("rate_kbit"))
        if rate_kbit < 1 or rate_kbit > 100000000:
            return fail("rate_kbit out of range")
    except Exception:
        return fail("bad parameters")
    TC_PROFILES[name] = rate_kbit
    return ok("tc profile set", name=name, rate_kbit=rate_kbit)

@app.post("/tc/apply_time_window")
def tc_apply_profile_time_window():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if name not in TC_PROFILES:
        return fail("unknown profile")
    try:
        start = hhmm_norm(data.get("start_hhmm"))
        stop = hhmm_norm(data.get("stop_hhmm"))
    except Exception as e:
        return fail(str(e))
    tz = (data.get("tz") or "local").lower()
    if tz not in ("local", "utc"):
        return fail("tz must be local|utc")

    TC_ACTIVE["name"] = name
    TC_ACTIVE["start"] = start
    TC_ACTIVE["stop"] = stop
    TC_ACTIVE["tz"] = tz

    # Apply immediately if we're in the window now; otherwise clear.
    in_window = tc_should_be_active_now(start, stop, "utc" if tz == "utc" else "local")
    if in_window:
        tc_apply_rate_kbit(TC_PROFILES[name])
        return ok("tc applied now (in window)", iface=get_default_iface(), profile=name, rate_kbit=TC_PROFILES[name])
    else:
        tc_clear_best_effort()
        return ok("tc not applied now (outside window); schedule stored", iface=get_default_iface(), profile=name, rate_kbit=TC_PROFILES[name])

# ------------------------
# EVALUATOR-ONLY endpoints (kept)
# ------------------------
def tcp_connect(host: str, port: int, timeout_s: float):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect((host, port))
        return True, "connected"
    except Exception as e:
        return False, str(e)
    finally:
        try:
            s.close()
        except:
            pass

@app.post("/eval/tcp_connect")
def eval_tcp_connect():
    if not require_eval():
        return fail("unauthorized", 403)
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "")
    try:
        port = int(data.get("port"))
        timeout_s = float(data.get("timeout", 1.0))
    except Exception:
        return fail("bad parameters")
    reachable, info = tcp_connect(host, port, timeout_s)
    return jsonify(ok=True, reachable=reachable, info=info)

@app.post("/eval/dns_lookup")
def eval_dns_lookup():
    if not require_eval():
        return fail("unauthorized", 403)
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "")
    try:
        res = socket.getaddrinfo(name, 443)
        ips = sorted({x[4][0] for x in res})
        return jsonify(ok=True, name=name, ips=ips)
    except Exception as e:
        return jsonify(ok=True, name=name, ips=[], error=str(e))

# ADD THESE AFTER /eval/dns_lookup (around line 900)
@app.post("/eval/tcp_at_time")
def eval_tcp_at_time():
    if not require_eval():
        return fail("unauthorized", 403)

    data = request.get_json(force=True, silent=True) or {}
    port = int(data.get("port", 0))
    test_time = data.get("time")  # "HH:MM"

    try:
        # No time window configured → always reachable
        if not TIME_WINDOW["start"] or not TIME_WINDOW["stop"]:
            return jsonify(ok=True, reachable=True)

        def to_minutes(t):
            h, m = map(int, t.split(":"))
            return h * 60 + m

        start = to_minutes(TIME_WINDOW["start"])
        stop = to_minutes(TIME_WINDOW["stop"])
        now = to_minutes(test_time)

        # Handle normal and overnight windows
        if start <= stop:
            in_window = start <= now < stop
        else:
            # overnight (e.g. 22:00 → 06:00)
            in_window = now >= start or now < stop

        return jsonify(ok=True, reachable=in_window)

    except Exception as e:
        return jsonify(ok=True, reachable=False, error=str(e))

@app.post("/eval/icmp_probe")
def eval_icmp_probe():
    if not require_eval():
        return fail("unauthorized", 403)

    try:
        rules = subprocess.check_output(
            ["iptables-save"], text=True
        ).splitlines()

        reachable = False

        for line in rules:
            if not line.startswith("-A OUTPUT"):
                continue

            tokens = line.split()

            # If a DROP rule explicitly blocks ICMP before any allow
            if "-j" in tokens and tokens[tokens.index("-j") + 1] == "DROP":
                if "-p" in tokens and tokens[tokens.index("-p") + 1] == "icmp":
                    reachable = False
                    break

            # Explicit ICMP allow
            if "-j" in tokens and tokens[tokens.index("-j") + 1] == "ACCEPT":
                if "-p" in tokens and tokens[tokens.index("-p") + 1] == "icmp":
                    reachable = True
                    break

                # Catch-all ACCEPT (no protocol specified)
                if "-p" not in tokens:
                    reachable = True
                    break

        return jsonify(ok=True, reachable=reachable)

    except Exception as e:
        return jsonify(ok=True, reachable=False, error=str(e))


@app.post("/eval/udp_probe")
def eval_udp_probe():
    """Test UDP connectivity (for DNS tunneling challenge) - evaluator only"""
    if not require_eval():
        return fail("unauthorized", 403)
    
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host")
    port = int(data.get("port", 53))
    
    try:
        # Simple UDP test - send packet and check if we can reach
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        # For DNS, send a simple query
        if port == 53:
            # Minimal DNS query for "test.com"
            dns_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03com\x00\x00\x01\x00\x01'
            sock.sendto(dns_query, (host, port))
            data, _ = sock.recvfrom(512)
            sock.close()
            return jsonify(ok=True, reachable=True, host=host, port=port)
        else:
            # Generic UDP probe
            sock.sendto(b"\x00" * 10, (host, port))
            sock.recvfrom(1024)
            sock.close()
            return jsonify(ok=True, reachable=True, host=host, port=port)
    except Exception as e:
        return jsonify(ok=True, reachable=False, host=host, port=port, error=str(e))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)