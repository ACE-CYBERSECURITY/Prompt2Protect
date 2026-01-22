from flask import Flask, jsonify, request
import subprocess
import ipaddress
import os
import socket

app = Flask(__name__)

API_PORT = 8080
EVAL_TOKEN = os.environ.get("EVAL_TOKEN", "")

IN_ALLOW = "p2p_in_allow_src"
IN_BLOCK = "p2p_in_block_src"
OUT_ALLOW = "p2p_out_allow_dst"
OUT_BLOCK = "p2p_out_block_dst"

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

def ensure_ipset(name: str):
    try:
        run(["ipset", "list", name])
    except subprocess.CalledProcessError:
        run(["ipset", "create", name, "hash:ip"])

def ipset_add(name: str, ip: str):
    ensure_ipset(name)
    run(["ipset", "add", name, ip, "-exist"])

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

def bootstrap():
    run(["iptables", "-F"])
    run(["iptables", "-X"])
    run(["iptables", "-P", "INPUT", "ACCEPT"])
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    run(["iptables", "-P", "FORWARD", "ACCEPT"])

    for s in (IN_ALLOW, IN_BLOCK, OUT_ALLOW, OUT_BLOCK):
        try:
            run(["ipset", "destroy", s])
        except subprocess.CalledProcessError:
            pass
        run(["ipset", "create", s, "hash:ip"])

    insert_rule_top("INPUT", ["-p", "tcp", "--dport", str(API_PORT), "-j", "ACCEPT"])
    insert_rule_top("INPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    insert_rule_top("OUTPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    insert_rule_top("OUTPUT", ["-o", "lo", "-j", "ACCEPT"])

    ensure_rule("INPUT", ["-m", "set", "--match-set", IN_ALLOW, "src", "-j", "ACCEPT"])
    ensure_rule("INPUT", ["-m", "set", "--match-set", IN_BLOCK, "src", "-j", "DROP"])
    ensure_rule("OUTPUT", ["-m", "set", "--match-set", OUT_ALLOW, "dst", "-j", "ACCEPT"])
    ensure_rule("OUTPUT", ["-m", "set", "--match-set", OUT_BLOCK, "dst", "-j", "DROP"])

bootstrap()

@app.get("/health")
def health():
    return ok("healthy")

@app.get("/status")
def status():
    rules = run(["iptables", "-S"])
    sets = run(["ipset", "list"])
    return jsonify(ok=True, iptables=rules, ipset=sets)

@app.post("/reset")
def reset():
    bootstrap()
    return ok("reset")

# ---------- OUTPUT ----------
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

# ---------- INPUT ----------
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

# ---------- EVALUATOR-ONLY ----------
def tcp_connect(host: str, port: int, timeout_s: float):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect((host, port))
        return True, "connected"
    except Exception as e:
        return False, str(e)
    finally:
        try: s.close()
        except: pass

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
