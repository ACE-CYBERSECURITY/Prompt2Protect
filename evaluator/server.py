import os, json, secrets, hmac, hashlib
import requests
import socket
import time
from typing import Optional

FIREWALL_URL = os.environ.get("FIREWALL_URL", "http://firewall:8080")
EVAL_TOKEN = os.environ.get("EVAL_TOKEN", "")
FLAG_SECRET = os.environ.get("FLAG_SECRET", "flag_secret")
FLAG_SECRET_BYTES = FLAG_SECRET.encode("utf-8")

def fw_get(path):
    r = requests.get(f"{FIREWALL_URL}{path}", timeout=(2, 4))
    r.raise_for_status()
    return r.json()

def fw_post(path, body=None):
    r = requests.post(f"{FIREWALL_URL}{path}", json=body or {}, timeout=(2, 4))
    r.raise_for_status()
    return r.json()

def fw_eval_post(path, body):
    r = requests.post(
        f"{FIREWALL_URL}{path}",
        json=body,
        headers={"X-EVAL-TOKEN": EVAL_TOKEN},
        timeout=(2, 4),
    )
    r.raise_for_status()
    return r.json()

def load_challenges():
    with open("/app/challenges.json", "r", encoding="utf-8") as f:
        arr = json.load(f)
    return {int(x["number"]): x for x in arr}

def make_session_id():
    return secrets.token_urlsafe(12)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("FLAG_SECRET must not be empty")
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decrypt_flag_base(challenge: dict) -> str:
    hx = (challenge.get("flag_inner_xor_hex") or "").strip()
    if not hx:
        raise ValueError(f"Missing flag_inner_xor_hex for challenge {challenge.get('id')}")
    ct = bytes.fromhex(hx)
    pt = xor_bytes(ct, FLAG_SECRET_BYTES)
    return pt.decode("utf-8", errors="strict")

def make_flag(challenge: dict) -> str:
    base = decrypt_flag_base(challenge)  # decrypted from challenges.json
    msg = f"{base}".encode("utf-8")
    sig = hmac.new(FLAG_SECRET_BYTES, msg, hashlib.sha256).hexdigest()[:24]
    inner = f"{base}"
    return f"{FLAG_SECRET}{{{inner}}}"

def assert_iptables_policy(status_blob, chain, policy):
    return f"-P {chain} {policy}" in (status_blob.get("iptables") or "")

def assert_ipset_contains(status_blob, setname, ip, present):
    blob = status_blob.get("ipset") or ""
    found = (f"Name: {setname}" in blob) and (f"\n{ip}\n" in blob or blob.strip().endswith(ip))
    return (found == present)

def probe_tcp_out(host, port, expect_reachable):
    res = fw_eval_post("/eval/tcp_connect", {"host": host, "port": int(port), "timeout": 1.0})
    got = bool(res.get("reachable"))
    return got == bool(expect_reachable)

def probe_dns_out(name, expect_any_ip):
    res = fw_eval_post("/eval/dns_lookup", {"name": name})
    ips = res.get("ips") or []
    got_any = len(ips) > 0
    return (got_any == bool(expect_any_ip))
# ADD THESE CHECK FUNCTIONS AFTER YOUR EXISTING ONES

def probe_tcp_in(port, expect_reachable):
    """Test if inbound TCP port is reachable from external perspective"""
    # This simulates an external client trying to connect to the firewall
    # In Docker, we test from evaluator → firewall container
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        # Try to connect to firewall container's client-facing port
        result = sock.connect_ex(("firewall", port))
        sock.close()
        reachable = (result == 0)
        return reachable == expect_reachable
    except Exception:
        return not expect_reachable


def probe_icmp_out(host, expect_reachable):
    """Test if outbound ICMP (ping) works"""
    res = fw_eval_post("/eval/icmp_probe", {"host": host})
    reachable = res.get("reachable", False)
    return reachable == expect_reachable


def probe_tcp_in_from_source(source, port, expect_reachable):
    """Test inbound TCP from specific source IP"""
    res = fw_eval_post("/eval/tcp_from_source", {
        "source": source,
        "port": port
    })
    reachable = res.get("reachable", False)
    return reachable == expect_reachable


def probe_tcp_in_at_time(port, test_time, expect_reachable):
    """Test if port is accessible at a specific time (for time window rules)"""
    # This would need to simulate time or wait until that time
    # For now, simplified - assume current time matches or mock it
    res = fw_eval_post("/eval/tcp_at_time", {
        "port": port,
        "time": test_time
    })
    reachable = res.get("reachable", False)
    return reachable == expect_reachable


def probe_udp_out(host, port, expect_reachable):
    """Test outbound UDP connectivity (for DNS tunneling challenge)"""
    res = fw_eval_post("/eval/udp_probe", {
        "host": host,
        "port": port
    })
    reachable = res.get("reachable", False)
    return reachable == expect_reachable


def assert_time_window_configured(start, stop):
    """Verify time window is set"""
    status_blob = fw_get("/status/summary")
    tw = status_blob.get("time_window", {})
    return tw.get("start") == start and tw.get("stop") == stop


def assert_ssh_rate_window(window_seconds):
    """Verify SSH rate window is configured"""
    status_blob = fw_get("/status/summary")
    ssh = status_blob.get("ssh_protect", {})
    return ssh.get("window_seconds") == window_seconds


def assert_ssh_rate_limit(per_minute, burst):
    """Verify SSH rate limit is configured"""
    status_blob = fw_get("/status/summary")
    ssh = status_blob.get("ssh_protect", {})
    return ssh.get("per_minute") == per_minute and ssh.get("burst") == burst


def assert_ssh_ban_config(set_name, ban_seconds):
    """Verify SSH ban configuration"""
    status_blob = fw_get("/status/summary")
    ssh = status_blob.get("ssh_protect", {})
    return ssh.get("ban_set") == set_name and ssh.get("ban_seconds") == ban_seconds


def assert_ssh_protection_enabled(enabled):
    """Verify SSH protection is enabled"""
    status_blob = fw_get("/status/summary")
    ssh = status_blob.get("ssh_protect", {})
    return ssh.get("enabled") == enabled


def simulate_ssh_attack(attempts, expect_banned):
    """Simulate SSH brute force attack"""
    res = fw_eval_post("/eval/simulate_ssh_attack", {
        "attempts": attempts
    })
    banned = res.get("banned", False)
    return banned == expect_banned


def assert_tc_profile_exists(name, rate_kbit):
    """Verify traffic control profile exists with correct rate"""
    status_blob = fw_get("/status/summary")
    profiles = status_blob.get("tc_profiles", {})
    return name in profiles and profiles[name].get("rate_kbit") == rate_kbit


def assert_tc_schedule_active(name, start, stop, tz):
    """Verify TC schedule is active"""
    status_blob = fw_get("/status/summary")
    schedules = status_blob.get("tc_schedules", {})
    if name not in schedules:
        return False
    sched = schedules[name]
    return (sched.get("start") == start and 
            sched.get("stop") == stop and 
            sched.get("tz") == tz)


def assert_ipset_exists(name, default_timeout=None):
    """Verify ipset exists, optionally check default timeout"""
    status_blob = fw_get("/status")
    ipset_output = status_blob.get("ipset", "")
    
    # Check existence
    if f"Name: {name}" not in ipset_output:
        return False
    
    # If timeout check requested
    if default_timeout is not None:
        # Parse ipset output for timeout value
        lines = ipset_output.split("\n")
        in_set = False
        for line in lines:
            if f"Name: {name}" in line:
                in_set = True
            if in_set and "timeout" in line.lower():
                # Check if default timeout matches
                if str(default_timeout) in line:
                    return True
        return False  # Timeout doesn't match
    
    return True


def assert_ipset_contains_with_timeout(set_name, ip, timeout_min, timeout_max):
    """Verify IP is in set with timeout in specified range"""
    status_blob = fw_get("/status")
    ipset_output = status_blob.get("ipset", "")
    
    # Check if IP is in the set
    if not assert_ipset_contains(status_blob, set_name, ip, True):
        return False
    
    # Parse timeout value for this specific IP
    lines = ipset_output.split("\n")
    in_members = False
    in_correct_set = False
    
    for line in lines:
        if f"Name: {set_name}" in line:
            in_correct_set = True
        if in_correct_set and "Members:" in line:
            in_members = True
            continue
        if in_members and ip in line:
            # Line format: "198.51.100.10 timeout 7200"
            parts = line.split()
            if "timeout" in parts:
                idx = parts.index("timeout")
                if idx + 1 < len(parts):
                    timeout_val = int(parts[idx + 1])
                    return timeout_min <= timeout_val <= timeout_max
    
    return False


def assert_iptables_rule_exists(match, action):
    """Verify a specific iptables rule exists"""
    status_blob = fw_get("/status")
    iptables_output = status_blob.get("iptables", "")
    
    # Check if both match pattern and action are present
    return match in iptables_output and f"-j {action}" in iptables_output


def assert_scan_detection_config(threshold_ports, window_seconds):
    """Verify scan detection is configured"""
    status_blob = fw_get("/status/summary")
    scan_config = status_blob.get("scan_detection", {})
    return (scan_config.get("threshold_ports") == threshold_ports and 
            scan_config.get("window_seconds") == window_seconds)


def simulate_port_scan(ports, expect_detection):
    """Simulate a port scan attack"""
    res = fw_eval_post("/eval/simulate_port_scan", {
        "ports": ports
    })
    detected = res.get("detected", False)
    return detected == expect_detection


def assert_ipset_contains_post_scan(set_name, attacker_ip, present):
    """Check if attacker IP was added to ipset after scan simulation"""
    # Wait a moment for detection to process
    time.sleep(1)
    status_blob = fw_get("/status")
    
    if attacker_ip == "simulated":
        # Get the simulated attacker IP from last scan
        scan_info = fw_get("/eval/last_scan_info")
        attacker_ip = scan_info.get("attacker_ip", "127.0.0.1")
    
    return assert_ipset_contains(status_blob, set_name, attacker_ip, present)

# UPDATE THE evaluate() FUNCTION TO HANDLE NEW CHECK TYPES
def evaluate(challenge):
    """Evaluate a challenge by running all its checks"""
    status_blob = fw_get("/status")

    for chk in challenge.get("checks", []):
        t = chk["type"]

        # Existing checks (keep these)
        if t == "assert_iptables_policy":
            if not assert_iptables_policy(status_blob, chk["chain"], chk["policy"]):
                return False

        elif t == "assert_ipset_contains":
            if not assert_ipset_contains(status_blob, chk["set"], chk["ip"], chk["present"]):
                return False

        elif t == "probe_tcp_out":
            if not probe_tcp_out(chk["host"], chk["port"], chk["expect_reachable"]):
                return False

        elif t == "probe_dns_out":
            if not probe_dns_out(chk["name"], chk["expect_any_ip"]):
                return False

        # NEW checks for demo + main challenges
        elif t == "probe_tcp_in":
            if not probe_tcp_in(chk["port"], chk["expect_reachable"]):
                return False

        elif t == "probe_icmp_out":
            if not probe_icmp_out(chk.get("host", "8.8.8.8"), chk["expect_reachable"]):
                return False

        elif t == "probe_tcp_in_from_source":
            if not probe_tcp_in_from_source(chk["source"], chk["port"], chk["expect_reachable"]):
                return False

        elif t == "probe_tcp_in_at_time":
            if not probe_tcp_in_at_time(chk["port"], chk["test_time"], chk["expect_reachable"]):
                return False

        elif t == "probe_udp_out":
            if not probe_udp_out(chk["host"], chk["port"], chk["expect_reachable"]):
                return False

        elif t == "assert_time_window_configured":
            if not assert_time_window_configured(chk["start"], chk["stop"]):
                return False

        elif t == "assert_ssh_rate_window":
            if not assert_ssh_rate_window(chk["window_seconds"]):
                return False

        elif t == "assert_ssh_rate_limit":
            if not assert_ssh_rate_limit(chk["per_minute"], chk["burst"]):
                return False

        elif t == "assert_ssh_ban_config":
            if not assert_ssh_ban_config(chk["set_name"], chk["ban_seconds"]):
                return False

        elif t == "assert_ssh_protection_enabled":
            if not assert_ssh_protection_enabled(chk["enabled"]):
                return False

        elif t == "simulate_ssh_attack":
            if not simulate_ssh_attack(chk["attempts"], chk["expect_banned"]):
                return False

        elif t == "assert_tc_profile_exists":
            if not assert_tc_profile_exists(chk["name"], chk["rate_kbit"]):
                return False

        elif t == "assert_tc_schedule_active":
            if not assert_tc_schedule_active(chk["name"], chk["start"], chk["stop"], chk["tz"]):
                return False

        elif t == "assert_ipset_exists":
            default_timeout = chk.get("default_timeout")
            if not assert_ipset_exists(chk["name"], default_timeout):
                return False

        elif t == "assert_ipset_contains_with_timeout":
            if not assert_ipset_contains_with_timeout(
                chk["set"], chk["ip"], chk["timeout_min"], chk["timeout_max"]
            ):
                return False

        elif t == "assert_iptables_rule_exists":
            if not assert_iptables_rule_exists(chk["match"], chk["action"]):
                return False

        elif t == "assert_scan_detection_config":
            if not assert_scan_detection_config(chk["threshold_ports"], chk["window_seconds"]):
                return False

        elif t == "simulate_port_scan":
            if not simulate_port_scan(chk["ports"], chk["expect_detection"]):
                return False

        elif t == "assert_ipset_contains_post_scan":
            if not assert_ipset_contains_post_scan(chk["set"], chk["attacker_ip"], chk["present"]):
                return False

        else:
            print(f"Unknown check type: {t}")
            return False  # fail on unknown check type

    return True

def menu(challenges_by_num):
    print("\n=== Prompt2Protect Evaluator ===")
    for n in sorted(challenges_by_num.keys()):
        c = challenges_by_num[n]
        print(f"  {n}) {c['title']}")
    print("  q) Quit")

def main():
    challenges_by_num = load_challenges()

    while True:
        menu(challenges_by_num)
        choice = input("\nEnter challenge number: ").strip()

        if choice.lower() == "q":
            print("Evaluator Closed")
            return

        try:
            num = int(choice)
        except:
            print("Wrong input. Try again.")
            continue

        if num not in challenges_by_num:
            print("Wrong input. Try again.")
            continue

        challenge = challenges_by_num[num]

        # Mandatory baseline reset at START of a challenge
        fw_post("/reset")
        session_id = make_session_id()

        print("\n--- Challenge Started ---")
        print(f"Challenge: {challenge['title']}")
        print(f"Goal: {challenge['goal']}")
        # NOTE: session_id intentionally NOT printed

        while True:
            ans = input("\nVerify now? (Y/N): ").strip().lower()

            if ans in ("n", "no"):
                print("Challenge cancelled.")
                break

            if ans in ("y", "yes"):
                passed = evaluate(challenge)
                if passed:
                    print("\nFLAG:")
                    print(make_flag(challenge))
                    # Reset ONLY on success
                    fw_post("/reset")
                    print("\nChallenge succeeded. Firewall reset.")
                    break
                else:
                    print("\nInsufficient Protection.")
                    # No reset; allow retry within same session
                    continue

            print("Wrong input. Enter Y or N.")

if __name__ == "__main__":
    main()
