import os, json, secrets, hmac, hashlib
import requests

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

def evaluate(challenge):
    status_blob = fw_get("/status")

    for chk in challenge.get("checks", []):
        t = chk["type"]

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

        else:
            return False  # fail closed

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
