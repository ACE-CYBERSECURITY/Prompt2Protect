from flask import Flask, jsonify
import subprocess

app = Flask(__name__)

API_PORT = 8080
ALLOWED_INPUT_PORTS = {22, 2222}  # whitelist for challenges

def sh(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

def bootstrap():
    # Always keep API reachable
    sh("iptables -F")
    sh("iptables -P INPUT ACCEPT")
    sh("iptables -P OUTPUT ACCEPT")
    sh("iptables -P FORWARD ACCEPT")

    sh(f"iptables -A INPUT -p tcp --dport {API_PORT} -j ACCEPT")
    sh("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    sh("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    sh("iptables -A OUTPUT -o lo -j ACCEPT")

bootstrap()

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.get("/status")
def status():
    return jsonify(rules=sh("iptables -S"))

# ---------- RESET ----------
@app.post("/reset")
def reset():
    bootstrap()
    return jsonify(ok=True, mode="reset")

# ---------- OUTPUT CONTROLS ----------
@app.post("/output/lockdown")
def output_lockdown():
    sh("iptables -P OUTPUT DROP")
    return jsonify(ok=True, output="DROP")

@app.post("/output/allow_all")
def output_allow_all():
    sh("iptables -P OUTPUT ACCEPT")
    return jsonify(ok=True, output="ACCEPT")

@app.post("/output/allow_dns")
def allow_dns():
    sh("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT")
    sh("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT")
    return jsonify(ok=True, rule="dns")

@app.post("/output/allow_https")
def allow_https():
    sh("iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT")
    return jsonify(ok=True, rule="https")

@app.post("/output/block_icmp")
def block_icmp():
    sh("iptables -A OUTPUT -p icmp -j DROP")
    return jsonify(ok=True, rule="icmp_blocked")

# ---------- INPUT CONTROLS ----------
@app.post("/input/block_ssh")
def block_ssh():
    sh("iptables -A INPUT -p tcp --dport 22 -j DROP")
    return jsonify(ok=True, ssh="blocked")

@app.post("/input/allow_port/<int:port>")
def allow_input_port(port):
    if port not in ALLOWED_INPUT_PORTS:
        return jsonify(ok=False, error="Port not allowed"), 403
    sh(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
    return jsonify(ok=True, port=port)

@app.post("/input/block_icmp")
def block_input_icmp():
    sh("iptables -A INPUT -p icmp -j DROP")
    return jsonify(ok=True, icmp="blocked")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
