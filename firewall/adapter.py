from flask import Flask, jsonify
import subprocess

app = Flask(__name__)

def sh(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.get("/status")
def status():
    return jsonify(rules=sh("iptables -S"))

@app.post("/reset")
def reset():
    sh("iptables -F")
    sh("iptables -P OUTPUT ACCEPT")
    return jsonify(ok=True, mode="reset")

@app.post("/lockdown")
def lockdown():
    sh("iptables -F")
    sh("iptables -P OUTPUT DROP")
    sh("iptables -A OUTPUT -o lo -j ACCEPT")
    sh("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    return jsonify(ok=True, mode="lockdown")

@app.post("/allow_dns")
def allow_dns():
    sh("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT")
    sh("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT")
    return jsonify(ok=True, rule="dns")

@app.post("/allow_https")
def allow_https():
    sh("iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT")
    return jsonify(ok=True, rule="https")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
