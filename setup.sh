	#!/bin/bash

set -e

echo "==== Prompt2Protect Setup ===="

read -p "Install Docker? (Y/N): " INSTALL_DOCKER

# Normalize input
INSTALL_DOCKER=$(echo "$INSTALL_DOCKER" | tr '[:lower:]' '[:upper:]')

# ---- Docker ----
if [ "$INSTALL_DOCKER" = "Y" ]; then
  echo "[+] Installing Docker..."
  sudo apt update
  sudo apt install -y docker.io
  sudo systemctl enable docker
  sudo systemctl start docker
  sudo usermod -aG docker "$USER"
  echo "[✓] Docker installed"
else
  echo "[→] Skipping Docker install"
fi
