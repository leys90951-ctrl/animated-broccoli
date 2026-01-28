#!/bin/bash
# start.sh

echo "╔══════════════════════════════════════════════════╗"
echo "║         Starting ShadowForge v4.0                ║"
echo "║                                                  ║"
echo "║  [1] Installing dependencies...                  ║"
python3 -m pip install -r requirements.txt

echo "║  [2] Creating directories...                     ║"
mkdir -p builds templates downloads

echo "║  [3] Starting C2 Server...                       ║"
python3 server.py &

echo "║  [4] C2 Server: localhost:4444                   ║"
echo "║      Web Panel: http://localhost:5000            ║"
echo "║                                                  ║"
echo "║  [!] SYSTEM ACTIVE - NO RESTRICTIONS             ║"
echo "╚══════════════════════════════════════════════════╝"

# Keep running
wait