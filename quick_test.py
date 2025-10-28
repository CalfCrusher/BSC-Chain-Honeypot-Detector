#!/usr/bin/env python3
"""
Quick smoke tests for the BSC Honeypot Detector.
Runs a few known addresses and prints condensed verdicts.

Tips:
- You can add known honeypot addresses in HONEYPOT_CANDIDATES below.
- Or create a local file 'honeypot_samples.txt' with one address per line; they'll be picked up automatically.
- Or set env HONEYPOT_ADDRS as comma-separated addresses.
"""
from honeypot_detector import HoneypotDetector
import os

ADDRESSES = [
    ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
    ("USDT", "0x55d398326f99059fF775485246999027B3197955"),
    ("MOON?", "0x5E4CEdf1f2dE5F3a096066286310E0094699ddE4"),
]

# Known/Reported honeypot candidates (examples; status may change over time)
# Feel free to replace with your own up-to-date list.
HONEYPOT_CANDIDATES = [
    # ("ReportedHoneypot1", "0x0000000000000000000000000000000000000000"),
    # ("ReportedHoneypot2", "0x0000000000000000000000000000000000000000"),
]

def _load_from_file():
    items = []
    path = os.path.join(os.getcwd(), 'honeypot_samples.txt')
    if os.path.exists(path):
        with open(path, 'r') as f:
            for line in f:
                addr = line.strip()
                if addr and addr.startswith('0x') and len(addr) == 42:
                    items.append(("HoneypotSample", addr))
    return items

def _load_from_env():
    env = os.environ.get('HONEYPOT_ADDRS', '')
    items = []
    if env:
        for addr in [x.strip() for x in env.split(',') if x.strip()]:
            if addr.startswith('0x') and len(addr) == 42:
                items.append(("HoneypotEnv", addr))
    return items

def run():
    all_items = ADDRESSES + HONEYPOT_CANDIDATES + _load_from_file() + _load_from_env()
    for name, addr in all_items:
        try:
            # Enable external check to increase chance of catching honeypots
            det = HoneypotDetector(addr, use_external=True)
            analysis = det.analyze()
            print(f"{name:6} {addr} -> {analysis['verdict']} (score {analysis['risk_score']}/10)")
        except Exception as e:
            print(f"{name:6} {addr} -> ERROR: {e}")

if __name__ == "__main__":
    run()
