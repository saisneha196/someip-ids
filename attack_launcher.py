#!/usr/bin/env python3
"""
Manual Attack Launcher — trigger attacks on demand and watch the dashboard react.

Usage:
    python attack_launcher.py flood          # 50 rapid-fire requests
    python attack_launcher.py replay         # 8 replayed session IDs
    python attack_launcher.py spoofed_offer  # 5 fake SD offers
    python attack_launcher.py evasion        # 12 slow stealthy requests
    python attack_launcher.py all            # run all attacks in sequence
    python attack_launcher.py interactive    # interactive menu
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(os.path.dirname(os.path.abspath(__file__))) / "local_logs" / "traffic.jsonl"


def write(record):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def flood(count=50):
    """Flood attack — blast 50 requests at 200 msg/s to overwhelm HVAC service."""
    print(f"  🔴 FLOOD: Sending {count} rapid requests to HVAC (0x1001)...")
    for i in range(count):
        write({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x00FF",
            "session_id": f"0x{random.randint(1, 0xFFFF):04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 32),
            "payload_hex": "",
            "label": "flood",
        })
        time.sleep(0.005)  # 200 msg/s
    print(f"    Done — {count} flood messages sent")


def replay(count=8):
    """Replay attack — resend captured requests with stale session ID 0x0001."""
    print(f"  🟠 REPLAY: Sending {count} replayed requests (session=0x0001)...")
    for i in range(count):
        write({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "172.20.0.10",
            "service_id": "0x1001",
            "method_id": "0x0001",
            "client_id": "0x0010",
            "session_id": "0x0001",  # Always the same — stale!
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": 6,
            "payload_hex": "000116410000",
            "label": "replay",
        })
        time.sleep(0.1)
    print(f"    Done — {count} replay messages sent")


def spoofed_offer(count=5):
    """Spoofed offer — broadcast fake SD offers to redirect traffic to attacker."""
    print(f"  🟣 SPOOFED OFFER: Broadcasting {count} fake service offers...")
    for i in range(count):
        write({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "sent",
            "src_ip": "attacker",
            "dst_ip": "255.255.255.255",
            "service_id": "0xFFFF",
            "method_id": "0x8100",
            "client_id": "0x0000",
            "session_id": f"0x{random.randint(1, 100):04X}",
            "message_type": "NOTIFICATION",
            "return_code": "0x00",
            "payload_size": 55,
            "payload_hex": "",
            "label": "spoofed_offer",
        })
        time.sleep(0.2)
    print(f"    Done — {count} spoofed offers broadcast")


def evasion(count=12):
    """Evasion attack — slow flood designed to slip under detector thresholds."""
    print(f"  💗 EVASION: Sending {count} stealthy requests across 3 services...")
    svc_ids = [0x1001, 0x2001, 0x3001]
    svc_ips = ["172.20.0.10", "172.20.0.11", "172.20.0.12"]
    session = random.randint(500, 900)
    for i in range(count):
        idx = i % 3
        session += 1
        write({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.40",
            "dst_ip": svc_ips[idx],
            "service_id": f"0x{svc_ids[idx]:04X}",
            "method_id": f"0x{random.choice([0x0001, 0x0002]):04X}",
            "client_id": "0x0040",
            "session_id": f"0x{session:04X}",
            "message_type": "REQUEST",
            "return_code": "0x00",
            "payload_size": random.randint(4, 12),
            "payload_hex": "",
            "label": "evasion_slow_flood",
        })
        time.sleep(0.3)  # Slow — ~3 msg/s
    print(f"    Done — {count} evasion messages sent (slowly)")


def interactive():
    """Interactive menu — pick an attack and watch the dashboard."""
    attacks = {
        "1": ("Flood (50 rapid requests)", flood),
        "2": ("Replay (8 stale sessions)", replay),
        "3": ("Spoofed Offer (5 fake SD)", spoofed_offer),
        "4": ("Evasion (12 slow stealthy)", evasion),
        "5": ("ALL attacks in sequence", None),
    }

    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  SOME/IP Attack Launcher — Manual Control    ║")
    print("  ╠══════════════════════════════════════════════╣")
    print("  ║  Watch http://localhost:8501 while attacking  ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

    while True:
        print("  Choose an attack:")
        for key, (name, _) in attacks.items():
            print(f"    {key}. {name}")
        print("    q. Quit")
        print()

        choice = input("  > ").strip().lower()

        if choice == "q":
            print("  Bye!")
            break
        elif choice == "5":
            print("\n  Running all attacks in sequence...\n")
            flood()
            print()
            time.sleep(3)
            replay()
            print()
            time.sleep(3)
            spoofed_offer()
            print()
            time.sleep(3)
            evasion()
            print("\n  All attacks complete! Check the dashboard.\n")
        elif choice in attacks:
            print()
            attacks[choice][1]()
            print()
        else:
            print("  Invalid choice, try again.\n")


def main():
    if not LOG_PATH.exists():
        print(f"  ⚠ Log file not found: {LOG_PATH}")
        print(f"  Start the system first: python run_local.py")
        sys.exit(1)

    if len(sys.argv) < 2:
        interactive()
        return

    cmd = sys.argv[1].lower()
    print()
    if cmd == "flood":
        flood()
    elif cmd == "replay":
        replay()
    elif cmd == "spoofed_offer":
        spoofed_offer()
    elif cmd == "evasion":
        evasion()
    elif cmd == "all":
        flood()
        time.sleep(3)
        replay()
        time.sleep(3)
        spoofed_offer()
        time.sleep(3)
        evasion()
    elif cmd == "interactive":
        interactive()
    else:
        print(f"  Unknown attack: {cmd}")
        print(f"  Options: flood, replay, spoofed_offer, evasion, all, interactive")
    print()


if __name__ == "__main__":
    main()
