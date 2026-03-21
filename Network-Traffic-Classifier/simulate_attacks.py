import json
import random
from datetime import datetime
from pathlib import Path

# Path to your threat log file
LOG_FILE = Path("../logs/threat_logs.json")


def write_log(entry):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def simulate_portscan():
    print("Simulating Port Scan...")

    for i in range(20):
        entry = {
            "@timestamp": datetime.utcnow().isoformat(),
            "tool": "NetworkTrafficClassifier",
            "event_type": "network_connection",
            "attack_type": "portsweep",
            "connection_key": f"192.168.1.100_{random.randint(1000,5000)}_192.168.1.1_{random.randint(1,1024)}",
            "severity": "critical",
            "confidence": 0.92,
            "model": "RandomForest",
            "model_version": "v1.0"
        }

        write_log(entry)

    print("Port scan simulation complete.")


def simulate_dos():
    print("Simulating DoS (Neptune)...")

    for i in range(30):
        entry = {
            "@timestamp": datetime.utcnow().isoformat(),
            "tool": "NetworkTrafficClassifier",
            "event_type": "network_connection",
            "attack_type": "neptune",
            "connection_key": f"10.0.0.5_{random.randint(1000,5000)}_10.0.0.1_80",
            "severity": "critical",
            "confidence": 0.95,
            "model": "RandomForest",
            "model_version": "v1.0"
        }

        write_log(entry)

    print("DoS simulation complete.")


if __name__ == "__main__":
    simulate_portscan()
    simulate_dos()