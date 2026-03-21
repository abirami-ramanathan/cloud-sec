import json
import datetime
from pathlib import Path
import os

# If running inside Docker, use mounted path
LOG_FILE = Path("/app/threat_logs.json")

# Fallback for local execution
if not LOG_FILE.exists():
    PROJECT_ROOT = Path(__file__).resolve().parent
    LOG_FILE = PROJECT_ROOT / "logs" / "threat_logs.json"

def write_threat_log(entry):
    entry["@timestamp"] = datetime.datetime.utcnow().isoformat()

    # Ensure file exists
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(LOG_FILE, "a") as f:
        json.dump(entry, f)
        f.write("\n")