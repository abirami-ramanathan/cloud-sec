# =========================
# Network Traffic Classifier - Docker Deployment Version
# With ELK Threat Logging
# =========================

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, message=".*feature names.*")

import pandas as pd
import pickle
import os
import time
from datetime import datetime
import numpy as np
from collections import Counter
import socket

import alert
from logger import write_threat_log


# =========================
# Severity Mapping Logic
# =========================

CRITICAL_ATTACKS = {
    "neptune", "smurf", "back", "teardrop",
    "pod", "land", "apache2", "udpstorm"
}

MEDIUM_ATTACKS = {
    "ipsweep", "portsweep", "satan", "probe"
}


def get_severity(attack_type):
    if attack_type == "normal":
        return "low"
    elif attack_type in CRITICAL_ATTACKS:
        return "critical"
    elif attack_type in MEDIUM_ATTACKS:
        return "medium"
    else:
        return "high"


# =========================
# Main CSV Processing Logic
# =========================

def process_csv(file_path):

    print("\nProcessing file:", file_path)

    # Load ML model
    with open("./RFCMODEL.pkl", "rb") as model_file:
        classifier = pickle.load(model_file)

    # Load scaler
    with open("./scalerr.sc", "rb") as scaler_file:
        scaler = pickle.load(scaler_file)

    # Define feature columns
    column_names = [
        "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
        "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
        "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
        "connection_key"
    ]

    # Read CSV
    df = pd.read_csv(file_path, header=None, names=column_names, skiprows=1)
    connection_keys = df.pop("connection_key")

    # Scale features
    transformed_data = scaler.transform(df)

    # Predict
    predictions = classifier.predict(transformed_data)
    df["predictions"] = predictions
    df["connection_key"] = connection_keys

    # =========================
    # Terminal Output
    # =========================

    prediction_counts = Counter(predictions)
    total_samples = len(predictions)

    print("\n" + "=" * 70)
    print("NETWORK TRAFFIC CLASSIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total Connections: {total_samples}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 70)

    for attack_type, count in prediction_counts.items():
        percentage = (count / total_samples) * 100
        print(f"{attack_type:20s} : {count:5d} ({percentage:6.2f}%)")

    print("=" * 70 + "\n")

    # =========================
    # ELK Threat Logging
    # =========================

    host_name = socket.gethostname()

    for _, row in df.iterrows():

        attack_type = row["predictions"]
        severity = get_severity(attack_type)
        is_attack = attack_type != "normal"

        log_entry = {
            "@timestamp": datetime.utcnow().isoformat(),
            "tool": "NetworkTrafficClassifier",
            "event_type": "network_connection",
            "host_name": host_name,
            "attack_type": attack_type,
            "connection_key": str(row.get("connection_key", "")),
            "severity": severity,
            "confidence": 0.98 if is_attack else 0.85,
            "model": "RandomForest",
            "model_version": "v1.0"
        }

        write_threat_log(log_entry)

        # Existing alert system
        if is_attack:
            alert.log_attack(attack_type)
        else:
            alert.log_normal()

    # =========================
    # Save Results
    # =========================

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    output_file = f"/app/data3/{timestamp}-results.csv"
    df.to_csv(output_file, index=False)

    print(f"Results saved to: {output_file}")


# =========================
# Folder Monitoring
# =========================

def monitor_folder(folder):

    print("Monitoring folder:", folder)

    while True:
        for file in os.listdir(folder):
            if file == "features.csv":
                file_path = os.path.join(folder, file)
                process_csv(file_path)
                os.remove(file_path)
        time.sleep(1)


# =========================
# Entry Point
# =========================

if __name__ == "__main__":
    folder_to_watch = "/app/data2"
    monitor_folder(folder_to_watch)