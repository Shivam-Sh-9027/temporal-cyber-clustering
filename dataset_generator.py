import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_dataset(n=100000, days=90):
    np.random.seed(42)

    start_date = datetime.now() - timedelta(days=days)

    timestamps = [
        start_date + timedelta(
            days=np.random.randint(0, days),
            hours=np.random.randint(0, 24),
            minutes=np.random.randint(0, 60),
            seconds=np.random.randint(0, 60),
        )
        for _ in range(n)
    ]

    attack_types = [
        "DDoS", "SQL Injection", "XSS", "Malware", "Phishing",
        "Brute Force", "Ransomware", "Privilege Escalation", "Botnet"
    ]

    severities = ["Low", "Medium", "High", "Critical"]

    df = pd.DataFrame({
        "timestamp": timestamps,
        "attack_type": np.random.choice(attack_types, n),
        "severity": np.random.choice(severities, n, p=[0.40, 0.35, 0.20, 0.05]),
        "source_ip": [
            f"{np.random.randint(1, 255)}.{np.random.randint(0, 255)}."
            f"{np.random.randint(0, 255)}.{np.random.randint(0, 255)}"
            for _ in range(n)
        ],
        "target_system": [
            f"server-{np.random.randint(1, 50)}"
            for _ in range(n)
        ],
        "duration": np.random.randint(5, 5000, n),
        "blocked": np.random.choice([True, False], n, p=[0.7, 0.3])
    })

    return df


print("Generating 1 lakh cybersecurity incidents...")
df = generate_dataset(9000000)
df.to_csv("incidents_9000000.csv", index=False)
print("DONE! Saved as incidents_9000000.csv")
