import webbrowser
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import io
import threading

app = Flask(__name__)
CORS(app)

INCIDENTS = None

# Column mapping for messy files
COLUMN_MAPPING = {
    'timestamp': ['timestamp', 'Timestamp', 'time', 'Time', 'event_time'],
    'attack_type': ['attack_type', 'Attack Type', 'type', 'Type', 'attack'],
    'severity': ['severity', 'Severity', 'Attack Severity', 'level'],
    'source_ip': ['source_ip', 'Source IP', 'src_ip', 'srcIP'],
    'target_system': ['target_system', 'Destination IP', 'dest_ip', 'target'],
    'duration': ['duration', 'Duration', 'time_duration'],
    'blocked': ['blocked', 'Blocked', 'is_blocked', 'status']
}


# ========================================
# Utilities
# ========================================
def normalize_columns(df):
    rename_map = {}
    for standard, variations in COLUMN_MAPPING.items():
        for col in df.columns:
            if col in variations:
                rename_map[col] = standard
    return df.rename(columns=rename_map)


def preprocess(df):
    df = normalize_columns(df)

    if "timestamp" not in df.columns:
        raise ValueError("timestamp column missing")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["day_name"] = df["timestamp"].dt.day_name()
    df["month"] = df["timestamp"].dt.month
    df["date"] = df["timestamp"].dt.date

    if "severity" in df.columns:
        severity_map = {
            'low': 1, 'Low': 1, 'LOW': 1,
            'medium': 2, 'Medium': 2, 'MEDIUM': 2,
            'high': 3, 'High': 3, 'HIGH': 3,
            'critical': 4, 'Critical': 4, 'CRITICAL': 4
        }
        df["severity_num"] = df["severity"].map(severity_map).fillna(2)

    if "blocked" in df.columns:
        df["blocked"] = df["blocked"].map({
            True: 1, "true": 1, "True": 1, "yes": 1, "Yes": 1, 1: 1,
            False: 0, "false": 0, "False": 0, "no": 0, "No": 0, 0: 0
        }).fillna(0)

    return df


# ========================================
# Serve Dashboard UI
# ========================================
@app.route("/")
def home():
    return render_template("index.html")


# ========================================
# Upload Incidents
# ========================================
@app.route("/api/incidents/upload", methods=["POST"])
def upload_incidents():
    global INCIDENTS

    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]

        if file.filename.endswith(".csv"):
            df = pd.read_csv(file)
        elif file.filename.endswith(".json"):
            df = pd.read_json(file)
        else:
            return jsonify({"error": "Unsupported file format"}), 400

        df = preprocess(df)
        INCIDENTS = df

        return jsonify({
            "message": "File uploaded",
            "records": len(df),
            "columns": list(df.columns),
            "date_range": {
                "start": str(df["timestamp"].min()),
                "end": str(df["timestamp"].max())
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ========================================
# Generate Synthetic Data
# ========================================
@app.route("/api/incidents/generate", methods=["POST"])
def generate_incidents():
    global INCIDENTS

    try:
        n_records = request.json.get("records", 1000)

        np.random.seed(42)
        start_date = datetime.now() - timedelta(days=90)

        timestamps = [
            start_date + timedelta(
                days=np.random.randint(0, 90),
                hours=np.random.randint(0, 24),
                minutes=np.random.randint(0, 60)
            )
            for _ in range(n_records)
        ]

        attack_types = ['DDoS', 'SQL Injection', 'XSS', 'Malware',
                        'Phishing', 'Brute Force', 'Ransomware']

        severities = ['Low', 'Medium', 'High', 'Critical']

        df = pd.DataFrame({
            "timestamp": timestamps,
            "attack_type": np.random.choice(attack_types, n_records),
            "severity": np.random.choice(severities, n_records),
            "source_ip": [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
                          for _ in range(n_records)],
            "target_system": [f"server-{np.random.randint(1,10)}"
                              for _ in range(n_records)],
            "duration": np.random.randint(10, 3600, n_records),
            "blocked": np.random.choice([True, False], n_records, p=[0.7, 0.3])
        })

        df = preprocess(df)
        INCIDENTS = df

        return jsonify({
            "message": "Synthetic data generated",
            "records": len(df),
            "date_range": {
                "start": str(df["timestamp"].min()),
                "end": str(df["timestamp"].max())
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ========================================
# Clustering Analysis
# ========================================
@app.route("/api/clustering/analyze", methods=["POST"])
def clustering():
    if INCIDENTS is None:
        return jsonify({"error": "No incidents loaded"}), 400

    try:
        n_clusters = request.json.get("n_clusters", 4)

        df = INCIDENTS
        features = df[["hour", "day_of_week", "month"]].values

        scaler = StandardScaler()
        scaled = scaler.fit_transform(features)

        model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        df["cluster"] = model.fit_predict(scaled)

        silhouette = silhouette_score(scaled, df["cluster"])
        inertia = model.inertia_

        centroids = scaler.inverse_transform(model.cluster_centers_)

        cluster_stats = []
        for i in range(n_clusters):
            c = df[df["cluster"] == i]
            cluster_stats.append({
                "cluster_id": i,
                "size": len(c),
                "avg_hour": float(centroids[i][0]),
                "avg_day": float(centroids[i][1]),
                "avg_month": float(centroids[i][2]),
                "percentage": float(len(c) / len(df) * 100)
            })

        return jsonify({
            "silhouette_score": float(silhouette),
            "inertia": float(inertia),
            "n_clusters": n_clusters,
            "cluster_stats": cluster_stats,
            "centroids": centroids.tolist()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ========================================
# Temporal Analysis
# ========================================
@app.route('/api/analysis/temporal', methods=['POST'])
def temporal():
    global INCIDENTS

    if INCIDENTS is None:
        return jsonify({"error": "No data loaded"}), 400

    df = INCIDENTS.copy()

    # Hourly distribution
    hourly = df.groupby("hour").size().to_dict()

    # Weekly heatmap (convert DF to records)
    heatmap = df.groupby(["day_of_week", "hour"]).size().reset_index(name="count")
    heatmap_records = heatmap.to_dict("records")

    # Attack type patterns
    if "attack_type" in df.columns:
        attack = df.groupby(["attack_type", "hour"]).size().reset_index(name="count")
        attack_records = attack.to_dict("records")
    else:
        attack_records = []

    # Severity patterns
    if "severity" in df.columns:
        severity = df.groupby(["severity", "hour"]).size().reset_index(name="count")
        severity_records = severity.to_dict("records")
    else:
        severity_records = []

    # High risk calculations
    hourly_counts = df.groupby("hour").size()
    high_risk_hours = hourly_counts[hourly_counts > hourly_counts.mean()].index.tolist()

    day_counts = df.groupby("day_name").size()
    high_risk_days = day_counts.nlargest(3).index.tolist()

    return jsonify({
        "hourly_distribution": hourly,
        "weekly_heatmap": heatmap_records,
        "attack_type_patterns": attack_records,
        "severity_patterns": severity_records,
        "high_risk_hours": high_risk_hours,
        "high_risk_days": high_risk_days,
        "total_incidents": len(df)
    })

# ========================================
# Prediction Analysis
# ========================================
@app.route("/api/analysis/predictions", methods=["POST"])
def predictions():
    if INCIDENTS is None:
        return jsonify({"error": "No data loaded"}), 400

    df = INCIDENTS

    hourly_counts = df.groupby("hour").size()
    mean = hourly_counts.mean()
    std = hourly_counts.std()

    threshold = mean + 0.5 * std

    high_risk_hours = hourly_counts[hourly_counts > threshold].index.tolist()

    high_risk_days = df.groupby("day_name").size().nlargest(3).index.tolist()

    last_date = df["timestamp"].max()

    preds = []
    for i in range(7):
        next_date = last_date + timedelta(days=i + 1)
        day_name = next_date.strftime("%A")

        day_avg = df[df["day_name"] == day_name].groupby("date").size().mean()

        preds.append({
            "date": str(next_date.date()),
            "day": day_name,
            "predicted_incidents": int(day_avg) if day_avg == day_avg else 0,
            "high_risk": day_name in high_risk_days
        })

    return jsonify({
        "predicted_high_risk_hours": high_risk_hours,
        "predicted_high_risk_days": high_risk_days,
        "next_week_predictions": preds,
        "recommendations": [
            f"Increase monitoring during hours: {high_risk_hours}",
            f"High-risk days: {', '.join(high_risk_days)}",
            "Deploy extra WAF rules during peaks",
            "Schedule audits during low-activity hours"
        ]
    })


# ========================================
# Auto-open Browser
# # ========================================
# def open_browser():
#     webbrowser.open("http://localhost:5000")


# ========================================
# Run Flask App
# ========================================
if __name__ == "__main__":
    # threading.Timer(1.5, open_browser).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
