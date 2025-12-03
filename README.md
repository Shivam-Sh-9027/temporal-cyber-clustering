# Temporal Clustering of Cyber Security Incidents

A modern dashboard and backend for analyzing, clustering, and predicting cybersecurity incidents using temporal patterns. Built with Python (Flask backend) and a beautiful, interactive frontend (HTML/JS/Chart.js).

## Screenshots

![Dashboard Screenshot1](Screenshot_2025-12-03_00_50_08.png)
![Dashboard Screenshot2](Screenshot_2025-12-03_00_53_09.png)

## Features

- **Upload & Analyze Incidents:** Upload your own CSV/JSON of incidents or generate synthetic data.
- **Temporal Clustering:** Cluster incidents by time using KMeans and visualize cluster distributions.
- **Interactive Charts:** Hourly, weekly, and attack-type visualizations powered by Chart.js.
- **Predictions:** 7-day attack predictions with high-risk day highlighting.
- **Security Recommendations:** Automated suggestions based on predicted risks.
- **Dark/Light Theme:** Toggleable modern UI.

## Project Structure

```
├── app.py                  # Flask backend
├── app.ipynb               # Jupyter notebook (experiments)
├── dataset_generator.py    # Synthetic data generator
├── incidents.csv           # Example dataset
├── templates/
│   └── index.html          # Main dashboard UI
└── __pycache__/            # Python cache files
```

## Quick Start

1. **Clone the repo:**
   ```bash
   git clone https://github.com/Shivam-Sh-9027/Temperal_clustering_of_cyber_security_incidents.git
   cd Temperal_clustering_of_cyber_security_incidents
   ```
2. **Create & activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the backend:**
   ```bash
   python app.py
   ```
5. **Open the dashboard:**
   Visit [http://localhost:5000](http://localhost:5000) in your browser.

## API Endpoints

- `POST /api/incidents/upload` — Upload incidents file (CSV/JSON)
- `POST /api/incidents/generate` — Generate synthetic incidents
- `POST /api/clustering/analyze` — Run clustering (pass `{ n_clusters: int }`)
- `POST /api/analysis/temporal` — Get temporal analysis
- `POST /api/analysis/predictions` — Get 7-day predictions & recommendations

## Example Data Format

**CSV Columns:**
- `timestamp` (ISO format)
- `attack_type` (string)
- `severity` (int or string)
- `description` (string)


## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Created by [Shivam]. Contributions welcome!*
