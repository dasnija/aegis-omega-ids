# Hybrid IDS Backend - Advanced Network Security Engine

## 🚀 Overview
This is the core intelligence engine of the Hybrid Intrusion Detection System (IDS). Built on **FastAPI** and **TensorFlow**, it provides a high-performance, asynchronous pipeline for detecting network attacks in PCAP files.

The backend orchestrates a complex 4-layer detection strategy:
1.  **Signature Analysis**: Instant detection of known patterns (SQLi, XSS, etc.).
2.  **Anomaly Detection**: Autoencoder-based flagging of zero-day deviations.
3.  **Deep Sequence Learning**: BiLSTM neural network for payload context analysis.
4.  **Ensemble Fusion**: Meta-classifier (Random Forest) for final high-confidence verdicts.

## 🛠️ Technology Stack
-   **Framework**: FastAPI (High-performance Async I/O)
-   **Machine Learning**: TensorFlow 2.10, Keras, Scikit-learn
-   **Data Processing**: Pandas, NumPy, Scapy (PCAP parsing)
-   **Task Management**: Python `asyncio` & BackgroundTasks for non-blocking inference
-   **Logging**: Comprehensive structured logging for forensics

## 📂 Directory Structure
```
backend/
├── app.py                  # Main FastAPI application entry point
├── config.py               # Centralized configuration (Models, Paths, Thresholds)
├── inference.py            # Core ML Inference Logic
├── database.py             # SQLite storage for job results
├── signature_filter.py     # Layer 1: Regex-based signature engine
├── autoencoder.py          # Layer 2: Anomaly detection model
├── bilstm_classifier.py    # Layer 3: Deep learning sequence model
├── meta_classifier.py      # Layer 4: Ensemble decision logic
├── requirements.txt        # Python dependency manifest
├── start_server.bat        # Windows deployment script
├── models/                 # Pre-trained model artifacts (.h5, .pkl)
├── data/                   # Dataset storage (Training data)
├── uploads/                # Temp storage for uploaded PCAPs
├── inference_results/      # JSON output of analysis results
└── logs/                   # System operation logs
```

## 🔌 API Reference
The API serves at `http://localhost:8000`. Full interactive documentation is available locally via Swagger UI.

### Key Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **POST** | `/api/upload` | Upload `.pcap` files for asynchronous analysis. Returns `job_id`. |
| **GET** | `/api/status/{job_id}` | Check the real-time progress of an analysis job. |
| **GET** | `/api/results/{job_id}` | Retrieve detailed JSON report of a completed analysis. |
| **GET** | `/api/health` | Health check endpoint for system monitoring. |
| **GET** | `/docs` | Interactive Swagger UI documentation. |
| **GET** | `/redoc` | ReDoc API documentation. |

## ⚙️ Installation & Setup

### Prerequisites
-   Python 3.9+
-   Visual C++ Redistributable (for TensorFlow on Windows)

### 1. Environment Setup
Create and activate a virtual environment to isolate dependencies.
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Models
Ensure the `models/` directory contains the necessary `.h5` and `.pkl` artifacts. These are required for the inference pipeline to initialize.

## 🚀 Deployment

### Development Mode
Run the server with hot-reloading enabled.
```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### Production Mode
For production, use the provided script or run with multiple workers.
```bash
# Windows
.\start_server.bat

# Manual Production Command
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

## 🔬 Model Pipeline Details
The system uses a **Lazy Loading** architecture for models to ensure fast startup, but models can be pre-loaded by calling the initialization routine in `app.py`.

-   **Input**: PCAP Files or CSV Flows (71 CICFlowMeter features)
-   **Output**: JSON detailed report containing:
    -   `final_verdict`: Benign / Malicious
    -   `confidence_score`: 0.0 - 1.0 probability
    -   `attack_classification`: Specific attack type (e.g., `sql_injection`, `brute_force`)
    -   `layer_details`: Debug info from each detection layer

## 🛡️ Security Notes
-   **Input Validation**: All file uploads are validated for extension and size.
-   **Sanitization**: Filenames are sanitized to prevent directory traversal.
-   **Secrets**: Ensure `config.py` does not contain hardcoded credentials in production.
