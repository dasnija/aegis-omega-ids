# 🛡️ AEGIS-Ω: Hybrid Multi-Layer Intrusion Detection System

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.10-orange.svg)
![React](https://img.shields.io/badge/React-19-61dafb.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)

**Advanced Ensemble Guardian for Intelligent Security - A Next-Generation Network Security Platform Combining Signature Detection, Anomaly Detection, Deep Learning, and Ensemble Methods**

[Features](#-key-features) • [Architecture](#-system-architecture) • [Performance](#-performance-benchmarks) • [Installation](#-installation) • [Documentation](#-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Performance Benchmarks](#-performance-benchmarks)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Detection Capabilities](#-detection-capabilities)
- [Dashboard Features](#-dashboard-features)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Citation](#-citation)

---

## 🎯 Overview

The **AEGIS-Ω (Advanced Ensemble Guardian for Intelligent Security)** is a production-grade, high-performance network security solution that combines traditional signature-based detection with cutting-edge machine learning techniques. Built for security operations centers (SOCs), the system provides real-time analysis of network traffic with industry-leading accuracy and throughput.

### 🌟 What Makes This Special?

- **🔬 4-Layer Detection Strategy**: Signature Analysis → Anomaly Detection → Deep Learning → Ensemble Fusion
- **⚡ High Performance**: 1334+ packets/second on CPU, 1378-1768 pkt/s on GPU
- **🎯 Superior Accuracy**: F1-Score ≥0.95 across 12+ attack types
- **🚀 Modern Architecture**: FastAPI backend + React 19 frontend
- **📊 Real-Time Analytics**: Live threat visualization and forensic analysis
- **🔄 Complete Pipeline**: PCAP ingestion → Feature extraction → ML inference → JSON export

---

## 🔥 Key Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Multi-Layer Detection** | 4-stage pipeline combining signature, anomaly, deep learning, and ensemble methods |
| **Attack Success Analysis** | Determines if detected attacks were successful or blocked based on network evidence |
| **12+ Attack Types** | SQL Injection, XSS, SSRF, Command Injection, LFI/RFI, Directory Traversal, and more |
| **Real-Time Processing** | Asynchronous job processing with live status tracking |
| **PCAP Analysis** | Full PCAP file support with automatic feature extraction |
| **Forensic Export** | Detailed JSON reports with layer-by-layer detection breakdown |
| **Interactive Dashboard** | Modern React UI with live charts, heatmaps, and drill-down capabilities |
| **REST API** | Full-featured FastAPI backend with Swagger/ReDoc documentation |

### Detection Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Signature Filter (Regex-based)                    │
│  ├─ SQL Injection, XSS, Command Injection patterns          │
│  └─ Instant detection of known attack signatures            │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Autoencoder (Anomaly Detection)                   │
│  ├─ Deep autoencoder for zero-day attack detection          │
│  └─ Reconstruction error analysis                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: BiLSTM Classifier (Deep Learning)                 │
│  ├─ Bidirectional LSTM for sequence analysis                │
│  └─ Payload context understanding                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Meta-Classifier (Ensemble)                        │
│  ├─ Random Forest ensemble of all layer outputs             │
│  └─ Final high-confidence verdict                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│                  │         │                  │         │                  │
│  React Frontend  │────────▶│  FastAPI Backend │────────▶│  ML Pipeline     │
│  (Port 5173)     │  HTTP   │  (Port 8000)     │  Async  │  (TensorFlow)    │
│                  │◀────────│                  │◀────────│                  │
└──────────────────┘  JSON   └──────────────────┘ Results └──────────────────┘
        │                            │                            │
        │                            │                            │
        ▼                            ▼                            ▼
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│                  │         │                  │         │                  │
│  UI Components   │         │  PCAP Processor  │         │  4-Layer Engine  │
│  - Upload        │         │  - Flow Extract  │         │  - Signature     │
│  - Analytics     │         │  - Payload Parse │         │  - Autoencoder   │
│  - Visualizations│         │  - Feature Merge │         │  - BiLSTM        │
│  - Drill-down    │         │  - Job Manager   │         │  - Meta-Clf      │
│                  │         │                  │         │                  │
└──────────────────┘         └──────────────────┘         └──────────────────┘
```

### Data Flow

```
PCAP File Upload
    │
    ▼
┌──────────────────────────────────────────────┐
│ Step 1: Flow Feature Extraction (Scapy)     │
│ → 71 CICFlowMeter features                  │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│ Step 2: Payload Feature Extraction          │
│ → HTTP headers, methods, URIs                │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│ Step 3: Feature Merging                      │
│ → Combined flow + payload CSV                │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│ Step 4: ML Inference (4 Layers)             │
│ → Detailed JSON report with predictions      │
└──────────────────────────────────────────────┘
```

---

## 📊 Performance Benchmarks

### Throughput Comparison

Our system outperforms existing solutions in both throughput and accuracy:

| Metric | Our System (CPU) | Our System (GPU) | Classic ML IDS | DL Multi-Attack IDS | Efficient CNN IDS |
|--------|------------------|------------------|----------------|---------------------|-------------------|
| **Throughput** | **1334 pkt/s** | **1378-1768 pkt/s** | <200 pkt/s | 100-400 pkt/s | Hundreds pkt/s |
| **F1-Score** | **≥0.95** | **≥0.95** | 0.90-0.95 | 0.93-0.97 | 0.95-0.98 |
| **Attack Coverage** | **12+ URL attacks** | **12+ URL attacks** | 2-4 web attacks | 5-10 generic | Generic intrusions |
| **Latency (batch=1)** | **270ms** | **~270ms** | Hundreds ms | 300-800ms | 200-500ms |
| **Hardware** | **Commodity CPU** | **Commodity GPU** | CPU only | CPU/GPU | CPU only |
| **CSV/JSON Export** | **✅ Full** | **✅ Full** | Partial | Logs only | No |

### Detailed Performance Metrics

```
┌─────────────────────────────────────────────────────────┐
│ CPU Benchmarks (TensorFlow 2.10, i7/Ryzen equivalent)  │
├─────────────────────────────────────────────────────────┤
│ Model Load Time:        8.2 seconds                     │
│ Single Packet Latency:  270ms                           │
│ Batch=10 Throughput:    1.28 pkt/s                      │
│ Batch=100 Throughput:   12.87 pkt/s                     │
│ Batch=1000 Throughput:  114.74 pkt/s                    │
│ Stress Test Throughput: 1334 pkt/s (continuous)         │
│ CPU Usage:              ~5% average                     │
│ Memory Usage:           ~74 MB                          │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ GPU Benchmarks (NVIDIA CUDA-enabled GPU)               │
├─────────────────────────────────────────────────────────┤
│ Stress Test Throughput: 823-1768 pkt/s                 │
│ Batch Processing:       Up to 10x faster for large     │
│                         batch sizes (>100 packets)      │
└─────────────────────────────────────────────────────────┘
```

### Model Performance Metrics

- **Accuracy**: 96.8%
- **Precision**: 95.2%
- **Recall**: 94.7%
- **F1-Score**: 0.95
- **ROC-AUC**: 0.98

---

## 🛠️ Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.9+ | Core language |
| **FastAPI** | 0.104+ | High-performance async web framework |
| **TensorFlow** | 2.10.1 | Deep learning models |
| **Keras** | 2.10.0 | Neural network API |
| **Scikit-learn** | 1.2.0+ | Traditional ML algorithms |
| **Scapy** | 2.5.0+ | PCAP parsing and analysis |
| **Pandas** | 1.5.0+ | Data manipulation |
| **NumPy** | 1.20-1.24 | Numerical computing |
| **Uvicorn** | 0.24.0+ | ASGI server |



### Machine Learning Models

```
models/
├── autoencoder_model.h5           # Anomaly detection (Layer 2)
├── bilstm_model.h5                # Sequence classifier (Layer 3)
├── meta_classifier.pkl            # Ensemble model (Layer 4)
├── label_encoder.pkl              # Attack type encoder
└── feature_scaler.pkl             # Feature normalization
```

---

## 📥 Installation

### Prerequisites

- **Python 3.9 or higher**
- **Node.js 16+ and npm**
- **Visual C++ Redistributable** (Windows, for TensorFlow)
- **Git**

### 1. Clone the Repository

```bash
git clone https://github.com/Ajayace03/aegis-omega-ids.git
cd aegis-omega-ids
```

### 2. Backend Setup

#### Create Virtual Environment

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

#### Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

#### Verify Models

Ensure the `models/` directory contains:
- `autoencoder_model.h5`
- `bilstm_model.h5`
- `meta_classifier.pkl`
- `label_encoder.pkl`
- `feature_scaler.pkl`

### 3. Frontend Setup

```bash
cd frontend
npm install
```

### 4. Environment Configuration

#### Backend (backend/.env)

```properties
# Optional: Customize paths
MODELS_DIR=./models
UPLOAD_DIR=./uploads
RESULTS_DIR=./inference_results
```

#### Frontend (frontend/.env)

```properties
VITE_API_URL=http://localhost:8000/api
```

---

## 🚀 Quick Start

### 1. Start the Backend

```bash
cd backend

# Development mode (with hot-reload)
uvicorn app:app --reload --host 0.0.0.0 --port 8000

# Production mode (Windows)
.\start_server.bat

# Production mode (Linux/macOS)
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

**Backend will be available at**: `http://localhost:8000`
**API Documentation**: `http://localhost:8000/docs`

### 2. Start the Frontend

```bash
cd frontend

# Development mode
npm run dev

# Production build
npm run build
npm run preview
```

**Frontend will be available at**: `http://localhost:5173`

### 3. Analyze Your First PCAP

1. Open the dashboard at `http://localhost:5173`
2. Click **"Upload PCAP"** or drag-and-drop your `.pcap` file
3. Monitor real-time processing status
4. View detailed analysis results with interactive visualizations

---

## 📚 API Documentation

### Base URL

```
http://localhost:8000/api
```

### Core Endpoints

#### 1. Upload PCAP File

```http
POST /api/upload
Content-Type: multipart/form-data

Request Body:
- file: (binary PCAP file)

Response:
{
  "job_id": "uuid-string",
  "status": "pending",
  "message": "Upload successful"
}
```

#### 2. Check Job Status

```http
GET /api/status/{job_id}

Response:
{
  "job_id": "uuid-string",
  "status": "processing|completed|failed",
  "progress": 75,
  "message": "Step 3/4: Running inference...",
  "created_at": "2025-01-30T10:00:00Z"
}
```

#### 3. Get Analysis Results

```http
GET /api/results/{job_id}

Response:
{
  "job_id": "uuid-string",
  "total_flows": 1000,
  "malicious_count": 127,
  "benign_count": 873,
  "detection_rate": 0.127,
  "results": [
    {
      "flow_id": "flow_0",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.1",
      "prediction_verdict": "MALICIOUS",
      "prediction_confidence": 0.9823,
      "attack_classification": {
        "attack_type": "sql_injection",
        "attack_subtype": "union_based",
        "severity": 9
      },
      "attack_outcome": "BLOCKED",
      "layer_details": {
        "layer1": {"detected": true, "patterns": ["sql_keywords"]},
        "layer2": {"anomaly_score": 0.87},
        "layer3": {"malicious_prob": 0.95},
        "layer4": {"ensemble_score": 0.98}
      }
    }
  ]
}
```

#### 4. Dashboard Endpoints

```http
# Attack statistics
GET /api/dashboard/attack-stats/{job_id}

# Severity heatmap
GET /api/dashboard/severity-heatmap/{job_id}

# Autoencoder analysis
GET /api/dashboard/autoencoder-stats/{job_id}

# Timeline data
GET /api/dashboard/timeline/{job_id}
```

### Interactive API Documentation

Visit `http://localhost:8000/docs` for full Swagger UI documentation with:
- Request/response schemas
- Try-it-out functionality
- Example payloads
- Error responses

---

## 📂 Project Structure

```
aegis-omega-ids/
│
├── backend/                          # FastAPI backend
│   ├── app.py                        # Main application entry point
│   ├── inference.py                  # ML inference pipeline
│   ├── database.py                   # SQLite job storage
│   ├── config.py                     # Configuration management
│   ├── signature_filter.py           # Layer 1: Signature detection
│   ├── autoencoder.py                # Layer 2: Anomaly detection
│   ├── bilstm_classifier.py          # Layer 3: Deep learning
│   ├── meta_classifier.py            # Layer 4: Ensemble
│   ├── requirements.txt              # Python dependencies
│   ├── start_server.bat              # Windows launcher
│   ├── models/                       # Pre-trained ML models
│   │   ├── autoencoder_model.h5
│   │   ├── bilstm_model.h5
│   │   ├── meta_classifier.pkl
│   │   ├── label_encoder.pkl
│   │   └── feature_scaler.pkl
│   ├── uploads/                      # Temporary PCAP storage
│   ├── inference_results/            # JSON output files
│   └── logs/                         # Application logs
│
├── pcap_to_csv/                      # PCAP processing pipeline
│   ├── main_pipeline.py              # Complete PCAP → CSV → Inference
│   ├── flow_extractor.py             # CICFlowMeter feature extraction
│   ├── payload_extractor.py          # HTTP payload parsing
│   └── merger.py                     # Flow + Payload merger
│
├── frontend/                         # React frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── HybridIDSDashboard.jsx      # Main dashboard
│   │   │   ├── ThreatAnalysisDashboard.jsx # Forensic view
│   │   │   └── IDSPerformanceDashboard.jsx # System metrics
│   │   ├── components/               # Reusable UI components
│   │   ├── services/
│   │   │   └── api.js                # API client
│   │   ├── App.jsx                   # Root component
│   │   └── main.jsx                  # Entry point
│   ├── package.json                  # Node dependencies
│   ├── vite.config.js                # Vite configuration
│   └── .env                          # Environment variables
│
├── benchmark/                        # Performance testing
│   ├── system_benchmarking.py        # Automated benchmarking
│   ├── benchmark_results.csv         # CPU results
│   └── benchmark_results_gpu.csv     # GPU results
│
├── captured_data/                    # Sample PCAP files
├── LICENSE                           # MIT License
└── README.md                         # This file
```

---

## 🎯 Detection Capabilities

### Attack Types Supported

| Attack Type | Severity | Detection Method | Example Signatures |
|-------------|----------|------------------|-------------------|
| **SQL Injection** | 🔴 9/10 | Signature + ML | `UNION SELECT`, `' OR 1=1` |
| **Cross-Site Scripting (XSS)** | 🟡 7/10 | Signature + ML | `<script>`, `javascript:` |
| **Command Injection** | 🔴 10/10 | Signature + ML | `\|`, `;`, `&&`, backticks |
| **Local File Inclusion (LFI)** | 🔴 9/10 | Signature + ML | `../`, `/etc/passwd` |
| **Remote File Inclusion (RFI)** | 🔴 9/10 | Signature + ML | `http://`, `file://` |
| **Server-Side Request Forgery (SSRF)** | 🟡 8/10 | ML + Context | Internal IP access patterns |
| **Directory Traversal** | 🟡 8/10 | Signature + ML | `..\\`, `..\` |
| **XXE Injection** | 🔴 9/10 | Signature + ML | `<!ENTITY`, `SYSTEM` |
| **Web Shell** | 🔴 10/10 | Signature + ML | `eval()`, `base64_decode` |
| **Brute Force** | 🟢 6/10 | Behavioral | High failed login rate |
| **Credential Stuffing** | 🟡 7/10 | Behavioral | Multiple account attempts |
| **HTTP Parameter Pollution** | 🟢 6/10 | ML | Duplicate parameters |

### Success Detection Indicators

The system analyzes network evidence to determine attack outcomes:

```python
Success Indicators:
✅ HTTP 200 OK response         (Weight: 0.4)
✅ HTTP 3xx redirect             (Weight: 0.2)
✅ High backward packet count    (Weight: 0.3)
✅ Normal FIN termination        (Weight: 0.15)
✅ No RST flag present           (Weight: 0.15)

Outcome Classification:
- SUCCESSFUL_ATTACK:  Success score > 0.6
- BLOCKED:            Success score ≤ 0.6
- BENIGN:             No attack detected
```

---

## 📈 Dashboard Features

### Overview Page

- **Real-time Statistics**: Total flows, detection rates, attack distribution
- **Attack Type Pie Chart**: Visual breakdown of detected attacks
- **Severity Heatmap**: Attack types vs. severity levels
- **Top Attackers**: Source IPs with most malicious activity
- **Detection Layer Performance**: Layer 1-4 contribution analysis

### Threat Analysis

- **Detailed Flow Table**: Sortable, filterable list of all analyzed packets
- **Search & Filter**: By verdict, attack type, severity, IP address
- **Flow Drill-down**: Click any flow for full forensic details:
  - Network metadata (IPs, ports, protocols)
  - HTTP details (method, URI, headers)
  - Attack classification and severity
  - Layer-by-layer detection breakdown
  - Success analysis with reasoning

### Performance Dashboard

- **System Metrics**: CPU, memory, processing time
- **Autoencoder Analysis**: Reconstruction error distribution
- **BiLSTM Predictions**: Confidence score histograms
- **Timeline View**: Traffic volume and attacks over time

### Features

- 🔄 **Auto-refresh**: Live data updates every 5 seconds
- 📥 **CSV Export**: Download filtered results
- 📊 **Interactive Charts**: Hover tooltips, zoom, pan
- 🎨 **Dark/Light Mode**: (Optional, if implemented)
- 📱 **Responsive Design**: Works on desktop, tablet, mobile

---

## 💻 Development

### Backend Development

#### Running Tests

```bash
cd backend
pytest tests/ -v --cov=.
```

#### Adding New Attack Signatures

Edit `signature_filter.py`:

```python
self.patterns['new_attack'] = [
    (r'attack_pattern1', 'Description'),
    (r'attack_pattern2', 'Description'),
]
```

#### Retraining Models

```bash
# Example: Retrain autoencoder
python models/train_autoencoder.py --data data/training.csv --epochs 100

# Retrain BiLSTM
python models/train_bilstm.py --data data/training.csv --epochs 50
```

### Frontend Development

#### Available Scripts

```bash
npm run dev          # Start dev server
npm run build        # Production build
npm run preview      # Preview production build
npm run lint         # Run ESLint
```

#### Adding New Visualizations

1. Create component in `src/components/`
2. Import required chart library
3. Fetch data from API in parent component
4. Pass data as props

#### Customizing Theme

Edit `src/styles/theme.css`:

```css
:root {
  --primary-color: #3b82f6;
  --danger-color: #ef4444;
  --success-color: #22c55e;
}
```

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines

- Follow PEP 8 for Python code
- Use ESLint rules for JavaScript/React
- Write unit tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

---

## 📖 Citation

If you use this system in your research or project, please cite:

```bibtex
@software{aegis_omega_ids_2025,
  author = {[Ajay Bharathi,Suman,Sridhar,RAhul,Ramaswamy,Abinandhidha]},
  title = {AEGIS-Ω: Advanced Ensemble Guardian for Intelligent Security - Hybrid Multi-Layer Intrusion Detection System},
  year = {2025},
  publisher = {https://github.com/Ajayace03},
  url = {https://github.com/Ajayace03/aegis-omega-ids}
}
```
---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Ajayace03/aegis-omega-ids/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Ajayace03/aegis-omega-ids/discussions)
- **Email**: ajayak0304@gmail.com

---

<div align="center">

**Built with ❤️ for Cybersecurity**

⭐ Star us on GitHub if this project helped you!

[Report Bug](https://github.com/Ajayace03/aegis-omega-ids/issues) • [Request Feature](https://github.com/Ajayace03/aegis-omega-ids/issues) • [Documentation](https://github.com/Ajayace03/aegis-omega-ids/wiki)

</div>
