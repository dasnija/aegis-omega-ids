# Installation Guide

Complete installation guide for AEGIS-Ω: Hybrid Multi-Layer Intrusion Detection System.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Detailed Backend Setup](#detailed-backend-setup)
4. [Detailed Frontend Setup](#detailed-frontend-setup)
5. [Verification](#verification)
6. [Common Issues](#common-issues)
7. [Docker Installation](#docker-installation)
8. [Production Deployment](#production-deployment)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11, Ubuntu 20.04+, macOS 11+ |
| **CPU** | 4 cores, 2.0 GHz+ |
| **RAM** | 8 GB |
| **Storage** | 10 GB free space |
| **Python** | 3.9 or higher |
| **Node.js** | 16.x or higher |
| **GPU** | Optional (NVIDIA CUDA-compatible for acceleration) |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| **CPU** | 8+ cores, 3.0 GHz+ |
| **RAM** | 16 GB+ |
| **Storage** | SSD with 50 GB+ free space |
| **GPU** | NVIDIA GPU with 4GB+ VRAM (for GPU acceleration) |

---

## Quick Installation

For experienced users who want to get started quickly:

```bash
# Clone repository
git clone https://github.com/yourusername/hybrid-ids.git
cd hybrid-ids

# Backend setup
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# Start backend (Terminal 1)
cd ../backend
uvicorn app:app --reload

# Start frontend (Terminal 2)
cd ../frontend
npm run dev
```

Visit: `http://localhost:5173`

---

## Detailed Backend Setup

### Step 1: Install Python

#### Windows

1. Download Python 3.9+ from [python.org](https://www.python.org/downloads/)
2. Run installer and **check "Add Python to PATH"**
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

#### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install python3.9 python3.9-venv python3-pip
python3 --version
```

#### macOS

```bash
brew install python@3.9
python3 --version
```

### Step 2: Clone Repository

```bash
git clone https://github.com/yourusername/aegis-omega-ids.git
cd aegis-omega-ids
```

### Step 3: Create Virtual Environment

**Why virtual environment?** Isolates project dependencies from system Python.

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate it
# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Linux/macOS
source .venv/bin/activate

# Verify activation (you should see (.venv) in prompt)
which python  # Linux/macOS
where python  # Windows
```

### Step 4: Install Python Dependencies

```bash
# Make sure virtual environment is activated
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt

# This will install:
# - TensorFlow 2.10.1
# - FastAPI and Uvicorn
# - Scikit-learn, Pandas, NumPy
# - Scapy for PCAP processing
# - And more...
```

**Note**: TensorFlow installation may take 5-10 minutes depending on your internet speed.

#### Troubleshooting TensorFlow Installation

**Windows**: If you get errors about Visual C++:
```bash
# Download and install Visual C++ Redistributable:
# https://aka.ms/vs/17/release/vc_redist.x64.exe
```

**Linux**: If you get errors:
```bash
sudo apt-get install python3-dev build-essential
pip install --upgrade pip setuptools wheel
pip install tensorflow==2.10.1
```

**macOS (M1/M2)**: Use TensorFlow Metal:
```bash
pip install tensorflow-macos==2.10.0
pip install tensorflow-metal
```

### Step 5: Download Pre-trained Models

Models are required for the system to function. Download them from:

```bash
# Option 1: Download from releases page
wget https://github.com/yourusername/aegis-omega-ids/releases/download/v1.0.0/models.zip
unzip models.zip -d backend/

# Option 2: Use provided script
python scripts/download_models.py

# Verify models are present
ls backend/models/
# Should see:
# - autoencoder_model.h5
# - bilstm_model.h5
# - meta_classifier.pkl
# - label_encoder.pkl
# - feature_scaler.pkl
```

### Step 6: Configure Backend

Create `.env` file in `backend/` directory:

```bash
cd backend
cp .env.example .env
```

Edit `.env`:

```properties
# Backend Configuration
DEBUG=True
LOG_LEVEL=INFO

# Directories
MODELS_DIR=./models
UPLOAD_DIR=./uploads
RESULTS_DIR=./inference_results
TEMP_DIR=./temp_processing

# API Settings
API_HOST=0.0.0.0
API_PORT=8000
MAX_UPLOAD_SIZE_MB=100

# CORS (update for production)
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

### Step 7: Test Backend

```bash
# Make sure you're in backend/ with activated virtual environment
python -c "import tensorflow as tf; print(f'TensorFlow version: {tf.__version__}')"
python -c "import fastapi; print('FastAPI imported successfully')"

# Test model loading
python -c "from inference import EnhancedInferencePipeline; p = EnhancedInferencePipeline(); print('Models loaded!')"
```

---

## Detailed Frontend Setup

### Step 1: Install Node.js

#### Windows

1. Download from [nodejs.org](https://nodejs.org/)
2. Run installer (choose LTS version)
3. Verify:
   ```cmd
   node --version
   npm --version
   ```

#### Linux (Ubuntu/Debian)

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
npm --version
```

#### macOS

```bash
brew install node@18
node --version
npm --version
```

### Step 2: Install Frontend Dependencies

```bash
cd frontend

# Install all packages
npm install

# This installs:
# - React 19
# - Vite
# - React Router
# - Recharts, Chart.js
# - Axios
# - And more...
```

### Step 3: Configure Frontend

Create `.env` file in `frontend/` directory:

```bash
cd frontend
cp .env.example .env
```

Edit `.env`:

```properties
# Backend API URL
VITE_API_URL=http://localhost:8000/api

# Optional: Enable debug mode
VITE_DEBUG=true
```

### Step 4: Test Frontend

```bash
# Build test (check for errors)
npm run build

# If successful, clean up
rm -rf dist

# Start dev server
npm run dev
```

You should see:

```
  VITE v5.x.x  ready in XXX ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.x.x:5173/
```

---

## Verification

### Complete System Test

1. **Start Backend** (Terminal 1):
   ```bash
   cd backend
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   uvicorn app:app --reload
   ```
   
   Expected output:
   ```
   INFO:     Uvicorn running on http://0.0.0.0:8000
   INFO:     Application startup complete.
   ```

2. **Start Frontend** (Terminal 2):
   ```bash
   cd frontend
   npm run dev
   ```
   
   Expected output:
   ```
   ➜  Local:   http://localhost:5173/
   ```

3. **Open Browser**: Visit `http://localhost:5173`

4. **Check API Docs**: Visit `http://localhost:8000/docs`

5. **Test with Sample PCAP**:
   - Download sample: `wget https://example.com/sample.pcap`
   - Upload through UI
   - Verify processing completes
   - Check results display

### Health Check

Test API endpoints manually:

```bash
# Health check
curl http://localhost:8000/api/health

# Expected response:
# {"status":"healthy","version":"1.0.0"}
```

---

## Common Issues

### Issue 1: Port Already in Use

**Error**: `Address already in use`

**Solution**:
```bash
# Find process using port 8000
# Linux/macOS
lsof -i :8000
kill -9 <PID>

# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Or use different port
uvicorn app:app --port 8001
```

### Issue 2: Module Not Found

**Error**: `ModuleNotFoundError: No module named 'tensorflow'`

**Solution**:
```bash
# Verify virtual environment is activated
which python  # Should show .venv/bin/python

# If not activated:
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Reinstall requirements
pip install -r requirements.txt
```

### Issue 3: CORS Errors in Browser

**Error**: `Access to fetch blocked by CORS policy`

**Solution**:
```python
# In backend/app.py, update CORS settings:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Issue 4: Out of Memory

**Error**: `MemoryError` or system freeze

**Solution**:
```python
# In backend/config.py, reduce batch size:
INFERENCE_BATCH_SIZE = 32  # Default: 100

# Or use smaller models
# Or add swap space (Linux):
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue 5: GPU Not Detected

**Error**: `Could not load dynamic library 'cudart64_110.dll'`

**Solution**:
```bash
# Install CUDA Toolkit 11.2 and cuDNN 8.1
# From: https://developer.nvidia.com/cuda-downloads

# Verify GPU is available:
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"

# If no GPU needed, TensorFlow will use CPU automatically
```

---

## Docker Installation

For isolated and reproducible deployments:

### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/hybrid-ids.git
cd hybrid-ids

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Access:
- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

### Option 2: Manual Docker Build

```bash
# Build backend
cd backend
docker build -t hybrid-ids-backend .
docker run -p 8000:8000 hybrid-ids-backend

# Build frontend
cd frontend
docker build -t hybrid-ids-frontend .
docker run -p 3000:80 hybrid-ids-frontend
```

---

## Production Deployment

### Using Nginx Reverse Proxy

1. **Install Nginx**:
   ```bash
   sudo apt install nginx
   ```

2. **Configure Nginx** (`/etc/nginx/sites-available/aegis-omega-ids`):
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;
   
       # Frontend
       location / {
           root /var/www/aegis-omega-ids/frontend/dist;
           try_files $uri $uri/ /index.html;
       }
   
       # Backend API
       location /api {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Enable site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/hybrid-ids /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

### Using Systemd Service

Create `/etc/systemd/system/aegis-omega-backend.service`:

```ini
[Unit]
Description=AEGIS-Ω Backend
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/aegis-omega-ids/backend
Environment="PATH=/opt/aegis-omega-ids/backend/.venv/bin"
ExecStart=/opt/aegis-omega-ids/backend/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable aegis-omega-backend
sudo systemctl start aegis-omega-backend
sudo systemctl status aegis-omega-backend
```

### SSL/TLS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## Next Steps

After successful installation:

1. **Read the User Guide**: `docs/USER_GUIDE.md`
2. **Try Example PCAPs**: `captured_data/samples/`
3. **Configure Detection Rules**: `backend/signature_filter.py`
4. **Customize Dashboard**: `frontend/src/pages/`
5. **Set Up Monitoring**: Check `docs/MONITORING.md`

---

## Support

If you encounter issues not covered here:

- 📖 Check [FAQ](docs/FAQ.md)
- 🐛 Open an [Issue](https://github.com/yourusername/aegis-omega-ids/issues)
- 💬 Join [Discussions](https://github.com/yourusername/aegis-omega-ids/discussions)
- 📧 Email: support@example.com

---

*Last updated: January 30, 2025*
