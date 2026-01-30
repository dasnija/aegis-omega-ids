# Hybrid IDS Dashboard - Security Operations Center (SOC) Interface

## 🚀 Overview
The **Hybrid IDS Dashboard** is a modern, responsive web application designed for security analysts. Built with **React 19** and **Vite**, it provides real-time visualization of network threats, detailed forensic reports, and system performance metrics.

It communicates with the `FastAPI` backend to submit PCAP files for analysis and render the complex results in an intuitive format.

## 🛠️ Technology Stack
-   **Core**: React 19, Vite (Next-gen frontend tooling)
-   **Routing**: React Router DOM v7
-   **Visualization**: Chart.js, Recharts (for attack distribution & timelines)
-   **HTTP Client**: Axios
-   **Styling**: CSS Modules, Lucide React (Icons)
-   **Linting**: ESLint + standard configuration

## 📂 Directory Structure
```
Frontend/
├── src/
│   ├── components/         # Reusable UI components (Buttons, Cards, Loaders)
│   ├── pages/              # Main Route Views
│   │   ├── HybridIDSDashboard.jsx      # Central Command Center
│   │   ├── IDSPerformanceDashboard.jsx # System Metrics View
│   │   └── ThreatAnalysisDashboard.jsx # Deep Dive Forensic View
│   ├── services/
│   │   └── api.js          # Centralized API service configuration
│   ├── styles/             # Global and component-specific styles
│   ├── App.jsx             # Main Application Layout & Routing
│   └── main.jsx            # Entry point
├── public/                 # Static assets
├── .env.example            # Template for environment variables
├── package.json            # Dependency manifest
└── vite.config.js          # Vite build configuration
```

## ⚙️ Installation & Setup

### Prerequisites
-   Node.js 16+
-   npm or yarn

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
Copy the example environment file and configure it for your local setup.
```bash
cp .env.example .env
```
**Default `.env` configuration:**
```properties
VITE_API_URL=http://localhost:8000/api
```

### 3. Start Development Server
```bash
npm run dev
```
The application will launch at `http://localhost:5173`.

## 📦 Building for Production

To create an optimized production build:
```bash
npm run build
```
This will generate a `dist/` directory containing the static assets ready for deployment on Nginx, Apache, or Vercel.

To preview the production build locally:
```bash
npm run preview
```

## 🧩 Key Features
-   **Drag-and-Drop Upload**: Intuitive interface for analyzing new PCAP files.
-   **Real-time Status Tracking**: Polling mechanism to track analysis progress stages.
-   **Interactive Visualizations**:
    -   Attack Type Distribution (Pie/Bar Charts)
    -   Traffic Volume over Time
    -   Confidence Score Heatmaps
-   **Forensic Drill-down**: Detailed view of specific flows, showing original payloads and layer-by-layer detection logic.
