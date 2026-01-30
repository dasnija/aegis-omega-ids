import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:8000/api';

// ============================================================================
// HYBRID IDS DASHBOARD - Complete Single-File Application
// ============================================================================

export default function App() {
  // State management
  const [currentView, setCurrentView] = useState('upload');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');
  const [jobId, setJobId] = useState(null);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const [stats, setStats] = useState(null);

  const pollingRef = useRef(null);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // ===== FILE HANDLING =====
  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    const validExt = ['.pcap', '.pcapng', '.cap'];
    const ext = selectedFile.name.substring(selectedFile.name.lastIndexOf('.')).toLowerCase();

    if (!validExt.includes(ext)) {
      setError('Please select a valid PCAP file (.pcap, .pcapng, .cap)');
      return;
    }

    setFile(selectedFile);
    setError(null);
    setStatus('idle');
  };

  // ===== UPLOAD & PROCESS =====
  const handleUpload = async () => {
    if (!file) {
      setError('Please select a file first');
      return;
    }

    setLoading(true);
    setError(null);
    setStatus('uploading');
    setMessage('Uploading file...');
    setUploadProgress(0);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API_URL}/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => {
          const percent = Math.round((e.loaded * 100) / e.total);
          setUploadProgress(percent);
        },
      });

      const newJobId = response.data.job_id;
      setJobId(newJobId);
      setStatus('processing');
      setMessage('Processing PCAP file...');

      // Start polling for status
      pollingRef.current = setInterval(() => pollStatus(newJobId), 2000);
      pollStatus(newJobId);

    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Upload failed');
      setLoading(false);
      setStatus('failed');
    }
  };

  // ===== POLL JOB STATUS =====
  const pollStatus = async (id) => {
    try {
      const response = await axios.get(`${API_URL}/status/${id}`);
      const job = response.data;

      setProcessingProgress(job.progress || 0);
      setMessage(job.message || 'Processing...');

      if (job.status === 'completed') {
        clearInterval(pollingRef.current);
        setStatus('completed');
        setStats(job.stats);
        setLoading(false);

        // Fetch results
        try {
          const resultsRes = await axios.get(`${API_URL}/results/${id}`);
          setResults(resultsRes.data);
        } catch (e) {
          console.log('Could not fetch detailed results');
        }

        setCurrentView('dashboard');
      } else if (job.status === 'failed') {
        clearInterval(pollingRef.current);
        setError(job.error || 'Processing failed');
        setLoading(false);
        setStatus('failed');
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  };

  // ===== DOWNLOAD HANDLERS =====
  const downloadJSON = async () => {
    if (!jobId) return;
    try {
      const response = await axios.get(`${API_URL}/download/${jobId}`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.download = `results_${jobId}.json`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setError('Download failed');
    }
  };

  const downloadCSV = async () => {
    if (!jobId) return;
    try {
      const response = await axios.get(`${API_URL}/download-merged-csv/${jobId}`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.download = `merged_${jobId}.csv`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setError('Download failed');
    }
  };

  // ===== RESET =====
  const handleReset = () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    setFile(null);
    setLoading(false);
    setStatus('idle');
    setMessage('');
    setJobId(null);
    setError(null);
    setResults(null);
    setStats(null);
    setUploadProgress(0);
    setProcessingProgress(0);
    setCurrentView('upload');
  };

  // ===== RENDER =====
  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <h1>Hybrid IDS</h1>
        </div>

        <nav className="nav">
          <button
            className={`nav-item ${currentView === 'upload' ? 'active' : ''}`}
            onClick={() => setCurrentView('upload')}
          >
            📤 Upload PCAP
          </button>
          <button
            className={`nav-item ${currentView === 'dashboard' ? 'active' : ''}`}
            onClick={() => stats && setCurrentView('dashboard')}
            disabled={!stats}
          >
            📊 Dashboard
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className={`status-badge ${status}`}>
            <span className="status-dot"></span>
            <span>{status.toUpperCase()}</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main">
        {/* Upload View */}
        {currentView === 'upload' && (
          <div className="view upload-view">
            <div className="upload-card">
              <div className="upload-header">
                <h2>🔍 Network Threat Analysis</h2>
                <p>Upload a PCAP file to detect attacks using our Hybrid IDS</p>
              </div>

              {/* File Input */}
              <label className="file-dropzone">
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={handleFileSelect}
                  disabled={loading}
                />
                <div className="dropzone-content">
                  <span className="dropzone-icon">📁</span>
                  <p><strong>Click to select</strong> or drag & drop</p>
                  <span className="dropzone-hint">.pcap, .pcapng, .cap (max 1GB)</span>
                </div>
              </label>

              {/* Selected File */}
              {file && status === 'idle' && (
                <div className="file-info">
                  📦 <strong>{file.name}</strong> ({(file.size / 1024 / 1024).toFixed(2)} MB)
                </div>
              )}

              {/* Progress */}
              {(status === 'uploading' || status === 'processing') && (
                <div className="progress-section">
                  <div className="progress-bar-container">
                    <div
                      className="progress-bar"
                      style={{ width: `${status === 'uploading' ? uploadProgress : processingProgress}%` }}
                    />
                  </div>
                  <p className="progress-message">{message}</p>
                </div>
              )}

              {/* Error */}
              {error && <div className="message error">❌ {error}</div>}

              {/* Success */}
              {status === 'completed' && stats && (
                <div className="message success">
                  ✅ Analysis complete! Found {stats.malicious_count || 0} malicious flows.
                </div>
              )}

              {/* Actions */}
              <div className="actions">
                {status !== 'completed' && (
                  <button
                    className="btn-primary"
                    onClick={handleUpload}
                    disabled={!file || loading}
                  >
                    {loading ? '⏳ Processing...' : '🚀 Analyze PCAP'}
                  </button>
                )}

                {status === 'completed' && (
                  <>
                    <button className="btn-success" onClick={() => setCurrentView('dashboard')}>
                      📊 View Dashboard
                    </button>
                    <button className="btn-primary" onClick={downloadJSON}>
                      📥 Download JSON
                    </button>
                    <button className="btn-secondary" onClick={handleReset}>
                      🔄 New Analysis
                    </button>
                  </>
                )}

                {status === 'failed' && (
                  <button className="btn-secondary" onClick={handleReset}>
                    🔄 Try Again
                  </button>
                )}
              </div>

              {/* Job ID */}
              {jobId && (
                <div className="job-id">
                  <small>Job ID: <code>{jobId}</code></small>
                </div>
              )}
            </div>

            {/* Features */}
            <div className="features">
              <h3>Supported Attack Detection</h3>
              <div className="feature-tags">
                {['SQL Injection', 'XSS', 'SSRF', 'Command Injection', 'Directory Traversal',
                  'LFI/RFI', 'Brute Force', 'XXE', 'Web Shell', 'Credential Stuffing'].map(tag => (
                    <span key={tag} className="tag">{tag}</span>
                  ))}
              </div>
            </div>
          </div>
        )}

        {/* Dashboard View */}
        {currentView === 'dashboard' && stats && (
          <div className="view dashboard-view">
            <div className="dashboard-header">
              <h2>📊 Analysis Results</h2>
              <div className="dashboard-actions">
                <button className="btn-primary" onClick={downloadJSON}>📥 JSON</button>
                <button className="btn-primary" onClick={downloadCSV}>📊 CSV</button>
                <button className="btn-secondary" onClick={handleReset}>🔄 New</button>
              </div>
            </div>

            {/* Stats Cards */}
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-icon">📈</div>
                <div className="stat-info">
                  <span className="stat-label">Total Flows</span>
                  <span className="stat-value">{stats.total_flows || 0}</span>
                </div>
              </div>

              <div className="stat-card danger">
                <div className="stat-icon">⚠️</div>
                <div className="stat-info">
                  <span className="stat-label">Malicious</span>
                  <span className="stat-value">{stats.malicious_count || 0}</span>
                </div>
              </div>

              <div className="stat-card success">
                <div className="stat-icon">✅</div>
                <div className="stat-info">
                  <span className="stat-label">Benign</span>
                  <span className="stat-value">{stats.benign_count || 0}</span>
                </div>
              </div>

              <div className="stat-card warning">
                <div className="stat-icon">🎯</div>
                <div className="stat-info">
                  <span className="stat-label">Detection Rate</span>
                  <span className="stat-value">{stats.detection_rate || 0}%</span>
                </div>
              </div>
            </div>

            {/* Results Table */}
            {results?.predictions && (
              <div className="results-section">
                <h3>🔍 Detected Threats ({results.predictions.filter(p => p.final_verdict === 'MALICIOUS').length})</h3>
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Verdict</th>
                        <th>Attack Type</th>
                        <th>Confidence</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.predictions.slice(0, 50).map((p, i) => (
                        <tr key={i} className={p.final_verdict === 'MALICIOUS' ? 'malicious' : ''}>
                          <td>{i + 1}</td>
                          <td>
                            <span className={`badge ${p.final_verdict?.toLowerCase()}`}>
                              {p.final_verdict}
                            </span>
                          </td>
                          <td>{p.attack_classification?.type || 'N/A'}</td>
                          <td>{((p.confidence_score || 0) * 100).toFixed(1)}%</td>
                          <td>
                            <span className={`risk-badge risk-${p.risk_level?.toLowerCase()}`}>
                              {p.risk_level || 'N/A'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
