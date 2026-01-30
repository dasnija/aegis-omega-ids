import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, Upload, Activity, AlertTriangle, Network,
  Database, Eye, Download, Search, ChevronRight,
  RefreshCw, CheckCircle, BarChart3, Layers, Target,
  Clock, Globe, Zap, X, TrendingUp, FileText, Server, Gauge
} from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line,
  AreaChart, Area
} from 'recharts';
import { pcapService, dashboardService, dbService } from '../services/api';
import IDSPerformanceDashboard from './IDSPerformanceDashboard';

// Attack type colors for charts
const ATTACK_COLORS = {
  xss: '#ef4444', ssrf: '#f97316', bruteforce: '#f59e0b',
  sql_injection: '#eab308', command_injection: '#84cc16',
  directory_traversal: '#22c55e', lfi_rfi: '#10b981',
  parameter_pollution: '#14b8a6', xxe: '#06b6d4',
  web_shell: '#0ea5e9', typosquatting: '#3b82f6',
  credential_stuffing: '#6366f1', unknown: '#94a3b8'
};

const VERDICT_COLORS = { MALICIOUS: '#ef4444', BENIGN: '#10b981' };

const HybridIDSDashboard = () => {
  // View and UI state
  const [currentView, setCurrentView] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Job management state
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState(null);

  // Dashboard data
  const [dashboardData, setDashboardData] = useState(null);
  const [flowAnalysis, setFlowAnalysis] = useState(null);
  const [layerDetails, setLayerDetails] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [predictions, setPredictions] = useState([]);
  const [attackStats, setAttackStats] = useState(null);
  const [heatmapData, setHeatmapData] = useState(null);
  const [autoencoderStats, setAutoencoderStats] = useState(null);

  // Filters
  const [filterVerdict, setFilterVerdict] = useState('all');
  const [filterAttackType, setFilterAttackType] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Modal state
  const [selectedFlow, setSelectedFlow] = useState(null);

  // Upload state
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);

  // Load jobs on mount
  useEffect(() => {
    loadJobs();
  }, []);

  // Load dashboard data when job is selected
  useEffect(() => {
    if (selectedJobId) {
      loadDashboardData(selectedJobId);
    }
  }, [selectedJobId]);

  const loadJobs = async () => {
    try {
      const response = await dbService.getAllJobs();
      const jobList = response.data?.jobs || [];
      setJobs(jobList);

      // Auto-select first completed job
      if (jobList.length > 0 && !selectedJobId) {
        const completedJob = jobList.find(j => j.status === 'completed') || jobList[0];
        if (completedJob?.job_id) {
          setSelectedJobId(completedJob.job_id);
        }
      }
    } catch (err) {
      console.error('Failed to load jobs:', err);
    }
  };

  const loadDashboardData = async (jobId) => {
    if (!jobId) return;

    setLoading(true);
    setError(null);

    try {
      // Fetch all dashboard data in parallel
      const [summaryRes, flowRes, layerRes, timelineRes, predictionsRes, attackStatsRes, heatmapRes, aeStatsRes] = await Promise.all([
        dashboardService.getDashboardSummary(jobId).catch(e => ({ data: null })),
        dashboardService.getFlowAnalysis(jobId).catch(e => ({ data: null })),
        dashboardService.getLayerDetails(jobId).catch(e => ({ data: null })),
        dashboardService.getTimelineData(jobId).catch(e => ({ data: null })),
        dbService.getPredictions(jobId).catch(e => ({ data: { predictions: [] } })),
        dashboardService.getAttackStats(jobId).catch(e => ({ data: null })),
        dashboardService.getSeverityHeatmap(jobId).catch(e => ({ data: null })),
        dashboardService.getAutoencoderStats(jobId).catch(e => ({ data: null }))
      ]);

      setDashboardData(summaryRes.data);
      setFlowAnalysis(flowRes.data);
      setLayerDetails(layerRes.data);
      setTimelineData(timelineRes.data);
      setPredictions(predictionsRes.data?.predictions || []);
      setAttackStats(attackStatsRes.data);
      setHeatmapData(heatmapRes.data);
      setAutoencoderStats(aeStatsRes.data);
      console.log('Autoencoder stats loaded:', aeStatsRes.data);

    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError('Failed to load dashboard data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll job status during upload
  const pollJobStatus = async (jobId) => {
    const maxAttempts = 120; // 10 minutes max
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await pcapService.getStatus(jobId);
        const status = response.data;

        setUploadProgress(status.progress || 0);
        setUploadStatus(status.message);

        if (status.status === 'completed') {
          return status;
        } else if (status.status === 'failed') {
          throw new Error(status.error || 'Processing failed');
        }

        await new Promise(resolve => setTimeout(resolve, 3000));
        attempts++;
      } catch (err) {
        console.error('Status poll error:', err);
        throw err;
      }
    }

    throw new Error('Processing timeout');
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadProgress(0);
    setUploadStatus('Uploading file...');
    setError(null);

    try {
      const response = await pcapService.upload(file, (progress) => {
        setUploadProgress(Math.min(progress, 10));
      });

      const jobId = response.data.job_id;
      await pollJobStatus(jobId);

      // Reload jobs and select the new one
      await loadJobs();
      setSelectedJobId(jobId);
      setCurrentView('overview');

    } catch (err) {
      console.error('Upload failed:', err);
      setError(err.message || 'Upload failed. Please try again.');
    } finally {
      setIsUploading(false);
      setUploadStatus(null);
    }
  };

  // Calculate statistics from dashboard data
  const stats = {
    totalFlows: dashboardData?.total_predictions || 0,
    malicious: dashboardData?.verdicts?.MALICIOUS || 0,
    benign: dashboardData?.verdicts?.BENIGN || 0,
  };

  // Prepare chart data
  const attackDistribution = dashboardData?.attack_stats?.map(stat => ({
    name: stat.attack_type?.replace(/_/g, ' ').toUpperCase() || 'Unknown',
    value: stat.count,
    rawName: stat.attack_type
  })) || [];

  const verdictDistribution = [
    { name: 'Malicious', value: stats.malicious, color: VERDICT_COLORS.MALICIOUS },
    { name: 'Benign', value: stats.benign, color: VERDICT_COLORS.BENIGN },
  ].filter(d => d.value > 0);

  // HTTP Methods chart data
  const methodChartData = flowAnalysis?.method_distribution
    ? Object.entries(flowAnalysis.method_distribution).map(([name, value]) => ({ name, value }))
    : [];

  // Host distribution chart data
  const hostChartData = flowAnalysis?.host_distribution
    ? Object.entries(flowAnalysis.host_distribution).slice(0, 8).map(([name, value]) => ({
      name: name.length > 20 ? name.substring(0, 20) + '...' : name,
      value
    }))
    : [];

  // User agent chart data
  const userAgentData = flowAnalysis?.user_agent_distribution
    ? Object.entries(flowAnalysis.user_agent_distribution).slice(0, 6).map(([name, value]) => ({
      name: name.length > 25 ? name.substring(0, 25) + '...' : name,
      value
    }))
    : [];

  // Timeline chart data
  const timelineChartData = timelineData?.timeline || [];

  // Filter predictions
  const filteredPredictions = predictions.filter(p => {
    const matchesVerdict = filterVerdict === 'all' || p.final_verdict === filterVerdict;
    const matchesAttack = filterAttackType === 'all' || p.attack_type === filterAttackType;
    const matchesSearch = !searchQuery ||
      p.packet_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.attack_type?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesVerdict && matchesAttack && matchesSearch;
  });

  // Get unique attack types
  const uniqueAttackTypes = [...new Set(predictions.map(p => p.attack_type).filter(Boolean))];

  return (
    <div className="app">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="logo">
          <Shield size={28} strokeWidth={2.5} />
          <div className="logo-text">
            <h1>AEGIS-Ω</h1>
            <p>Hybrid Multi-Layer Intrusion Detection System</p>
          </div>
        </div>

        <nav className="nav">
          {[
            { id: 'upload', icon: Upload, label: 'Upload PCAP' },
            { id: 'overview', icon: Activity, label: 'Overview' },
            { id: 'threats', icon: AlertTriangle, label: 'Threat Analysis' },
            { id: 'network', icon: Network, label: 'Flow Analysis' },
            { id: 'layers', icon: Layers, label: 'Layer Analysis' },
            { id: 'database', icon: Database, label: 'Predictions' },
            { id: 'performance', icon: Gauge, label: 'Performance' },
          ].map(item => (
            <button
              key={item.id}
              className={`nav-item ${currentView === item.id ? 'active' : ''}`}
              onClick={() => setCurrentView(item.id)}
            >
              <item.icon size={20} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        {/* Job Selector */}
        {jobs.length > 0 && (
          <div className="job-selector">
            <label>Select Analysis:</label>
            <select
              value={selectedJobId || ''}
              onChange={(e) => setSelectedJobId(e.target.value)}
            >
              {jobs.map(job => (
                <option key={job.job_id} value={job.job_id}>
                  {job.original_filename || job.job_id} ({job.status})
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="sidebar-footer">
          <div className="status-badge">
            <div className="status-dot"></div>
            <div>
              <div className="status-label">System Status</div>
              <div className="status-value">Online</div>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="main">
        {error && (
          <div className="error-banner">
            <AlertTriangle size={20} />
            <span>{error}</span>
            <button onClick={() => setError(null)}><X size={16} /></button>
          </div>
        )}

        {loading ? (
          <div className="loading">
            <RefreshCw size={48} className="spinner" />
            <p>Loading analysis data...</p>
          </div>
        ) : (
          <>
            {/* ========== UPLOAD VIEW ========== */}
            {currentView === 'upload' && (
              <div className="view">
                <div className="upload-card">
                  <div className="upload-header">
                    <Upload size={48} />
                    <h2>Upload PCAP File</h2>
                    <p>Upload network capture files for comprehensive URL-based attack detection</p>
                  </div>

                  {!isUploading ? (
                    <>
                      <label className="dropzone">
                        <input
                          type="file"
                          accept=".pcap,.pcapng,.cap"
                          onChange={handleFileUpload}
                          style={{ display: 'none' }}
                        />
                        <Upload size={40} />
                        <p>Click to browse or drag and drop</p>
                        <span>Supports .pcap, .pcapng, .cap files</span>
                      </label>

                      <div className="attack-types">
                        <h4>Supported Attack Detection</h4>
                        <div className="tags">
                          {['SQL Injection', 'XSS', 'SSRF', 'Command Injection', 'Directory Traversal',
                            'LFI/RFI', 'Brute Force', 'XXE', 'Web Shell', 'Typosquatting'].map(tag => (
                              <span key={tag} className="tag">{tag}</span>
                            ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="upload-progress">
                      <div className="progress-info">
                        <span>{uploadStatus || 'Processing...'}</span>
                        <span>{uploadProgress}%</span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${uploadProgress}%` }} />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ========== OVERVIEW VIEW ========== */}
            {currentView === 'overview' && (
              <div className="view">
                <div className="page-header">
                  <h2>Overview Dashboard</h2>
                  <button className="btn-secondary" onClick={() => loadDashboardData(selectedJobId)}>
                    <RefreshCw size={18} />
                    Refresh
                  </button>
                </div>

                {!dashboardData ? (
                  <div className="no-data-message">
                    <Database size={48} />
                    <h3>No Analysis Data</h3>
                    <p>Upload a PCAP file to see analysis results</p>
                    <button className="btn-primary" onClick={() => setCurrentView('upload')}>
                      <Upload size={18} /> Upload PCAP
                    </button>
                  </div>
                ) : (
                  <>
                    {/* KPI Cards */}
                    <div className="stats-grid">
                      <div className="stat-card">
                        <div className="stat-header">
                          <Activity size={22} />
                          <span>Total Flows</span>
                        </div>
                        <div className="stat-value">{stats.totalFlows.toLocaleString()}</div>
                      </div>

                      <div className="stat-card warning">
                        <div className="stat-header">
                          <Target size={22} />
                          <span>Attacks Orchestrated</span>
                        </div>
                        <div className="stat-value">{attackStats?.attacks_attempted?.toLocaleString() || 0}</div>
                        <div className="stat-sub">
                          {attackStats?.attempt_rate || 0}% of traffic
                        </div>
                      </div>

                      <div className="stat-card danger">
                        <div className="stat-header">
                          <AlertTriangle size={22} />
                          <span>Attacks Successful</span>
                        </div>
                        <div className="stat-value">{attackStats?.attacks_successful?.toLocaleString() || 0}</div>
                        <div className="stat-sub">
                          {attackStats?.success_rate || 0}% success rate
                        </div>
                      </div>

                      <div className="stat-card success">
                        <div className="stat-header">
                          <Shield size={22} />
                          <span>Attacks Attempt</span>
                        </div>
                        <div className="stat-value">{attackStats?.attacks_blocked?.toLocaleString() || 0}</div>
                        <div className="stat-sub">
                          {attackStats?.attacks_attempted > 0
                            ? (100 - (attackStats?.success_rate || 0)).toFixed(1)
                            : 0}% blocked
                        </div>
                      </div>
                    </div>

                    {/* Charts Row */}
                    <div className="charts-row">
                      {/* Verdict Distribution Pie Chart */}
                      <div className="chart-card">
                        <h3>Traffic Verdict Distribution</h3>
                        <p className="subtitle">Malicious vs Benign traffic analysis</p>
                        {verdictDistribution.length > 0 ? (
                          <ResponsiveContainer width="100%" height={280}>
                            <PieChart>
                              <Pie
                                data={verdictDistribution}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                                outerRadius={90}
                                dataKey="value"
                              >
                                {verdictDistribution.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                              </Pie>
                              <Tooltip />
                              <Legend />
                            </PieChart>
                          </ResponsiveContainer>
                        ) : (
                          <div className="no-data">No data available</div>
                        )}
                      </div>

                      {/* Attack Type Distribution Pie Chart */}
                      <div className="chart-card">
                        <h3>Attack Type Distribution</h3>
                        <p className="subtitle">Detected attack categories</p>
                        {attackDistribution.length > 0 ? (
                          <ResponsiveContainer width="100%" height={280}>
                            <PieChart>
                              <Pie
                                data={attackDistribution}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, percent }) => `${(percent * 100).toFixed(0)}%`}
                                outerRadius={90}
                                dataKey="value"
                              >
                                {attackDistribution.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={ATTACK_COLORS[entry.rawName] || '#6366f1'} />
                                ))}
                              </Pie>
                              <Tooltip />
                              <Legend />
                            </PieChart>
                          </ResponsiveContainer>
                        ) : (
                          <div className="no-data">No attacks detected</div>
                        )}
                      </div>
                    </div>

                    {/* HTTP Methods Bar Chart */}
                    {methodChartData.length > 0 && (
                      <div className="chart-card full-width">
                        <h3>HTTP Method Distribution</h3>
                        <p className="subtitle">Distribution of HTTP request methods</p>
                        <ResponsiveContainer width="100%" height={250}>
                          <BarChart data={methodChartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="value" fill="#3b82f6" radius={[8, 8, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    )}

                    {/* Detection Timeline */}
                    {timelineChartData.length > 0 && (
                      <div className="chart-card full-width">
                        <h3>Detection Timeline</h3>
                        <p className="subtitle">Cumulative malicious vs benign detections</p>
                        <ResponsiveContainer width="100%" height={250}>
                          <AreaChart data={timelineChartData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="batch" />
                            <YAxis />
                            <Tooltip />
                            <Area type="monotone" dataKey="malicious" stackId="1" stroke="#ef4444" fill="#fecaca" name="Malicious" />
                            <Area type="monotone" dataKey="benign" stackId="1" stroke="#10b981" fill="#d1fae5" name="Benign" />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    )}

                    {/* Severity Heatmap */}
                    {heatmapData && heatmapData.attack_types?.length > 0 ? (
                      <div className="chart-card full-width">
                        <h3>Attack Severity Heatmap</h3>
                        <p className="subtitle">Attack types vs severity levels (darker = higher count)</p>
                        <div className="heatmap-container">
                          <div className="heatmap-grid" style={{
                            display: 'grid',
                            gridTemplateColumns: `120px repeat(11, 1fr)`,
                            gap: '2px',
                            marginTop: '16px'
                          }}>
                            {/* Header row */}
                            <div className="heatmap-cell header"></div>
                            {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(sev => (
                              <div key={`header-${sev}`} className="heatmap-cell header" style={{
                                textAlign: 'center',
                                fontSize: '12px',
                                fontWeight: '600',
                                padding: '8px 4px',
                                color: '#64748b'
                              }}>
                                {sev}
                              </div>
                            ))}

                            {/* Data rows */}
                            {heatmapData.attack_types.map(attackType => (
                              <React.Fragment key={attackType}>
                                <div className="heatmap-label" style={{
                                  fontSize: '12px',
                                  fontWeight: '500',
                                  padding: '8px',
                                  display: 'flex',
                                  alignItems: 'center',
                                  textTransform: 'capitalize'
                                }}>
                                  {attackType.replace(/_/g, ' ')}
                                </div>
                                {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(sev => {
                                  const cellData = heatmapData.heatmap_data.find(
                                    d => d.attack_type === attackType && d.severity === sev
                                  );
                                  const count = cellData?.count || 0;
                                  const maxCount = heatmapData.max_count || 1;
                                  const intensity = count / maxCount;

                                  // Red gradient from light to dark
                                  const getHeatColor = (val) => {
                                    if (val === 0) return '#fff5f5';
                                    if (val < 0.2) return '#fecaca';
                                    if (val < 0.4) return '#fca5a5';
                                    if (val < 0.6) return '#f87171';
                                    if (val < 0.8) return '#ef4444';
                                    return '#b91c1c';
                                  };

                                  return (
                                    <div
                                      key={`${attackType}-${sev}`}
                                      className="heatmap-cell"
                                      style={{
                                        backgroundColor: getHeatColor(intensity),
                                        padding: '8px',
                                        textAlign: 'center',
                                        fontSize: '11px',
                                        fontWeight: count > 0 ? '600' : '400',
                                        color: intensity > 0.5 ? '#fff' : '#64748b',
                                        borderRadius: '4px',
                                        minHeight: '36px',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        transition: 'transform 0.2s',
                                        cursor: 'default'
                                      }}
                                      title={`${attackType} - Severity ${sev}: ${count} occurrences`}
                                    >
                                      {count > 0 ? count : ''}
                                    </div>
                                  );
                                })}
                              </React.Fragment>
                            ))}
                          </div>

                          {/* Legend */}
                          <div className="heatmap-legend" style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '8px',
                            marginTop: '16px',
                            fontSize: '12px',
                            color: '#64748b'
                          }}>
                            <span>Low</span>
                            <div style={{ display: 'flex', gap: '2px' }}>
                              {['#fff5f5', '#fecaca', '#fca5a5', '#f87171', '#ef4444', '#b91c1c'].map((color, i) => (
                                <div key={i} style={{
                                  width: '24px',
                                  height: '16px',
                                  backgroundColor: color,
                                  borderRadius: '2px'
                                }} />
                              ))}
                            </div>
                            <span>High</span>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="chart-card full-width">
                        <h3>Attack Severity Heatmap</h3>
                        <p className="subtitle">{heatmapData ? 'No attack types detected' : 'Loading heatmap data...'}</p>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ========== NETWORK/FLOW ANALYSIS VIEW ========== */}
            {currentView === 'network' && (
              <div className="view">
                <div className="page-header">
                  <h2>Network Flow Analysis</h2>
                  <button className="btn-secondary" onClick={() => loadDashboardData(selectedJobId)}>
                    <RefreshCw size={18} />
                  </button>
                </div>

                {!flowAnalysis ? (
                  <div className="no-data-message">
                    <Network size={48} />
                    <h3>No Flow Data</h3>
                    <p>Select a completed analysis to view flow statistics</p>
                  </div>
                ) : (
                  <>
                    {/* Flow Stats Cards */}
                    <div className="stats-grid">
                      <div className="stat-card">
                        <div className="stat-header"><Globe size={22} /><span>Total Flows</span></div>
                        <div className="stat-value">{flowAnalysis.flow_stats?.total_flows?.toLocaleString() || 0}</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-header"><Clock size={22} /><span>Avg Duration</span></div>
                        <div className="stat-value">{(flowAnalysis.flow_stats?.avg_flow_duration || 0).toFixed(4)}s</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-header"><Activity size={22} /><span>Avg Packet Size</span></div>
                        <div className="stat-value">{(flowAnalysis.flow_stats?.avg_packet_length || 0).toFixed(1)} bytes</div>
                      </div>
                      <div className="stat-card info">
                        <div className="stat-header"><FileText size={22} /><span>HTTP Flows</span></div>
                        <div className="stat-value">{flowAnalysis.flow_stats?.http_flows?.toLocaleString() || 0}</div>
                      </div>
                    </div>

                    <div className="charts-row">
                      {/* Host Distribution */}
                      {hostChartData.length > 0 && (
                        <div className="chart-card">
                          <h3>Top Hosts</h3>
                          <p className="subtitle">Most requested hosts</p>
                          <ResponsiveContainer width="100%" height={280}>
                            <BarChart data={hostChartData} layout="vertical">
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis type="number" />
                              <YAxis dataKey="name" type="category" width={120} />
                              <Tooltip />
                              <Bar dataKey="value" fill="#8b5cf6" radius={[0, 8, 8, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}

                      {/* User Agent Distribution */}
                      {userAgentData.length > 0 && (
                        <div className="chart-card">
                          <h3>User Agent Distribution</h3>
                          <p className="subtitle">Top user agents detected</p>
                          <ResponsiveContainer width="100%" height={280}>
                            <BarChart data={userAgentData} layout="vertical">
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis type="number" />
                              <YAxis dataKey="name" type="category" width={150} />
                              <Tooltip />
                              <Bar dataKey="value" fill="#06b6d4" radius={[0, 8, 8, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                    </div>

                    {/* Source/Dest IP Distribution */}
                    <div className="charts-row">
                      {flowAnalysis.src_ip_distribution && Object.keys(flowAnalysis.src_ip_distribution).length > 0 && (
                        <div className="chart-card">
                          <h3>Source IP Distribution</h3>
                          <p className="subtitle">Top source IP addresses</p>
                          <ResponsiveContainer width="100%" height={250}>
                            <BarChart
                              data={Object.entries(flowAnalysis.src_ip_distribution).slice(0, 6).map(([ip, count]) => ({ ip, count }))}
                            >
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="ip" />
                              <YAxis />
                              <Tooltip />
                              <Bar dataKey="count" fill="#10b981" radius={[8, 8, 0, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}

                      {flowAnalysis.dst_ip_distribution && Object.keys(flowAnalysis.dst_ip_distribution).length > 0 && (
                        <div className="chart-card">
                          <h3>Destination IP Distribution</h3>
                          <p className="subtitle">Top destination IP addresses</p>
                          <ResponsiveContainer width="100%" height={250}>
                            <BarChart
                              data={Object.entries(flowAnalysis.dst_ip_distribution).slice(0, 6).map(([ip, count]) => ({ ip, count }))}
                            >
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="ip" />
                              <YAxis />
                              <Tooltip />
                              <Bar dataKey="count" fill="#f59e0b" radius={[8, 8, 0, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ========== LAYERS VIEW (Redesigned) ========== */}
            {currentView === 'layers' && (
              <div className="view">
                <div className="page-header">
                  <h2>Multi-Layer Detection Analysis</h2>
                  <button className="btn-secondary" onClick={() => loadDashboardData(selectedJobId)}>
                    <RefreshCw size={18} />
                  </button>
                </div>

                {predictions.length === 0 ? (
                  <div className="no-data-message">
                    <Layers size={48} />
                    <h3>No Layer Data</h3>
                    <p>Select a completed analysis to view layer details</p>
                  </div>
                ) : (() => {
                  // Get threshold from autoencoderStats (or use a default)
                  const aeThreshold = autoencoderStats?.threshold || 0.001;

                  // Calculate layer statistics from predictions
                  // Layer 2: Count packets where reconstruction_error > threshold
                  const layer1Detections = predictions.filter(p => p.layer1_detected).length;
                  const layer2Detections = predictions.filter(p => {
                    const error = p.layer2_reconstruction_error || 0;
                    return error > aeThreshold;
                  }).length;
                  const layer3Detections = predictions.filter(p => p.layer3_detected).length;
                  const totalDetections = layer1Detections + layer2Detections + layer3Detections || 1;

                  const layer1Percent = ((layer1Detections / totalDetections) * 100).toFixed(1);
                  const layer2Percent = ((layer2Detections / totalDetections) * 100).toFixed(1);
                  const layer3Percent = ((layer3Detections / totalDetections) * 100).toFixed(1);

                  // Calculate overall stats - total attacks detected by meta classifier
                  const maliciousCount = predictions.filter(p => p.final_verdict === 'MALICIOUS').length;

                  // Prepare line chart data (sample 50 packets for performance)
                  // Normalize reconstruction_error to 0-1 range for visualization
                  const maxError = Math.max(...predictions.map(p => p.layer2_reconstruction_error || 0), aeThreshold * 2);
                  const sampleSize = Math.min(50, predictions.length);
                  const step = Math.max(1, Math.floor(predictions.length / sampleSize));
                  const lineChartData = predictions
                    .filter((_, i) => i % step === 0)
                    .slice(0, sampleSize)
                    .map((p, i) => ({
                      index: i + 1,
                      layer1: p.layer1_confidence || (p.layer1_detected ? 0.9 : 0.1),
                      layer2: maxError > 0 ? Math.min(1, (p.layer2_reconstruction_error || 0) / maxError) : 0,
                      layer3: p.layer3_prob_malicious || 0
                    }));

                  // Contribution data for bar chart
                  const contributionData = [
                    { layer: 'Layer 1: Signature', detections: layer1Detections, percent: parseFloat(layer1Percent), color: '#3b82f6' },
                    { layer: 'Layer 2: Autoencoder', detections: layer2Detections, percent: parseFloat(layer2Percent), color: '#8b5cf6' },
                    { layer: 'Layer 3: BiLSTM', detections: layer3Detections, percent: parseFloat(layer3Percent), color: '#f59e0b' }
                  ];

                  return (
                    <>
                      {/* Meta Classifier - The Judge - Simplified */}
                      <div className="meta-classifier-judge" style={{
                        background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)',
                        borderRadius: '16px',
                        padding: '32px',
                        marginBottom: '24px',
                        color: 'white',
                        textAlign: 'center',
                        boxShadow: '0 10px 40px rgba(0,0,0,0.2)'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', marginBottom: '16px' }}>
                          <Shield size={40} style={{ color: '#fbbf24' }} />
                          <h2 style={{ margin: 0, fontSize: '28px' }}>META CLASSIFIER</h2>
                        </div>
                        <div style={{ fontSize: '72px', fontWeight: '800', color: '#ef4444' }}>
                          {maliciousCount}
                        </div>
                        <div style={{ fontSize: '20px', opacity: 0.9 }}>
                          ATTACKS DETECTED
                        </div>
                        <p style={{ marginTop: '12px', opacity: 0.6, fontSize: '14px' }}>
                          out of {predictions.length} total packets analyzed
                        </p>
                      </div>

                      {/* Layer Contribution Analysis */}
                      <div className="chart-card" style={{ marginBottom: '24px' }}>
                        <h3>📊 Layer Contribution Analysis</h3>
                        <p className="subtitle">Which layer contributed most to threat detection</p>
                        <ResponsiveContainer width="100%" height={250}>
                          <BarChart data={contributionData} layout="vertical">
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis type="number" domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                            <YAxis type="category" dataKey="layer" width={150} />
                            <Tooltip formatter={(value, name) => [`${value}%`, 'Contribution']} />
                            <Bar dataKey="percent" radius={[0, 8, 8, 0]}>
                              {contributionData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                        <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', marginTop: '16px', flexWrap: 'wrap' }}>
                          {contributionData.map((item, i) => (
                            <div key={i} style={{ textAlign: 'center' }}>
                              <div style={{ fontSize: '24px', fontWeight: '700', color: item.color }}>{item.detections}</div>
                              <div style={{ fontSize: '12px', color: '#64748b' }}>detections</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Layer Agreement Line Plot */}
                      <div className="chart-card" style={{ marginBottom: '24px' }}>
                        <h3>📈 Layer Agreement (Sync Analysis)</h3>
                        <p className="subtitle">When lines overlap, models are "thinking the same" - higher sync = more confident detection</p>
                        <ResponsiveContainer width="100%" height={300}>
                          <LineChart data={lineChartData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="index" label={{ value: 'Packet Sample', position: 'insideBottom', offset: -5 }} />
                            <YAxis domain={[0, 1]} label={{ value: 'Malicious Probability', angle: -90, position: 'insideLeft' }} />
                            <Tooltip
                              formatter={(value, name) => [(value * 100).toFixed(1) + '%', name]}
                              labelFormatter={(label) => `Packet #${label}`}
                            />
                            <Legend />
                            <Line type="monotone" dataKey="layer1" name="Layer 1: Signature" stroke="#3b82f6" strokeWidth={2} dot={false} />
                            <Line type="monotone" dataKey="layer2" name="Layer 2: Autoencoder" stroke="#8b5cf6" strokeWidth={2} dot={false} />
                            <Line type="monotone" dataKey="layer3" name="Layer 3: BiLSTM" stroke="#f59e0b" strokeWidth={2} dot={false} />
                          </LineChart>
                        </ResponsiveContainer>
                      </div>

                      {/* Three Layer Cards with Animation */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                        {/* Layer 1: Signature */}
                        <div className="layer-card" style={{
                          background: 'linear-gradient(135deg, #1e40af 0%, #3b82f6 100%)',
                          borderRadius: '16px',
                          padding: '24px',
                          color: 'white',
                          boxShadow: '0 10px 30px rgba(59, 130, 246, 0.3)',
                          transition: 'transform 0.3s ease',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                            <Target size={28} />
                            <div>
                              <h4 style={{ margin: 0, fontSize: '18px' }}>LAYER 1: SIGNATURE</h4>
                              <p style={{ margin: 0, opacity: 0.8, fontSize: '12px' }}>Known Pattern Match</p>
                            </div>
                          </div>
                          <div style={{ marginBottom: '12px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                              <span>Detection Rate</span>
                              <span style={{ fontWeight: '700' }}>{layer1Percent}%</span>
                            </div>
                            <div style={{ background: 'rgba(255,255,255,0.2)', borderRadius: '8px', height: '12px', overflow: 'hidden' }}>
                              <div style={{
                                width: `${layer1Percent}%`,
                                height: '100%',
                                background: 'linear-gradient(90deg, #60a5fa, #93c5fd)',
                                borderRadius: '8px',
                                transition: 'width 1s ease-out'
                              }} />
                            </div>
                          </div>
                          <div style={{ fontSize: '32px', fontWeight: '800', textAlign: 'center' }}>{layer1Detections}</div>
                          <div style={{ textAlign: 'center', opacity: 0.8 }}>packets flagged</div>
                          {layer1Detections > 0 && (
                            <div style={{ marginTop: '12px', textAlign: 'center', background: 'rgba(255,255,255,0.2)', padding: '6px 12px', borderRadius: '20px', fontSize: '12px' }}>
                              ✓ Contributed to detection
                            </div>
                          )}
                        </div>

                        {/* Layer 2: Autoencoder - Enhanced with Reconstruction Error vs Threshold */}
                        <div className="layer-card" style={{
                          background: 'linear-gradient(135deg, #6d28d9 0%, #8b5cf6 100%)',
                          borderRadius: '16px',
                          padding: '24px',
                          color: 'white',
                          boxShadow: '0 10px 30px rgba(139, 92, 246, 0.3)',
                          transition: 'transform 0.3s ease',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                            <BarChart3 size={28} />
                            <div>
                              <h4 style={{ margin: 0, fontSize: '18px' }}>LAYER 2: AUTOENCODER</h4>
                              <p style={{ margin: 0, opacity: 0.8, fontSize: '12px' }}>Reconstruction Error Analysis</p>
                            </div>
                          </div>

                          {/* Detection Logic Explanation */}
                          <div style={{
                            background: 'rgba(0,0,0,0.2)',
                            borderRadius: '8px',
                            padding: '10px',
                            marginBottom: '16px',
                            fontSize: '11px',
                            textAlign: 'center'
                          }}>
                            <strong>Detection Logic:</strong> If Reconstruction Error &gt; Threshold → ANOMALY
                          </div>

                          {/* Threshold vs Error Visualization */}
                          {autoencoderStats && (
                            <div style={{ marginBottom: '16px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <span style={{ fontSize: '12px' }}>Threshold</span>
                                <span style={{ fontSize: '12px', fontWeight: '700' }}>{autoencoderStats.threshold?.toFixed(4) || 'N/A'}</span>
                              </div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <span style={{ fontSize: '12px' }}>Mean Error</span>
                                <span style={{ fontSize: '12px', fontWeight: '700' }}>{autoencoderStats.statistics?.mean_error?.toFixed(4) || 'N/A'}</span>
                              </div>

                              {/* Visual Bar showing threshold position */}
                              <div style={{ marginTop: '12px', position: 'relative' }}>
                                <div style={{
                                  background: 'rgba(255,255,255,0.2)',
                                  borderRadius: '8px',
                                  height: '20px',
                                  position: 'relative',
                                  overflow: 'hidden'
                                }}>
                                  {/* Normal zone (below threshold) */}
                                  <div style={{
                                    width: '70%',
                                    height: '100%',
                                    background: 'linear-gradient(90deg, #10b981, #34d399)',
                                    borderRadius: '8px 0 0 8px'
                                  }} />
                                  {/* Anomaly zone (above threshold) */}
                                  <div style={{
                                    position: 'absolute',
                                    right: 0,
                                    top: 0,
                                    width: '30%',
                                    height: '100%',
                                    background: 'linear-gradient(90deg, #ef4444, #f87171)',
                                    borderRadius: '0 8px 8px 0'
                                  }} />
                                  {/* Threshold line */}
                                  <div style={{
                                    position: 'absolute',
                                    left: '70%',
                                    top: '-4px',
                                    bottom: '-4px',
                                    width: '3px',
                                    background: '#fbbf24',
                                    borderRadius: '2px',
                                    boxShadow: '0 0 8px #fbbf24'
                                  }} />
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px', fontSize: '10px', opacity: 0.8 }}>
                                  <span>✓ Normal</span>
                                  <span style={{ color: '#fbbf24' }}>← Threshold</span>
                                  <span>⚠ Anomaly</span>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Stats */}
                          <div style={{ display: 'flex', justifyContent: 'space-around', textAlign: 'center', marginBottom: '12px' }}>
                            <div>
                              <div style={{ fontSize: '24px', fontWeight: '800', color: '#10b981' }}>
                                {autoencoderStats?.normal_count || (predictions.length - layer2Detections)}
                              </div>
                              <div style={{ fontSize: '10px', opacity: 0.8 }}>Normal</div>
                            </div>
                            <div>
                              <div style={{ fontSize: '24px', fontWeight: '800', color: '#ef4444' }}>
                                {autoencoderStats?.anomaly_count || layer2Detections}
                              </div>
                              <div style={{ fontSize: '10px', opacity: 0.8 }}>Anomalies</div>
                            </div>
                          </div>

                          {/* Anomaly Rate */}
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '14px', opacity: 0.8 }}>Anomaly Detection Rate</div>
                            <div style={{ fontSize: '28px', fontWeight: '800' }}>
                              {autoencoderStats?.anomaly_rate || layer2Percent}%
                            </div>
                          </div>

                          {layer2Detections > 0 && (
                            <div style={{ marginTop: '12px', textAlign: 'center', background: 'rgba(255,255,255,0.2)', padding: '6px 12px', borderRadius: '20px', fontSize: '12px' }}>
                              ✓ Contributed to detection
                            </div>
                          )}
                        </div>

                        {/* Layer 3: BiLSTM */}
                        <div className="layer-card" style={{
                          background: 'linear-gradient(135deg, #b45309 0%, #f59e0b 100%)',
                          borderRadius: '16px',
                          padding: '24px',
                          color: 'white',
                          boxShadow: '0 10px 30px rgba(245, 158, 11, 0.3)',
                          transition: 'transform 0.3s ease',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                            <Zap size={28} />
                            <div>
                              <h4 style={{ margin: 0, fontSize: '18px' }}>LAYER 3: BiLSTM</h4>
                              <p style={{ margin: 0, opacity: 0.8, fontSize: '12px' }}>Malicious Confidence</p>
                            </div>
                          </div>
                          {/* Circular gauge */}
                          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}>
                            <svg width="100" height="100" viewBox="0 0 100 100">
                              <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="8" />
                              <circle
                                cx="50" cy="50" r="40"
                                fill="none"
                                stroke="#fde047"
                                strokeWidth="8"
                                strokeDasharray={`${2.51 * parseFloat(layer3Percent)} 251`}
                                strokeLinecap="round"
                                transform="rotate(-90 50 50)"
                                style={{ transition: 'stroke-dasharray 1s ease-out' }}
                              />
                              <text x="50" y="55" textAnchor="middle" fill="white" fontSize="20" fontWeight="700">
                                {layer3Percent}%
                              </text>
                            </svg>
                          </div>
                          <div style={{ fontSize: '32px', fontWeight: '800', textAlign: 'center' }}>{layer3Detections}</div>
                          <div style={{ textAlign: 'center', opacity: 0.8 }}>classified malicious</div>
                          {layer3Detections > 0 && (
                            <div style={{ marginTop: '12px', textAlign: 'center', background: 'rgba(255,255,255,0.2)', padding: '6px 12px', borderRadius: '20px', fontSize: '12px' }}>
                              ✓ Contributed to detection
                            </div>
                          )}
                        </div>
                      </div>

                      {/* CSS for wave animation */}
                      <style>{`
                        @keyframes wave {
                          0%, 100% { transform: translateX(0); }
                          50% { transform: translateX(-20px); }
                        }
                        .layer-card:hover {
                          transform: translateY(-5px) scale(1.02);
                        }
                      `}</style>
                    </>
                  );
                })()}
              </div>
            )}

            {/* ========== THREATS VIEW ========== */}
            {currentView === 'threats' && (
              <div className="view">
                <div className="page-header">
                  <h2>Threat Analysis</h2>
                  <div className="header-actions">
                    <button className="btn-secondary" onClick={() => loadDashboardData(selectedJobId)}>
                      <RefreshCw size={18} />
                    </button>
                    {selectedJobId && (
                      <button className="btn-primary" onClick={() => pcapService.downloadResults(selectedJobId)}>
                        <Download size={18} />
                        Export JSON
                      </button>
                    )}
                  </div>
                </div>

                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search by flow ID or attack type..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    {searchQuery && (
                      <button onClick={() => setSearchQuery('')} className="clear-btn">
                        <X size={16} />
                      </button>
                    )}
                  </div>

                  <select value={filterVerdict} onChange={(e) => setFilterVerdict(e.target.value)}>
                    <option value="all">All Verdicts</option>
                    <option value="MALICIOUS">Malicious</option>
                    <option value="BENIGN">Benign</option>
                  </select>

                  <select value={filterAttackType} onChange={(e) => setFilterAttackType(e.target.value)}>
                    <option value="all">All Attack Types</option>
                    {uniqueAttackTypes.map(type => (
                      <option key={type} value={type}>{type?.replace(/_/g, ' ').toUpperCase()}</option>
                    ))}
                  </select>
                </div>

                <div className="filter-info">
                  Showing {filteredPredictions.length} of {predictions.length} predictions
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Flow ID</th>
                        <th>Verdict</th>
                        <th>Attack Type</th>
                        <th>Confidence</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPredictions.slice(0, 100).map((pred, i) => (
                        <tr key={i} className={pred.final_verdict === 'MALICIOUS' ? 'malicious' : ''}>
                          <td className="mono">{pred.packet_id}</td>
                          <td>
                            <span className={`badge ${pred.final_verdict?.toLowerCase()}`}>
                              {pred.final_verdict}
                            </span>
                          </td>
                          <td>{pred.attack_type?.replace(/_/g, ' ').toUpperCase() || 'N/A'}</td>
                          <td>{((pred.confidence_score || 0) * 100).toFixed(1)}%</td>
                          <td>
                            <button className="btn-icon" onClick={() => setSelectedFlow(pred)}>
                              <Eye size={16} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ========== DATABASE/PREDICTIONS VIEW ========== */}
            {currentView === 'database' && (
              <div className="view">
                <div className="page-header">
                  <h2>Predictions Database</h2>
                  <div className="header-actions">
                    <button className="btn-secondary" onClick={() => loadDashboardData(selectedJobId)}>
                      <RefreshCw size={18} />
                    </button>
                    {selectedJobId && (
                      <button className="btn-primary" onClick={() => pcapService.downloadMergedCSV(selectedJobId)}>
                        <Download size={18} />
                        Download CSV
                      </button>
                    )}
                  </div>
                </div>

                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search predictions..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>

                  <select value={filterVerdict} onChange={(e) => setFilterVerdict(e.target.value)}>
                    <option value="all">All Verdicts</option>
                    <option value="MALICIOUS">Malicious</option>
                    <option value="BENIGN">Benign</option>
                  </select>

                  <select value={filterAttackType} onChange={(e) => setFilterAttackType(e.target.value)}>
                    <option value="all">All Attack Types</option>
                    {uniqueAttackTypes.map(type => (
                      <option key={type} value={type}>{type?.replace(/_/g, ' ').toUpperCase()}</option>
                    ))}
                  </select>
                </div>

                <div className="filter-info">{filteredPredictions.length} records found</div>

                <div className="table-container full">
                  <table>
                    <thead>
                      <tr>
                        <th>Flow ID</th>
                        <th>Verdict</th>
                        <th>Attack Type</th>
                        <th>Confidence</th>
                        <th>Signature Match</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPredictions.slice(0, 100).map((pred, i) => (
                        <tr key={i}>
                          <td className="mono">{pred.packet_id}</td>
                          <td>
                            <span className={`badge ${pred.final_verdict?.toLowerCase()}`}>
                              {pred.final_verdict}
                            </span>
                          </td>
                          <td>{pred.attack_type?.replace(/_/g, ' ') || 'N/A'}</td>
                          <td>{((pred.confidence_score || 0) * 100).toFixed(1)}%</td>
                          <td>{pred.layer1_detected ? '✓' : '✗'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}

        {/* ========== PERFORMANCE VIEW ========== */}
        {currentView === 'performance' && (
          <IDSPerformanceDashboard />
        )}

        {/* Flow Detail Modal */}
        {selectedFlow && (
          <div className="modal-overlay" onClick={() => setSelectedFlow(null)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Prediction Details</h3>
                <button onClick={() => setSelectedFlow(null)}>
                  <X size={20} />
                </button>
              </div>
              <div className="modal-body">
                <div className="detail-row">
                  <span>Flow ID:</span>
                  <span className="mono">{selectedFlow.flow_id}</span>
                </div>
                <div className="detail-row">
                  <span>Verdict:</span>
                  <span className={`badge ${selectedFlow.final_verdict?.toLowerCase()}`}>
                    {selectedFlow.final_verdict}
                  </span>
                </div>
                <div className="detail-row">
                  <span>Attack Type:</span>
                  <span>{selectedFlow.predicted_attack_type?.replace(/_/g, ' ').toUpperCase() || 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span>Confidence:</span>
                  <span>{(selectedFlow.confidence * 100).toFixed(2)}%</span>
                </div>
                <div className="detail-row">
                  <span>Signature Matched:</span>
                  <span>{selectedFlow.signature_matched ? 'Yes' : 'No'}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      <style>{`
        * { margin: 0; padding: 0; box-sizing: border-box; }

        .app {
          display: flex;
          height: 100vh;
          background: #f8fafc;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          color: #1e293b;
        }

        .sidebar {
          width: 260px;
          background: linear-gradient(180deg, #192b6dff 0%, #0f172a 100%);
          color: white;
          display: flex;
          flex-direction: column;
          padding: 24px 16px;
        }

        .logo {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 0 8px 24px;
          border-bottom: 1px solid rgba(255, 255, 255, 1);
          margin-bottom: 24px;
        }

        .logo h1 { font-size: 20px; font-weight: 700; }
        .logo p { font-size: 12px; opacity: 0.7; }
        .logo p { color:aqua; }
        .logo h1 { color:white; }

        .nav { flex: 1; display: flex; flex-direction: column; gap: 4px; }

        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 14px;
          border: none;
          background: transparent;
          color: rgba(255,255,255,0.7);
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 14px;
        }

        .nav-item:hover { background: rgba(255,255,255,0.1); color: white; }
        .nav-item.active { background: #3b82f6; color: white; }

        .job-selector {
          padding: 16px;
          border-top: 1px solid rgba(255,255,255,0.1);
          margin-top: 16px;
        }

        .job-selector label {
          display: block;
          font-size: 11px;
          opacity: 0.7;
          margin-bottom: 8px;
        }

        .job-selector select {
          width: 100%;
          padding: 8px;
          border-radius: 6px;
          border: none;
          background: rgba(30, 25, 60, 1);
          color: white;
          font-size: 12px;
        }

        .sidebar-footer { margin-top: auto; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.1); }

        .status-badge {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px;
          background: rgba(16, 185, 129, 0.2);
          border-radius: 8px;
        }

        .status-dot {
          width: 10px;
          height: 10px;
          background: #10b981;
          border-radius: 50%;
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        .status-label { font-size: 11px; opacity: 0.7; }
        .status-value { font-size: 13px; font-weight: 600; }

        .main {
          flex: 1;
          overflow-y: auto;
          padding: 32px;
        }

        .loading {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100%;
          gap: 16px;
          color: #64748b;
        }

        .spinner { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .error-banner {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 8px;
          margin-bottom: 24px;
          color: #dc2626;
        }

        .error-banner button {
          margin-left: auto;
          background: none;
          border: none;
          cursor: pointer;
          color: #dc2626;
        }

        .view { animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
        }

        .page-header h2 { font-size: 24px; font-weight: 700; }

        .header-actions { display: flex; gap: 12px; }

        .btn-primary, .btn-secondary {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 16px;
          border-radius: 8px;
          border: none;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: all 0.2s;
        }

        .btn-primary { background: #3b82f6; color: white; }
        .btn-primary:hover { background: #2563eb; }
        .btn-secondary { background: white; color: #1e293b; border: 1px solid #e2e8f0; }
        .btn-secondary:hover { background: #f1f5f9; }

        .btn-icon {
          padding: 8px;
          border: none;
          background: #f1f5f9;
          border-radius: 6px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .btn-icon:hover { background: #e2e8f0; }

        .no-data-message {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 80px 40px;
          text-align: center;
          color: #64748b;
        }

        .no-data-message h3 { margin: 16px 0 8px; font-size: 20px; color: #1e293b; }
        .no-data-message p { margin-bottom: 24px; }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }

        .stat-card {
          background: white;
          padding: 20px;
          border-radius: 12px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .stat-card.danger { border-left: 4px solid #ef4444; }
        .stat-card.success { border-left: 4px solid #10b981; }
        .stat-card.warning { border-left: 4px solid #f59e0b; }
        .stat-card.info { border-left: 4px solid #3b82f6; }

        .stat-header {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #64748b;
          margin-bottom: 12px;
          font-size: 14px;
        }

        .stat-value { font-size: 28px; font-weight: 700; color: #1e293b; }
        .stat-sub { font-size: 13px; color: #64748b; margin-top: 4px; }

        .charts-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 24px;
          margin-bottom: 24px;
        }

        .chart-card {
          background: white;
          padding: 24px;
          border-radius: 12px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .chart-card.full-width { grid-column: 1 / -1; }

        .chart-card h3 { font-size: 16px; margin-bottom: 4px; }
        .chart-card .subtitle { font-size: 13px; color: #64748b; margin-bottom: 16px; }
        .no-data { text-align: center; padding: 40px; color: #94a3b8; }

        .layer-details {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 20px;
          margin-bottom: 32px;
        }

        .layer-detail {
          background: white;
          padding: 24px;
          border-radius: 12px;
          text-align: center;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .layer-detail h3 { font-size: 16px; margin: 16px 0 8px; }
        .layer-detail p { font-size: 13px; color: #64748b; margin-bottom: 16px; }
        .big-number { font-size: 36px; font-weight: 700; }
        .layer-percentage { font-size: 14px; color: #64748b; margin-top: 8px; }

        .filters {
          display: flex;
          gap: 12px;
          margin-bottom: 16px;
          flex-wrap: wrap;
        }

        .search-box {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 0 12px;
          background: white;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          flex: 1;
          min-width: 200px;
        }

        .search-box input {
          flex: 1;
          border: none;
          padding: 10px 0;
          outline: none;
        }

        .clear-btn {
          background: none;
          border: none;
          cursor: pointer;
          color: #94a3b8;
        }

        .filters select {
          padding: 10px 12px;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          background: white;
          min-width: 150px;
        }

        .filter-info {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 16px;
        }

        .table-container {
          background: white;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .table-container.full { max-height: 500px; overflow-y: auto; }

        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #f1f5f9; }
        th { background: #f8fafc; font-weight: 600; font-size: 13px; color: #64748b; }
        td { font-size: 14px; }
        tr.malicious { background: #fef2f2; }
        .mono { font-family: monospace; font-size: 12px; }

        .badge {
          padding: 4px 10px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 600;
        }

        .badge.malicious { background: #fef2f2; color: #dc2626; }
        .badge.benign { background: #f0fdf4; color: #16a34a; }
        .badge.danger { background: #fef2f2; color: #dc2626; }
        .badge.success { background: #f0fdf4; color: #16a34a; }

        .upload-card {
          max-width: 600px;
          margin: 0 auto;
          background: white;
          padding: 40px;
          border-radius: 16px;
          text-align: center;
          box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }

        .upload-header { margin-bottom: 32px; }
        .upload-header h2 { margin: 16px 0 8px; }
        .upload-header p { color: #64748b; }

        .dropzone {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 48px;
          border: 2px dashed #e2e8f0;
          border-radius: 12px;
          cursor: pointer;
          transition: all 0.2s;
          margin-bottom: 24px;
        }

        .dropzone:hover { border-color: #3b82f6; background: #f8fafc; }
        .dropzone p { margin: 12px 0 4px; font-weight: 500; }
        .dropzone span { font-size: 13px; color: #94a3b8; }

        .attack-types h4 { margin-bottom: 12px; font-size: 14px; }
        .tags { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; }
        .tag {
          padding: 6px 12px;
          background: #f1f5f9;
          border-radius: 20px;
          font-size: 12px;
          color: #64748b;
        }

        .upload-progress { padding: 24px; }
        .progress-info { display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 14px; }
        .progress-bar { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: #3b82f6; transition: width 0.3s; }

        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }

        .modal {
          background: white;
          border-radius: 16px;
          width: 90%;
          max-width: 500px;
          overflow: hidden;
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 20px 24px;
          border-bottom: 1px solid #e2e8f0;
        }

        .modal-header h3 { font-size: 18px; }
        .modal-header button { background: none; border: none; cursor: pointer; color: #64748b; }

        .modal-body { padding: 24px; }

        .detail-row {
          display: flex;
          justify-content: space-between;
          padding: 12px 0;
          border-bottom: 1px solid #f1f5f9;
        }

        .detail-row:last-child { border-bottom: none; }
        .detail-row span:first-child { color: #64748b; }
      `}</style>
    </div>
  );
};

export default HybridIDSDashboard;
