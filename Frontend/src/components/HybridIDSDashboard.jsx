import React, { useState, useEffect } from 'react';
import {
  Shield, Upload, Activity, AlertTriangle, Network,
  Database, Eye, Download, Search, ChevronRight,
  RefreshCw, CheckCircle, BarChart3, Layers, Target,
  Clock, Globe, Zap, X, TrendingUp
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

// ATTACK COLORS for Pie Charts
const ATTACK_COLORS = {
  xss: '#ef4444',
  ssrf: '#f97316',
  bruteforce: '#f59e0b',
  sql_injection: '#eab308',
  command_injection: '#84cc16',
  directory_traversal: '#22c55e',
  lfi_rfi: '#10b981',
  parameter_pollution: '#14b8a6',
  xxe: '#06b6d4',
  web_shell: '#0ea5e9',
  typosquatting: '#3b82f6',
  credential_stuffing: '#6366f1'
};

// ===== MOCK DATA GENERATOR =====
// TODO: Replace this with actual API calls to your backend
const generateMockData = () => {
  const attackTypes = [
    'xss', 'ssrf', 'bruteforce', 'sql_injection', 'command_injection',
    'directory_traversal', 'lfi_rfi', 'parameter_pollution', 'xxe',
    'web_shell', 'typosquatting', 'credential_stuffing'
  ];
  const ips = ['10.170.104.115', '172.21.40.253', '192.168.1.1', '10.0.0.5'];

  return Array.from({ length: 100 }, (_, i) => ({
    flow_id: `flow_${i}`,
    src_ip: ips[Math.floor(Math.random() * ips.length)],
    dst_ip: ips[Math.floor(Math.random() * ips.length)],
    src_port: Math.floor(Math.random() * 65535),
    dst_port: [80, 443, 8080][Math.floor(Math.random() * 3)],
    prediction_verdict: Math.random() > 0.35 ? 'MALICIOUS' : 'BENIGN',
    prediction_confidence: (Math.random() * 0.4 + 0.6).toFixed(4),
    attack_type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
    attack_severity: Math.floor(Math.random() * 5) + 1, // 1-5 severity
    attack_outcome: Math.random() > 0.3 ? 'SUCCESSFUL_ATTACK' : 'BLOCKED',
    layer1_detected: Math.random() > 0.4,
    layer2_status: Math.random() > 0.4 ? 'Anomaly' : 'Normal',
    layer3_detected: Math.random() > 0.4,
    method: ['GET', 'POST', 'PUT'][Math.floor(Math.random() * 3)],
    uri: ['/login.php', '/admin/', '/api/data'][Math.floor(Math.random() * 3)],
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
  }));
};

const HybridIDSDashboard = () => {
  const [currentView, setCurrentView] = useState('overview');
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  // Filter states
  const [filterVerdict, setFilterVerdict] = useState('all');
  const [filterAttackType, setFilterAttackType] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  // ===== DATA LOADING =====
  // Using mock data for now since no API integration yet
  const loadData = () => {
    setLoading(true);
    setTimeout(() => {
      setData(generateMockData());
      setLoading(false);
    }, 800);
  };

  // Calculate statistics
  const stats = {
    totalFlows: data.length,
    malicious: data.filter(d => d.prediction_verdict === 'MALICIOUS').length,
    benign: data.filter(d => d.prediction_verdict === 'BENIGN').length,
    successfulAttacks: data.filter(d => d.attack_outcome === 'SUCCESSFUL_ATTACK').length,
    layer1Detections: data.filter(d => d.layer1_detected).length,
    layer2Anomalies: data.filter(d => d.layer2_status === 'Anomaly').length,
    layer3Detections: data.filter(d => d.layer3_detected).length,
  };

  // Attack distribution for pie chart
  const attackDistribution = Object.entries(
    data.filter(d => d.prediction_verdict === 'MALICIOUS')
      .reduce((acc, flow) => {
        acc[flow.attack_type] = (acc[flow.attack_type] || 0) + 1;
        return acc;
      }, {})
  ).map(([name, value]) => ({
    name: name.replace(/_/g, ' ').toUpperCase(),
    value,
    rawName: name
  }));

  // Severity distribution (1-5)
  const severityDistribution = [1, 2, 3, 4, 5].map(sev => ({
    severity: `Level ${sev}`,
    count: data.filter(d => d.attack_severity === sev && d.prediction_verdict === 'MALICIOUS').length
  }));

  // Attack outcome distribution for pie chart
  const outcomeDistribution = [
    {
      name: 'Successful Attacks',
      value: data.filter(d => d.attack_outcome === 'SUCCESSFUL_ATTACK').length,
      color: '#ef4444'
    },
    {
      name: 'Blocked Attacks',
      value: data.filter(d => d.attack_outcome === 'BLOCKED' && d.prediction_verdict === 'MALICIOUS').length,
      color: '#10b981'
    },
    {
      name: 'Benign Traffic',
      value: stats.benign,
      color: '#94a3b8'
    }
  ];

  // Filtered data
  const filteredData = data.filter(d => {
    const matchesVerdict = filterVerdict === 'all' || d.prediction_verdict === filterVerdict;
    const matchesAttackType = filterAttackType === 'all' || d.attack_type === filterAttackType;
    const matchesSeverity = filterSeverity === 'all' || d.attack_severity === parseInt(filterSeverity);
    const matchesSearch = !searchQuery ||
      d.src_ip.includes(searchQuery) ||
      d.dst_ip.includes(searchQuery) ||
      d.attack_type?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesVerdict && matchesAttackType && matchesSeverity && matchesSearch;
  });

  // Get unique attack types for filter
  const uniqueAttackTypes = [...new Set(data.map(d => d.attack_type))].filter(Boolean);

  // ===== FILE UPLOAD HANDLER =====
  // TODO: Replace with real upload logic
  // const handleFileUpload = async (e) => {
  //   const file = e.target.files[0];
  //   if (!file) return;
  //   
  //   try {
  //     setIsUploading(true);
  //     const response = await pcapService.upload(file, (progress) => {
  //       setUploadProgress(progress);
  //     });
  //     setCurrentView('overview');
  //     await loadData();
  //   } catch (error) {
  //     console.error('Upload failed:', error);
  //   } finally {
  //     setIsUploading(false);
  //   }
  // };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsUploading(true);
    setUploadProgress(0);

    const interval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setTimeout(() => {
            setIsUploading(false);
            setCurrentView('overview');
            loadData();
          }, 500);
          return 100;
        }
        return prev + 10;
      });
    }, 300);
  };

  const exportData = (format) => {
    const dataStr = format === 'json'
      ? JSON.stringify(filteredData, null, 2)
      : filteredData.map(d => Object.values(d).join(',')).join('\n');

    const blob = new Blob([dataStr], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `hybrid_ids_export_${Date.now()}.${format}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="app">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="logo">
          <Shield size={28} strokeWidth={2.5} />
          <div className="logo-text">
            <h1>Hybrid IDS</h1>
            <p>URL Attack Detection</p>
          </div>
        </div>

        <nav className="nav">
          {[
            { id: 'upload', icon: Upload, label: 'Upload PCAP' },
            { id: 'overview', icon: Activity, label: 'Overview' },
            { id: 'threats', icon: AlertTriangle, label: 'Threat Analysis' },
            { id: 'network', icon: Network, label: 'Network Flows' },
            { id: 'layers', icon: Layers, label: 'Layer Analysis' },
            { id: 'database', icon: Database, label: 'Database Explorer' },
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
                        <span>Supports .pcap, .pcapng, .cap files (Max 1GB)</span>
                      </label>

                      <div className="attack-types">
                        <h4>Supported Attack Detection</h4>
                        <div className="tags">
                          {['SQL Injection', 'XSS', 'SSRF', 'Command Injection', 'Directory Traversal',
                            'LFI/RFI', 'Brute Force', 'Parameter Pollution', 'XXE', 'Web Shell',
                            'Typosquatting', 'Credential Stuffing'].map(tag => (
                              <span key={tag} className="tag">{tag}</span>
                            ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="upload-progress">
                      <div className="progress-info">
                        <span>Processing PCAP file...</span>
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
                  <button className="btn-secondary" onClick={loadData}>
                    <RefreshCw size={18} />
                    Refresh
                  </button>
                </div>

                {/* KPI Cards */}
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-header">
                      <Activity size={22} />
                      <span>Total Flows</span>
                    </div>
                    <div className="stat-value">{stats.totalFlows}</div>
                  </div>

                  <div className="stat-card danger">
                    <div className="stat-header">
                      <AlertTriangle size={22} />
                      <span>Malicious</span>
                    </div>
                    <div className="stat-value">{stats.malicious}</div>
                    <div className="stat-sub">{((stats.malicious / stats.totalFlows) * 100).toFixed(1)}% of total</div>
                  </div>

                  <div className="stat-card success">
                    <div className="stat-header">
                      <CheckCircle size={22} />
                      <span>Benign</span>
                    </div>
                    <div className="stat-value">{stats.benign}</div>
                    <div className="stat-sub">{((stats.benign / stats.totalFlows) * 100).toFixed(1)}% of total</div>
                  </div>

                  <div className="stat-card warning">
                    <div className="stat-header">
                      <Target size={22} />
                      <span>Successful Attacks</span>
                    </div>
                    <div className="stat-value">{stats.successfulAttacks}</div>
                  </div>
                </div>

                {/* Charts Row */}
                <div className="charts-row">
                  {/* Attack Type Distribution Pie Chart */}
                  <div className="chart-card">
                    <h3>Attack Type Distribution</h3>
                    <p className="subtitle">Composition of detected attacks by category</p>
                    {attackDistribution.length > 0 ? (
                      <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                          <Pie
                            data={attackDistribution}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                            outerRadius={100}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {attackDistribution.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={ATTACK_COLORS[entry.rawName] || '#6366f1'} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="no-data">No malicious attacks detected</div>
                    )}
                  </div>

                  {/* Attack Outcome Pie Chart */}
                  <div className="chart-card">
                    <h3>Traffic Outcome Analysis</h3>
                    <p className="subtitle">Success vs blocked attacks and benign traffic</p>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={outcomeDistribution}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                          outerRadius={100}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {outcomeDistribution.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Severity Distribution Bar Chart */}
                <div className="chart-card full-width">
                  <h3>Attack Severity Distribution</h3>
                  <p className="subtitle">Severity levels from 1 (Low) to 5 (Critical)</p>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={severityDistribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis dataKey="severity" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="count" fill="#3b82f6" radius={[8, 8, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Detection Layer Performance */}
                <div className="layer-section">
                  <h3>Multi-Layer Detection Performance</h3>
                  <div className="layer-cards">
                    {[
                      { icon: Target, label: 'Layer 1: Signature', value: stats.layer1Detections, color: '#3b82f6' },
                      { icon: BarChart3, label: 'Layer 2: Anomaly', value: stats.layer2Anomalies, color: '#8b5cf6' },
                      { icon: Zap, label: 'Layer 3: ML', value: stats.layer3Detections, color: '#10b981' }
                    ].map((layer, i) => (
                      <div key={i} className="layer-card">
                        <layer.icon size={24} style={{ color: layer.color }} />
                        <div className="layer-info">
                          <h4>{layer.label}</h4>
                          <div className="layer-value">{layer.value}</div>
                          <div className="layer-percent">
                            {((layer.value / stats.totalFlows) * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ========== THREATS VIEW ========== */}
            {currentView === 'threats' && (
              <div className="view">
                <div className="page-header">
                  <h2>Threat Analysis</h2>
                  <div className="header-actions">
                    <button className="btn-secondary" onClick={loadData}>
                      <RefreshCw size={18} />
                    </button>
                    <button className="btn-primary" onClick={() => exportData('csv')}>
                      <Download size={18} />
                      Export CSV
                    </button>
                    <button className="btn-primary" onClick={() => exportData('json')}>
                      <Download size={18} />
                      Export JSON
                    </button>
                  </div>
                </div>

                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search by IP, attack type..."
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
                      <option key={type} value={type}>{type.replace(/_/g, ' ').toUpperCase()}</option>
                    ))}
                  </select>

                  <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
                    <option value="all">All Severities</option>
                    {[1, 2, 3, 4, 5].map(sev => (
                      <option key={sev} value={sev}>Severity {sev}</option>
                    ))}
                  </select>
                </div>

                <div className="filter-info">
                  Showing {filteredData.length} of {data.length} flows
                </div>

                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Verdict</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                        <th>Outcome</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredData.slice(0, 50).map((flow, i) => (
                        <tr key={i} className={flow.prediction_verdict === 'MALICIOUS' ? 'malicious' : ''}>
                          <td>{new Date(flow.timestamp).toLocaleTimeString()}</td>
                          <td className="mono">{flow.src_ip}:{flow.src_port}</td>
                          <td className="mono">{flow.dst_ip}:{flow.dst_port}</td>
                          <td>
                            <span className={`badge ${flow.prediction_verdict.toLowerCase()}`}>
                              {flow.prediction_verdict}
                            </span>
                          </td>
                          <td>{flow.attack_type ? flow.attack_type.replace(/_/g, ' ').toUpperCase() : 'N/A'}</td>
                          <td>
                            <span className={`severity severity-${flow.attack_severity}`}>
                              Level {flow.attack_severity}
                            </span>
                          </td>
                          <td>
                            <span className={`badge ${flow.attack_outcome === 'SUCCESSFUL_ATTACK' ? 'danger' : 'success'}`}>
                              {flow.attack_outcome === 'SUCCESSFUL_ATTACK' ? 'Success' : 'Blocked'}
                            </span>
                          </td>
                          <td>
                            <button className="btn-icon" onClick={() => setSelectedFlow(flow)}>
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

            {/* ========== DATABASE EXPLORER VIEW ========== */}
            {currentView === 'database' && (
              <div className="view">
                <div className="page-header">
                  <h2>Database Explorer</h2>
                  <button className="btn-primary" onClick={() => exportData('json')}>
                    <Download size={18} />
                    Export Data
                  </button>
                </div>

                {/* Enhanced Filters for Database */}
                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search database..."
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
                      <option key={type} value={type}>{type.replace(/_/g, ' ').toUpperCase()}</option>
                    ))}
                  </select>

                  <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
                    <option value="all">All Severities</option>
                    {[1, 2, 3, 4, 5].map(s => <option key={s} value={s}>Severity {s}</option>)}
                  </select>
                </div>

                <div className="filter-info">
                  {filteredData.length} records found
                </div>

                <div className="table-container full">
                  <table>
                    <thead>
                      <tr>
                        <th>Flow ID</th>
                        <th>Method</th>
                        <th>URI</th>
                        <th>Verdict</th>
                        <th>Attack Type</th>
                        <th>Severity</th>
                        <th>L1</th>
                        <th>L2</th>
                        <th>L3</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredData.slice(0, 30).map((flow, i) => (
                        <tr key={i}>
                          <td className="mono">{flow.flow_id}</td>
                          <td><span className="method">{flow.method}</span></td>
                          <td className="uri">{flow.uri}</td>
                          <td>
                            <span className={`badge ${flow.prediction_verdict.toLowerCase()}`}>
                              {flow.prediction_verdict}
                            </span>
                          </td>
                          <td>{flow.attack_type ? flow.attack_type.replace(/_/g, ' ') : 'N/A'}</td>
                          <td>
                            <span className={`severity severity-${flow.attack_severity}`}>
                              {flow.attack_severity}
                            </span>
                          </td>
                          <td>{flow.layer1_detected ? '✓' : '✗'}</td>
                          <td>{flow.layer2_status === 'Anomaly' ? '✓' : '✗'}</td>
                          <td>{flow.layer3_detected ? '✓' : '✗'}</td>
                          <td>{(parseFloat(flow.prediction_confidence) * 100).toFixed(1)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ========== NETWORK VIEW ========== */}
            {currentView === 'network' && (
              <div className="view">
                <div className="page-header">
                  <h2>Network Flow Analysis</h2>
                </div>
                <div className="info-cards">
                  {[
                    { icon: Globe, label: 'Unique IPs', value: new Set([...data.map(d => d.src_ip), ...data.map(d => d.dst_ip)]).size },
                    { icon: Network, label: 'Active Connections', value: data.length },
                    { icon: Clock, label: 'Analyzed Flows', value: `${data.length} flows` }
                  ].map((item, i) => (
                    <div key={i} className="info-card">
                      <item.icon size={32} />
                      <h4>{item.label}</h4>
                      <p>{item.value}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ========== LAYERS VIEW ========== */}
            {currentView === 'layers' && (
              <div className="view">
                <div className="page-header">
                  <h2>Multi-Layer Detection Analysis</h2>
                </div>
                <div className="layer-details">
                  {[
                    { icon: Target, title: 'Layer 1: Signature Detection', desc: 'Pattern-based threat identification', value: stats.layer1Detections },
                    { icon: BarChart3, title: 'Layer 2: Anomaly Detection', desc: 'Statistical behavior analysis', value: stats.layer2Anomalies },
                    { icon: Zap, title: 'Layer 3: ML Prediction', desc: 'Deep learning classification', value: stats.layer3Detections }
                  ].map((layer, i) => (
                    <div key={i} className="layer-detail">
                      <layer.icon size={32} />
                      <h3>{layer.title}</h3>
                      <p>{layer.desc}</p>
                      <div className="big-number">{layer.value}</div>
                      <div className="layer-percentage">
                        {((layer.value / stats.totalFlows) * 100).toFixed(1)}% detection rate
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* ========== FLOW DETAIL MODAL ========== */}
        {selectedFlow && (
          <div className="modal-overlay" onClick={() => setSelectedFlow(null)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Flow Details</h3>
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
                  <span>Source:</span>
                  <span className="mono">{selectedFlow.src_ip}:{selectedFlow.src_port}</span>
                </div>
                <div className="detail-row">
                  <span>Destination:</span>
                  <span className="mono">{selectedFlow.dst_ip}:{selectedFlow.dst_port}</span>
                </div>
                <div className="detail-row">
                  <span>Method:</span>
                  <span>{selectedFlow.method}</span>
                </div>
                <div className="detail-row">
                  <span>URI:</span>
                  <span className="mono">{selectedFlow.uri}</span>
                </div>
                <div className="detail-row">
                  <span>Verdict:</span>
                  <span className={`badge ${selectedFlow.prediction_verdict.toLowerCase()}`}>
                    {selectedFlow.prediction_verdict}
                  </span>
                </div>
                <div className="detail-row">
                  <span>Attack Type:</span>
                  <span>{selectedFlow.attack_type ? selectedFlow.attack_type.replace(/_/g, ' ').toUpperCase() : 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span>Severity:</span>
                  <span className={`severity severity-${selectedFlow.attack_severity}`}>
                    Level {selectedFlow.attack_severity}
                  </span>
                </div>
                <div className="detail-row">
                  <span>Confidence:</span>
                  <span>{(parseFloat(selectedFlow.prediction_confidence) * 100).toFixed(2)}%</span>
                </div>
                <div className="detail-row">
                  <span>Outcome:</span>
                  <span className={`badge ${selectedFlow.attack_outcome === 'SUCCESSFUL_ATTACK' ? 'danger' : 'success'}`}>
                    {selectedFlow.attack_outcome === 'SUCCESSFUL_ATTACK' ? 'Successful Attack' : 'Blocked'}
                  </span>
                </div>
                <div className="detail-row">
                  <span>Timestamp:</span>
                  <span>{new Date(selectedFlow.timestamp).toLocaleString()}</span>
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

        /* ===== SIDEBAR ===== */
        .sidebar {
          width: 280px;
          background: white;
          border-right: 1px solid #e2e8f0;
          display: flex;
          flex-direction: column;
          padding: 24px 0;
          box-shadow: 2px 0 8px rgba(0,0,0,0.05);
        }

        .logo {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 0 24px 24px;
          border-bottom: 1px solid #e2e8f0;
          color: #3b82f6;
        }

        .logo-text h1 {
          font-size: 20px;
          font-weight: 700;
          color: #0f172a;
        }

        .logo-text p {
          font-size: 12px;
          color: #64748b;
        }

        .nav {
          flex: 1;
          padding: 24px 12px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: none;
          border: none;
          border-radius: 8px;
          color: #64748b;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 14px;
          font-weight: 500;
          text-align: left;
        }

        .nav-item:hover {
          background: #f1f5f9;
          color: #3b82f6;
        }

        .nav-item.active {
          background: #eff6ff;
          color: #3b82f6;
          font-weight: 600;
        }

        .sidebar-footer {
          padding: 0 24px;
          border-top: 1px solid #e2e8f0;
          padding-top: 16px;
        }

        .status-badge {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px;
          background: #f0fdf4;
          border-radius: 8px;
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #22c55e;
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        .status-label {
          font-size: 11px;
          color: #64748b;
          text-transform: uppercase;
        }

        .status-value {
          font-size: 13px;
          font-weight: 600;
          color: #22c55e;
        }

        /* ===== MAIN CONTENT ===== */
        .main {
          flex: 1;
          overflow-y: auto;
          padding: 32px;
          background: #f8fafc;
        }

        .loading {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100%;
          gap: 16px;
        }

        .spinner {
          animation: spin 1s linear infinite;
          color: #3b82f6;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .view {
          max-width: 1400px;
          margin: 0 auto;
        }

        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
        }

        .page-header h2 {
          font-size: 28px;
          color: #0f172a;
        }

        .header-actions {
          display: flex;
          gap: 12px;
        }

        /* ===== BUTTONS ===== */
        .btn-primary, .btn-secondary {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }

        .btn-primary {
          background: #3b82f6;
          color: white;
        }

        .btn-primary:hover {
          background: #2563eb;
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }

        .btn-secondary {
          background: white;
          color: #64748b;
          border: 1px solid #e2e8f0;
        }

        .btn-secondary:hover {
          border-color: #3b82f6;
          color: #3b82f6;
        }

        /* ===== UPLOAD VIEW ===== */
        .upload-card {
          background: white;
          border-radius: 16px;
          padding: 48px;
          text-align: center;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          max-width: 800px;
          margin: 40px auto;
        }

        .upload-header {
          margin-bottom: 32px;
        }

        .upload-header svg {
          color: #3b82f6;
          margin-bottom: 16px;
        }

        .upload-header h2 {
          font-size: 24px;
          margin-bottom: 8px;
          color: #0f172a;
        }

        .upload-header p {
          color: #64748b;
          font-size: 14px;
        }

        .dropzone {
          display: block;
          padding: 48px;
          border: 2px dashed #cbd5e1;
          border-radius: 12px;
          cursor: pointer;
          transition: all 0.2s;
          margin-bottom: 32px;
        }

        .dropzone:hover {
          border-color: #3b82f6;
          background: #f0f9ff;
        }

        .dropzone svg {
          color: #3b82f6;
          margin-bottom: 12px;
        }

        .dropzone p {
          font-size: 16px;
          color: #0f172a;
          margin-bottom: 4px;
        }

        .dropzone span {
          font-size: 13px;
          color: #64748b;
        }

        .attack-types {
          text-align: left;
          padding: 24px;
          background: #f8fafc;
          border-radius: 8px;
        }

        .attack-types h4 {
          font-size: 14px;
          color: #64748b;
          margin-bottom: 16px;
          text-transform: uppercase;
        }

        .tags {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }

        .tag {
          padding: 6px 12px;
          background: white;
          border: 1px solid #e2e8f0;
          border-radius: 6px;
          font-size: 12px;
          color: #475569;
        }

        .upload-progress {
          padding: 32px;
        }

        .progress-info {
          display: flex;
          justify-content: space-between;
          margin-bottom: 12px;
          font-size: 14px;
          color: #64748b;
          font-weight: 600;
        }

        .progress-bar {
          height: 8px;
          background: #e2e8f0;
          border-radius: 4px;
          overflow: hidden;
        }

        .progress-fill {
          height: 100%;
          background: linear-gradient(90deg, #3b82f6, #10b981);
          transition: width 0.3s;
        }

        /* ===== STATS GRID ===== */
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 20px;
          margin-bottom: 32px;
        }

        .stat-card {
          background: white;
          border-radius: 12px;
          padding: 24px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          transition: transform 0.2s;
        }

        .stat-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .stat-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 16px;
          color: #64748b;
          font-size: 14px;
          font-weight: 600;
        }

        .stat-value {
          font-size: 36px;
          font-weight: 700;
          color: #0f172a;
          margin-bottom: 4px;
        }

        .stat-sub {
          font-size: 13px;
          color: #64748b;
        }

        .stat-card.danger .stat-header svg { color: #ef4444; }
        .stat-card.danger .stat-value { color: #ef4444; }
        .stat-card.success .stat-header svg { color: #10b981; }
        .stat-card.success .stat-value { color: #10b981; }
        .stat-card.warning .stat-header svg { color: #f59e0b; }
        .stat-card.warning .stat-value { color: #f59e0b; }

        /* ===== CHARTS ===== */
        .charts-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 24px;
          margin-bottom: 32px;
        }

        .chart-card {
          background: white;
          border-radius: 12px;
          padding: 24px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .chart-card.full-width {
          grid-column: 1 / -1;
        }

        .chart-card h3 {
          font-size: 18px;
          color: #0f172a;
          margin-bottom: 4px;
        }

        .subtitle {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 24px;
        }

        .no-data {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 300px;
          color: #94a3b8;
          font-size: 14px;
        }

        /* ===== LAYER CARDS ===== */
        .layer-section {
          background: white;
          border-radius: 12px;
          padding: 24px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .layer-section h3 {
          font-size: 18px;
          color: #0f172a;
          margin-bottom: 20px;
        }

        .layer-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
        }

        .layer-card {
          display: flex;
          gap: 16px;
          padding: 20px;
          background: #f8fafc;
          border-radius: 8px;
          border: 1px solid #e2e8f0;
        }

        .layer-info h4 {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 8px;
        }

        .layer-value {
          font-size: 28px;
          font-weight: 700;
          color: #0f172a;
        }

        .layer-percent {
          font-size: 12px;
          color: #64748b;
        }

        /* ===== FILTERS ===== */
        .filters {
          display: flex;
          gap: 12px;
          margin-bottom: 20px;
          flex-wrap: wrap;
        }

        .search-box {
          position: relative;
          flex: 1;
          min-width: 300px;
          display: flex;
          align-items: center;
        }

        .search-box svg {
          position: absolute;
          left: 12px;
          color: #94a3b8;
        }

        .search-box input {
          width: 100%;
          padding: 10px 40px 10px 40px;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          font-size: 14px;
          background: white;
        }

        .search-box input:focus {
          outline: none;
          border-color: #3b82f6;
        }

        .clear-btn {
          position: absolute;
          right: 8px;
          background: none;
          border: none;
          padding: 4px;
          cursor: pointer;
          color: #94a3b8;
          display: flex;
          align-items: center;
        }

        .clear-btn:hover {
          color: #64748b;
        }

        .filters select {
          padding: 10px 16px;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          font-size: 14px;
          background: white;
          color: #0f172a;
          cursor: pointer;
        }

        .filters select:focus {
          outline: none;
          border-color: #3b82f6;
        }

        .filter-info {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 16px;
        }

        /* ===== TABLE ===== */
        .table-container {
          background: white;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .table-container.full {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
        }

        thead {
          background: #f8fafc;
          border-bottom: 2px solid #e2e8f0;
        }

        th {
          padding: 14px 16px;
          text-align: left;
          font-size: 12px;
          font-weight: 700;
          text-transform: uppercase;
          color: #64748b;
          letter-spacing: 0.5px;
        }

        td {
          padding: 14px 16px;
          font-size: 13px;
          color: #475569;
          border-bottom: 1px solid #f1f5f9;
        }

        tr:hover {
          background: #f8fafc;
        }

        tr.malicious {
          background: #fef2f2;
        }

        tr.malicious:hover {
          background: #fee2e2;
        }

        .mono {
          font-family: 'Courier New', monospace;
          font-size: 12px;
        }

        .badge {
          display: inline-block;
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
        }

        .badge.malicious {
          background: #fee2e2;
          color: #991b1b;
        }

        .badge.benign {
          background: #d1fae5;
          color: #065f46;
        }

        .badge.danger {
          background: #fee2e2;
          color: #991b1b;
        }

        .badge.success {
          background: #d1fae5;
          color: #065f46;
        }

        .severity {
          display: inline-block;
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 11px;
          font-weight: 600;
        }

        .severity-1 { background: #dbeafe; color: #1e40af; }
        .severity-2 { background: #fef3c7; color: #92400e; }
        .severity-3 { background: #fed7aa; color: #9a3412; }
        .severity-4 { background: #fecaca; color: #991b1b; }
        .severity-5 { background: #fecdd3; color: #881337; }

        .method {
          padding: 4px 8px;
          background: #e0e7ff;
          color: #3730a3;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 600;
          font-family: 'Courier New', monospace;
        }

        .uri {
          font-family: 'Courier New', monospace;
          font-size: 12px;
          color: #475569;
        }

        .btn-icon {
          padding: 6px;
          background: #f1f5f9;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          color: #64748b;
          display: flex;
          align-items: center;
          transition: all 0.2s;
        }

        .btn-icon:hover {
          background: #3b82f6;
          color: white;
        }

        /* ===== INFO CARDS ===== */
        .info-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 20px;
        }

        .info-card {
          background: white;
          border-radius: 12px;
          padding: 32px;
          text-align: center;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .info-card svg {
          color: #3b82f6;
          margin-bottom: 16px;
        }

        .info-card h4 {
          font-size: 14px;
          color: #64748b;
          margin-bottom: 8px;
        }

        .info-card p {
          font-size: 24px;
          font-weight: 700;
          color: #0f172a;
        }

        /* ===== LAYER DETAILS ===== */
        .layer-details {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 24px;
        }

        .layer-detail {
          background: white;
          border-radius: 12px;
          padding: 32px;
          text-align: center;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .layer-detail svg {
          color: #3b82f6;
          margin-bottom: 16px;
        }

        .layer-detail h3 {
          font-size: 18px;
          color: #0f172a;
          margin-bottom: 8px;
        }

        .layer-detail p {
          font-size: 13px;
          color: #64748b;
          margin-bottom: 24px;
        }

        .big-number {
          font-size: 48px;
          font-weight: 700;
          color: #3b82f6;
          margin-bottom: 8px;
        }

        .layer-percentage {
          font-size: 14px;
          color: #64748b;
        }

        /* ===== MODAL ===== */
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          backdrop-filter: blur(4px);
        }

        .modal {
          background: white;
          border-radius: 16px;
          width: 90%;
          max-width: 600px;
          max-height: 80vh;
          overflow-y: auto;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 24px;
          border-bottom: 1px solid #e2e8f0;
        }

        .modal-header h3 {
          font-size: 20px;
          color: #0f172a;
        }

        .modal-header button {
          background: none;
          border: none;
          padding: 8px;
          cursor: pointer;
          color: #64748b;
          border-radius: 6px;
          display: flex;
          align-items: center;
        }

        .modal-header button:hover {
          background: #f1f5f9;
          color: #0f172a;
        }

        .modal-body {
          padding: 24px;
        }

        .detail-row {
          display: flex;
          justify-content: space-between;
          padding: 12px 0;
          border-bottom: 1px solid #f1f5f9;
        }

        .detail-row:last-child {
          border-bottom: none;
        }

        .detail-row span:first-child {
          font-weight: 600;
          color: #64748b;
          font-size: 13px;
        }

        .detail-row span:last-child {
          color: #0f172a;
          font-size: 13px;
        }

        /* ===== RESPONSIVE ===== */
        @media (max-width: 1024px) {
          .sidebar {
            width: 240px;
          }

          .main {
            padding: 20px;
          }

          .charts-row {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 768px) {
          .app {
            flex-direction: column;
          }

          .sidebar {
            width: 100%;
            height: auto;
            flex-direction: row;
            padding: 12px;
            border-right: none;
            border-bottom: 1px solid #e2e8f0;
          }

          .logo {
            border: none;
            padding: 0;
          }

          .nav {
            flex-direction: row;
            padding: 0;
            overflow-x: auto;
          }

          .sidebar-footer {
            display: none;
          }

          .main {
            padding: 16px;
          }

          .stats-grid {
            grid-template-columns: 1fr;
          }

          .filters {
            flex-direction: column;
          }

          .search-box {
            min-width: 100%;
          }
        }
      `}</style>
    </div>
  );
};

export default HybridIDSDashboard;
