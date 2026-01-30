import axios from 'axios';

const API_BASE_URL = '/api';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const pcapService = {
  // Upload PCAP file
  upload: async (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);

    return axios.post(`${API_BASE_URL}/upload`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        if (onProgress) onProgress(percentCompleted);
      },
    });
  },

  // Get job status
  getStatus: async (jobId) => {
    return axios.get(`${API_BASE_URL}/status/${jobId}`);
  },

  // Get inference results
  getResults: async (jobId) => {
    return axios.get(`${API_BASE_URL}/results/${jobId}`);
  },

  // Get job logs (for debugging)
  getLogs: async (jobId) => {
    return axios.get(`${API_BASE_URL}/logs/${jobId}`);
  },

  // Download results as JSON
  downloadResults: async (jobId) => {
    const response = await axios.get(`${API_BASE_URL}/download/${jobId}`, {
      responseType: 'blob',
    });

    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `analysis_${jobId}.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  // Download merged CSV
  downloadMergedCSV: async (jobId, originalFilename = 'results') => {
    const response = await axios.get(`${API_BASE_URL}/download-merged-csv/${jobId}`, {
      responseType: 'blob',
    });

    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    const baseName = originalFilename.replace(/\.[^/.]+$/, '');
    link.setAttribute('download', `${baseName}_merged_features.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  // List all jobs
  listJobs: async () => {
    return axios.get(`${API_BASE_URL}/jobs`);
  },

  // Delete a job
  deleteJob: async (jobId) => {
    return axios.delete(`${API_BASE_URL}/jobs/${jobId}`);
  },
};

// Dashboard and visualization services
export const dashboardService = {
  // Get KPI summary
  getKPISummary: async (timeRange = '24h') => {
    return axios.get(`${API_BASE_URL}/kpi/summary?time_range=${timeRange}`);
  },

  // Get dashboard summary for a specific job
  getDashboardSummary: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/summary/${jobId}`);
  },

  // Get flow analysis for visualizations
  getFlowAnalysis: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/flow-analysis/${jobId}`);
  },

  // Get layer-by-layer details
  getLayerDetails: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/layer-details/${jobId}`);
  },

  // Get timeline data
  getTimelineData: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/timeline/${jobId}`);
  },

  // Get layer statistics
  getLayerStatistics: async (timeRange = '24h') => {
    return axios.get(`${API_BASE_URL}/layers/statistics?time_range=${timeRange}`);
  },

  // Get attack attempted vs successful stats
  getAttackStats: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/attack-stats/${jobId}`);
  },

  // Get severity heatmap data
  getSeverityHeatmap: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/severity-heatmap/${jobId}`);
  },

  // Get autoencoder-specific stats for Layer 2 visualization
  getAutoencoderStats: async (jobId) => {
    return axios.get(`${API_BASE_URL}/dashboard/autoencoder-stats/${jobId}`);
  },
};

// Database services
export const dbService = {
  // Get all jobs from database
  getAllJobs: async (limit = 50) => {
    return axios.get(`${API_BASE_URL}/db/jobs?limit=${limit}`);
  },

  // Get job summary from database
  getJobSummary: async (jobId) => {
    return axios.get(`${API_BASE_URL}/db/job/${jobId}`);
  },

  // Get predictions for a job (limit=0 means no limit, fetch all)
  getPredictions: async (jobId, verdict = null, attackType = null, limit = 0, offset = 0) => {
    let url = `${API_BASE_URL}/db/predictions/${jobId}?limit=${limit}&offset=${offset}`;
    if (verdict) url += `&verdict=${verdict}`;
    if (attackType) url += `&attack_type=${attackType}`;
    return axios.get(url);
  },

  // Get attack statistics for a job
  getAttackStats: async (jobId) => {
    return axios.get(`${API_BASE_URL}/db/attack-stats/${jobId}`);
  },

  // Get overall attack statistics
  getAllAttackStats: async () => {
    return axios.get(`${API_BASE_URL}/db/attack-stats`);
  },
};

// Health check
export const healthCheck = async () => {
  return axios.get(`${API_BASE_URL}/health`);
};

// Server logs
export const getServerLogs = async (lines = 100) => {
  return axios.get(`${API_BASE_URL}/server-logs?lines=${lines}`);
};

export default apiClient;
