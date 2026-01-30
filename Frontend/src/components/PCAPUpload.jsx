import React, { useState, useEffect, useRef } from 'react';
import { pcapService } from '../services/api';
import '../styles/pcap-upload.css';

export default function PCAPUpload({ onUploadStart, onUploadComplete }) {
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [processingProgress, setProcessingProgress] = useState(0);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);
    const [status, setStatus] = useState('idle'); // idle, uploading, processing, completed, failed
    const [message, setMessage] = useState('');
    const [jobId, setJobId] = useState(null);
    const [stats, setStats] = useState(null);
    const pollingRef = useRef(null);

    // Cleanup polling on unmount
    useEffect(() => {
        return () => {
            if (pollingRef.current) {
                clearInterval(pollingRef.current);
            }
        };
    }, []);

    const handleFileSelect = (event) => {
        const selectedFile = event.target.files[0];
        if (selectedFile) {
            const validExtensions = ['.pcap', '.pcapng', '.cap'];
            const fileExt = selectedFile.name.substring(selectedFile.name.lastIndexOf('.')).toLowerCase();

            if (!validExtensions.includes(fileExt)) {
                setError('⚠️ Please select a valid PCAP file (.pcap, .pcapng, or .cap)');
                setFile(null);
                return;
            }

            if (selectedFile.size > 1000 * 1024 * 1024) {
                setError('⚠️ File too large (max 1GB)');
                setFile(null);
                return;
            }

            setFile(selectedFile);
            setError(null);
            setSuccess(null);
            setMessage('');
            setStats(null);
            setStatus('idle');
            setUploadProgress(0);
            setProcessingProgress(0);
        }
    };

    const pollJobStatus = async (id) => {
        try {
            const response = await pcapService.getStatus(id);
            const jobStatus = response.data;

            setProcessingProgress(jobStatus.progress);
            setMessage(jobStatus.message);

            if (jobStatus.status === 'completed') {
                clearInterval(pollingRef.current);
                pollingRef.current = null;

                setStatus('completed');
                setStats(jobStatus.stats);
                setSuccess(`✅ Analysis complete! Detected ${jobStatus.stats?.malicious_count || 0} malicious flows.`);
                setLoading(false);

                // Notify parent component
                if (onUploadComplete) {
                    onUploadComplete({
                        job_id: id,
                        total_packets: jobStatus.stats?.total_flows || 0,
                        malicious_count: jobStatus.stats?.malicious_count || 0,
                        benign_count: jobStatus.stats?.benign_count || 0,
                        stats: jobStatus.stats
                    });
                }
            } else if (jobStatus.status === 'failed') {
                clearInterval(pollingRef.current);
                pollingRef.current = null;

                setStatus('failed');
                setError(`❌ Processing failed: ${jobStatus.error || 'Unknown error'}`);
                setLoading(false);

                // Fetch and log detailed error information
                try {
                    const logsResponse = await pcapService.getLogs(id);
                    console.error('Job Logs:', logsResponse.data);
                    if (logsResponse.data.error_traceback) {
                        console.error('Traceback:', logsResponse.data.error_traceback);
                    }
                } catch (logError) {
                    console.error('Failed to fetch job logs:', logError);
                }
            }
        } catch (error) {
            console.error('Error polling status:', error);
        }
    };

    const handleUpload = async () => {
        if (!file) {
            setError('⚠️ Please select a file first');
            return;
        }

        setLoading(true);
        setError(null);
        setSuccess(null);
        setUploadProgress(0);
        setProcessingProgress(0);
        setStatus('uploading');

        // Notify parent component
        if (onUploadStart) {
            onUploadStart();
        }

        try {
            console.log(file, "jhwbhwb");
            // Upload the file
            setMessage('Uploading file...');
            const uploadResponse = await pcapService.upload(file, (progress) => {
                setUploadProgress(progress);
            });
            console.log(uploadResponse, "uploadResponse");

            const newJobId = uploadResponse.data.job_id;
            setJobId(newJobId);
            setUploadProgress(100);
            setStatus('processing');
            setMessage('File uploaded. Starting analysis...');

            // Start polling for job status
            pollingRef.current = setInterval(() => {
                pollJobStatus(newJobId);
            }, 2000);

            // Initial poll
            await pollJobStatus(newJobId);

        } catch (error) {
            setStatus('failed');
            const errorMsg = error.response?.data?.detail || error.message || 'Upload failed';
            setError(`❌ Error: ${errorMsg}`);
            setLoading(false);

            if (pollingRef.current) {
                clearInterval(pollingRef.current);
                pollingRef.current = null;
            }
        }
    };

    const handleDownload = async () => {
        if (!jobId) return;

        try {
            await pcapService.downloadResults(jobId);
        } catch (error) {
            setError('❌ Failed to download results');
        }
    };

    const handleDownloadMergedCSV = async () => {
        if (!jobId) return;

        try {
            await pcapService.downloadMergedCSV(jobId, file?.name || 'results');
        } catch (error) {
            setError('❌ Failed to download merged CSV');
        }
    };

    const handleReset = () => {
        setFile(null);
        setLoading(false);
        setUploadProgress(0);
        setProcessingProgress(0);
        setError(null);
        setSuccess(null);
        setStatus('idle');
        setMessage('');
        setJobId(null);
        setStats(null);

        if (pollingRef.current) {
            clearInterval(pollingRef.current);
            pollingRef.current = null;
        }
    };

    const getProgressPercent = () => {
        if (status === 'uploading') {
            return Math.round(uploadProgress * 0.3); // 0-30%
        } else if (status === 'processing') {
            return 30 + Math.round(processingProgress * 0.7); // 30-100%
        } else if (status === 'completed') {
            return 100;
        }
        return 0;
    };

    return (
        <div className="pcap-upload-container">
            <div className="upload-card">
                <h2>📁 Upload PCAP File</h2>
                <p className="subtitle">Upload a PCAP file to analyze network traffic for malicious activity</p>

                <label className="file-input-label">
                    <input
                        type="file"
                        accept=".pcap,.pcapng,.cap"
                        onChange={handleFileSelect}
                        disabled={loading}
                    />
                    {!file && (
                        <div className="file-input-display">
                            <div className="upload-icon">📤</div>
                            <p>Click to select or drag & drop</p>
                            <p className="file-hint">.pcap, .pcapng, or .cap files (max 1GB)</p>
                        </div>
                    )}
                </label>

                {file && status === 'idle' && (
                    <div className="message ready">
                        📦 <strong>{file.name}</strong> ({(file.size / 1024 / 1024).toFixed(2)} MB)
                    </div>
                )}

                {/* Progress Bar */}
                {(status === 'uploading' || status === 'processing') && (
                    <div className="progress-section">
                        <div className="progress-bar-container">
                            <div
                                className="progress-bar"
                                style={{ width: `${getProgressPercent()}%` }}
                            >
                                <span className="progress-text">{getProgressPercent()}%</span>
                            </div>
                        </div>
                        {message && <p className="progress-message">{message}</p>}
                    </div>
                )}

                {/* Status Messages */}
                {error && <div className="message error">{error}</div>}
                {success && <div className="message success">{success}</div>}

                {/* Stats Display */}
                {stats && status === 'completed' && (
                    <div className="stats-container">
                        <h3>📊 Analysis Results</h3>
                        <div className="stat-item">
                            <span className="stat-label">Total Flows</span>
                            <span className="stat-value">{stats.total_flows}</span>
                        </div>
                        <div className="stat-item malicious">
                            <span className="stat-label">Malicious</span>
                            <span className="stat-value">{stats.malicious_count}</span>
                        </div>
                        <div className="stat-item benign">
                            <span className="stat-label">Benign</span>
                            <span className="stat-value">{stats.benign_count}</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-label">Detection Rate</span>
                            <span className="stat-value">{stats.detection_rate}%</span>
                        </div>
                    </div>
                )}

                <div className="button-row">
                    {status !== 'completed' && (
                        <button
                            className="btn-primary"
                            onClick={handleUpload}
                            disabled={!file || loading}
                        >
                            {loading ? '⏳ Analyzing...' : '🚀 Analyze PCAP'}
                        </button>
                    )}

                    {status === 'completed' && (
                        <>
                            <button className="btn-success" onClick={handleDownload}>
                                📥 Download JSON Results
                            </button>
                            <button className="btn-primary" onClick={handleDownloadMergedCSV}>
                                📊 Download Merged CSV
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

                {jobId && (
                    <div className="job-info">
                        <small>Job ID: <code>{jobId}</code></small>
                    </div>
                )}
            </div>
        </div>
    );
}
