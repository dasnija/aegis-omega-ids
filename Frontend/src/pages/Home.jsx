import React, { useEffect, useState } from 'react';
import { useJob } from '../context/JobContext';
import PCAPUpload from '../components/PCAPUpload';
import { pcapService } from '../services/api';

const Home = () => {
    const { setJobId, updateJobStatus } = useJob();
    const [activeJobId, setActiveJobId] = useState(null);

    const handleUploadStart = () => {
        updateJobStatus('uploading');
    };

    const handleUploadComplete = async (data) => {
        console.log("Upload Complete:", data);
        setJobId(data.job_id);
        setActiveJobId(data.job_id);
        updateJobStatus('completed');

        // Here we could fetch the initial result set if needed
        try {
            // Small delay to ensure backend is ready
            setTimeout(async () => {
                const result = await pcapService.getResults(data.job_id);
                updateJobStatus('completed', result.data);
            }, 1000);
        } catch (error) {
            console.error("Failed to fetch initial results:", error);
        }
    };

    return (
        <div className="home-container">
            <div className="welcome-section" style={{ textAlign: 'center', marginBottom: '3rem' }}>
                <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Network Threat Hunter</h1>
                <p style={{ color: '#a0aec0', fontSize: '1.1rem' }}>
                    Advanced Hybrid IDS powered by Deep Learning. Upload a PCAP file to detect anomalies,
                    identify attack patterns, and visualize network traffic.
                </p>
            </div>

            <PCAPUpload
                onUploadStart={handleUploadStart}
                onUploadComplete={handleUploadComplete}
            />
        </div>
    );
};

export default Home;
