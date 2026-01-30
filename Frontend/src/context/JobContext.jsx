import { createContext, useContext, useState } from 'react';

const JobContext = createContext();

export const JobProvider = ({ children }) => {
    const [jobId, setJobId] = useState(null);
    const [jobStatus, setJobStatus] = useState('idle'); // idle, uploading, processing, completed, failed
    const [analysisResult, setAnalysisResult] = useState(null);
    const [mergedData, setMergedData] = useState(null); // For future use if we load the full CSV

    const resetJob = () => {
        setJobId(null);
        setJobStatus('idle');
        setAnalysisResult(null);
        setMergedData(null);
    };

    const updateJobStatus = (status, result = null) => {
        setJobStatus(status);
        if (result) {
            setAnalysisResult(result);
        }
    };

    return (
        <JobContext.Provider value={{
            jobId,
            setJobId,
            jobStatus,
            updateJobStatus,
            analysisResult,
            setAnalysisResult,
            mergedData,
            setMergedData,
            resetJob
        }}>
            {children}
        </JobContext.Provider>
    );
};

export const useJob = () => {
    const context = useContext(JobContext);
    if (!context) {
        throw new Error('useJob must be used within a JobProvider');
    }
    return context;
};
