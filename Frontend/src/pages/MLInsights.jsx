import React, { useEffect, useState } from 'react';
import { useJob } from '../context/JobContext';
import { databaseService } from '../services/api';
import {
    ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, Legend, LineChart, Line
} from 'recharts';
import '../styles/ml-insights.css';

const MLInsights = () => {
    const { jobId } = useJob();
    const [loading, setLoading] = useState(true);
    const [layer1Stats, setLayer1Stats] = useState([]);
    const [layer2Data, setLayer2Data] = useState([]);
    const [layer3Data, setLayer3Data] = useState([]);

    useEffect(() => {
        const fetchMLData = async () => {
            if (!jobId) return;

            try {
                setLoading(true);
                // Fetch valid predictions 
                const response = await databaseService.getPredictions(jobId, 500); // Sample 500
                const data = response.data.predictions;

                if (!data) return;

                // Layer 1: Signature Hits
                const sigHits = data.filter(p => p.layer1_detected).length;
                const sigMiss = data.length - sigHits;
                setLayer1Stats([
                    { name: 'Detected', value: sigHits, fill: '#ef4444' },
                    { name: 'Passed', value: sigMiss, fill: '#3b82f6' }
                ]);

                // Layer 2: Autoencoder (Anomaly Score vs Reconstruction Error)
                // Filter out extreme outliers for better visualization or use log scale
                const l2 = data
                    .filter(p => p.layer2_anomaly_score != null)
                    .map(p => ({
                        x: p.layer2_reconstruction_error,
                        y: p.layer2_anomaly_score,
                        isAnomaly: p.layer2_status === 'Anomaly' // Color coding
                    }));
                setLayer2Data(l2);

                // Layer 3: Bi-LSTM Probability Distribution
                // Binning the probabilities
                const l3Bins = Array(10).fill(0);
                data.forEach(p => {
                    if (p.layer3_prob_malicious != null) {
                        const binIndex = Math.min(Math.floor(p.layer3_prob_malicious * 10), 9);
                        l3Bins[binIndex]++;
                    }
                });

                setLayer3Data(l3Bins.map((count, i) => ({
                    range: `${i * 10}-${(i + 1) * 10}%`,
                    count
                })));

            } catch (error) {
                console.error("Error fetching ML data:", error);
            } finally {
                setLoading(false);
            }
        };

        fetchMLData();
    }, [jobId]);

    if (loading) return <div className="loading-spinner">Decrypting Neural Pathways...</div>;

    return (
        <div className="ml-container">

            {/* Architecture Diagram / Flow */}
            <div className="pipeline-flow">
                <div className="stage">
                    <div className="stage-title">Layer 1: Signature</div>
                    <div className="stage-desc">Known Patterns</div>
                </div>
                <div className="arrow">→</div>
                <div className="stage">
                    <div className="stage-title">Layer 2: Autoencoder</div>
                    <div className="stage-desc">Anomaly Detection</div>
                </div>
                <div className="arrow">→</div>
                <div className="stage">
                    <div className="stage-title">Layer 3: Bi-LSTM</div>
                    <div className="stage-desc">Sequence Analysis</div>
                </div>
                <div className="arrow">→</div>
                <div className="stage final">
                    <div className="stage-title">Meta-Classifier</div>
                    <div className="stage-desc">Final Verdict</div>
                </div>
            </div>

            <div className="charts-grid-ml">
                {/* Layer 1 Stats */}
                <div className="dashboard-card chart-card">
                    <h3>Layer 1: Signature Filter Efficiency</h3>
                    <div style={{ width: '100%', height: 250 }}>
                        <ResponsiveContainer>
                            <BarChart data={layer1Stats}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                <XAxis dataKey="name" stroke="#a0aec0" />
                                <YAxis stroke="#a0aec0" />
                                <Tooltip contentStyle={{ backgroundColor: '#2d3748', border: 'none' }} />
                                <Bar dataKey="value" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                    <p className="chart-note">
                        Traffic stopped immediately by known attack signatures.
                    </p>
                </div>

                {/* Layer 2 Scatter */}
                <div className="dashboard-card chart-card">
                    <h3>Layer 2: Autoencoder Manifold</h3>
                    <div style={{ width: '100%', height: 250 }}>
                        <ResponsiveContainer>
                            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                <XAxis type="number" dataKey="x" name="Reconstruction Error" stroke="#a0aec0" />
                                <YAxis type="number" dataKey="y" name="Anomaly Score" stroke="#a0aec0" />
                                <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#2d3748', border: 'none' }} />
                                <Legend />
                                <Scatter name="Normal" data={layer2Data.filter(d => !d.isAnomaly)} fill="#10b981" />
                                <Scatter name="Anomaly" data={layer2Data.filter(d => d.isAnomaly)} fill="#ef4444" shape="cross" />
                            </ScatterChart>
                        </ResponsiveContainer>
                    </div>
                    <p className="chart-note">
                        Visualization of statistical deviations. High reconstruction error indicates identifying unknown attacks.
                    </p>
                </div>

                {/* Layer 3 Histogram */}
                <div className="dashboard-card chart-card">
                    <h3>Layer 3: Bi-LSTM Confidence Distribution</h3>
                    <div style={{ width: '100%', height: 250 }}>
                        <ResponsiveContainer>
                            <BarChart data={layer3Data}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                                <XAxis dataKey="range" stroke="#a0aec0" label={{ value: 'Malicious Probability %', position: 'insideBottom', offset: -5 }} />
                                <YAxis stroke="#a0aec0" />
                                <Tooltip contentStyle={{ backgroundColor: '#2d3748', border: 'none' }} />
                                <Bar dataKey="count" fill="#8884d8" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                    <p className="chart-note">
                        Distribution of malicious probability scores assigned by the Deep Learning model.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default MLInsights;
