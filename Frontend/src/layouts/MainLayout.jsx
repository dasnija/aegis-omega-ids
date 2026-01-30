import React, { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { useJob } from '../context/JobContext';
import {
    LayoutDashboard,
    ShieldAlert,
    Network,
    FileSearch,
    BrainCircuit,
    Upload
} from 'lucide-react';
import '../styles/layout.css';

const MainLayout = () => {
    const { jobStatus } = useJob();
    const location = useLocation();
    const [sidebarOpen, setSidebarOpen] = useState(true);

    const isAnalysisReady = jobStatus === 'completed';

    const navItems = [
        { path: '/', label: 'Upload & Process', icon: <Upload size={20} />, disabled: false },
        { path: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={20} />, disabled: !isAnalysisReady },
        { path: '/ml-insights', label: 'ML Insights', icon: <BrainCircuit size={20} />, disabled: !isAnalysisReady },
    ];

    return (
        <div className="app-container">
            <aside className={`sidebar ${sidebarOpen ? 'open' : 'collapsed'}`}>
                <div className="sidebar-header">
                    <h1 className="logo-text">{sidebarOpen ? 'Hybrid IDS' : 'H'}</h1>
                    <button className="toggle-btn" onClick={() => setSidebarOpen(!sidebarOpen)}>
                        {sidebarOpen ? '«' : '»'}
                    </button>
                </div>

                <nav className="sidebar-nav">
                    {navItems.map((item) => (
                        <Link
                            key={item.path}
                            to={item.disabled ? '#' : item.path}
                            className={`nav-item ${location.pathname === item.path ? 'active' : ''} ${item.disabled ? 'disabled' : ''}`}
                            title={!sidebarOpen ? item.label : ''}
                        >
                            <span className="nav-icon">{item.icon}</span>
                            {sidebarOpen && <span className="nav-label">{item.label}</span>}
                        </Link>
                    ))}
                </nav>

                <div className="sidebar-footer">
                    {sidebarOpen && <div className="status-indicator">
                        <span className={`status-dot ${jobStatus}`}></span>
                        <span className="status-text">{jobStatus.toUpperCase()}</span>
                    </div>}
                </div>
            </aside>

            <main className="main-content">
                <header className="top-bar">
                    <h2 className="page-title">
                        {navItems.find(item => item.path === location.pathname)?.label || 'Dashboard'}
                    </h2>
                </header>
                <div className="content-area">
                    <Outlet />
                </div>
            </main>
        </div>
    );
};

export default MainLayout;
