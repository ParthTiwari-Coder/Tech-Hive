import React, { useState, useEffect, createContext, useContext, useRef } from 'react';
import { AlertCircle, Shield, Activity, Upload, BarChart3, Database, Lock, CheckCircle, XCircle, TrendingUp, FileText, Filter, Download, RefreshCw, Zap, Clock, Network } from 'lucide-react';

// Backend API URL - change this if backend runs on different port
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Context for global state management
const AppContext = createContext();

const useAppContext = () => {
  const context = useContext(AppContext);
  if (!context) throw new Error('useAppContext must be used within AppProvider');
  return context;
};

const AppProvider = ({ children }) => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [currentPrediction, setCurrentPrediction] = useState(null);
  const [threatLogs, setThreatLogs] = useState([]);
  const [modelStatus, setModelStatus] = useState('loading');
  const [metrics, setMetrics] = useState({
    totalFlows: 0,
    intrusionsDetected: 0,
    recallScore: 0,
    lastDetection: new Date().toISOString()
  });

  const value = {
    currentPage,
    setCurrentPage,
    currentPrediction,
    setCurrentPrediction,
    threatLogs,
    setThreatLogs,
    modelStatus,
    setModelStatus,
    metrics,
    setMetrics,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

// Navigation Component
const Navigation = () => {
  const { currentPage, setCurrentPage } = useAppContext();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'input', label: 'Data Input', icon: Upload },
    { id: 'logs', label: 'Threat Log', icon: FileText },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 }
  ];

  return (
    <nav className="bg-navbar-bg border-b border-navbar-border shadow-xl backdrop-blur-md px-6 py-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-accent-primary drop-shadow-neon-blue" />
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">
            IntrusionX AI
          </h1>
        </div>
      </div>
      <div className="flex gap-2 flex-wrap">
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md transition-all ${
                currentPage === item.id
                  ? 'bg-accent-primary text-bg-primary shadow-lg shadow-neon-blue border border-accent-primary/50'
                  : 'bg-panel-bg text-text-secondary hover:bg-table-row-hover hover:text-navbar-hover border border-card-border hover:border-accent-primary/30'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span className="text-sm font-medium">{item.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
};

// Dashboard Page - Connected to backend
const DashboardPage = () => {
  const { metrics, modelStatus, setModelStatus, setMetrics } = useAppContext();
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/api/dashboard`);
      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const data = await response.json();
      
      // Debug: Log the received data
      console.log('Dashboard data received:', data);
      console.log('Metrics:', data.metrics);
      
      setDashboardData(data);
      setModelStatus('online');
      
      // Update metrics from backend
      setMetrics(prev => ({
        ...prev,
        recallScore: data.metrics.recall || 0,
        intrusionsDetected: data.metrics.false_positives + Math.floor(Math.random() * 100),
      }));
      
      setError(null);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
      setError(err.message);
      setModelStatus('offline');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-accent-primary animate-spin mx-auto mb-4" />
          <p className="text-text-primary">Loading dashboard data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-6">
          <AlertCircle className="w-12 h-12 text-severity-high mx-auto mb-4" />
          <h3 className="text-xl font-bold text-text-primary text-center mb-2">Dashboard Error</h3>
          <p className="text-text-secondary text-center mb-4">{error}</p>
          <p className="text-text-muted text-sm text-center">Make sure to run nn.py first to train the model.</p>
          <div className="flex justify-center mt-4">
            <button
              onClick={fetchDashboardData}
              className="px-6 py-2 bg-btn-primary text-white rounded-lg hover:bg-btn-primary-hover"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  const cards = [
    { 
      title: 'Model Accuracy', 
      value: dashboardData?.metrics?.accuracy ? `${(dashboardData.metrics.accuracy * 100).toFixed(1)}%` : '0.0%', 
      icon: TrendingUp, 
      color: 'text-accent-primary', 
      iconBg: 'from-accent-primary to-accent-deep' 
    },
    { 
      title: 'Recall Score', 
      value: dashboardData?.metrics?.recall ? `${(dashboardData.metrics.recall * 100).toFixed(1)}%` : '0.0%', 
      icon: Shield, 
      color: 'text-severity-benign', 
      iconBg: 'from-severity-benign to-teal-deep' 
    },
    { 
      title: 'Precision', 
      value: dashboardData?.metrics?.precision ? `${(dashboardData.metrics.precision * 100).toFixed(1)}%` : '0.0%', 
      icon: Activity, 
      color: 'text-ai-cyan', 
      iconBg: 'from-ai-cyan to-teal-deep' 
    },
    { 
      title: 'Detection Threshold', 
      value: dashboardData?.metrics?.threshold ? dashboardData.metrics.threshold.toFixed(3) : '0.000', 
      icon: Zap, 
      color: 'text-accent-secondary', 
      iconBg: 'from-accent-secondary to-accent-secondary-deep' 
    }
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold text-text-primary">System Overview</h2>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-md backdrop-blur-sm ${
          modelStatus === 'online' 
            ? 'bg-toast-info-bg border border-toast-info-border shadow-lg shadow-neon-blue' 
            : 'bg-toast-error-bg border border-toast-error-border shadow-lg shadow-red-glow'
        }`}>
          <div className={`w-2 h-2 rounded-full ${modelStatus === 'online' ? 'bg-accent-primary animate-pulse shadow-lg shadow-neon-blue' : 'bg-severity-critical shadow-lg shadow-red-glow'}`} />
          <span className="text-sm font-medium text-text-primary">{modelStatus === 'online' ? 'Model Online' : 'Model Offline'}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div key={idx} className="bg-card-bg/80 backdrop-blur-sm rounded-lg p-6 border border-card-border hover:border-accent-primary transition-all shadow-xl hover:shadow-card-glow">
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-lg bg-gradient-to-br ${card.iconBg} shadow-lg`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
              </div>
              <p className="text-text-secondary text-sm mb-2 font-medium">{card.title}</p>
              <p className={`text-3xl font-bold ${card.color}`}>{card.value}</p>
            </div>
          );
        })}
      </div>

      {/* Confusion Matrix */}
      <div className="bg-card-bg/80 backdrop-blur-sm rounded-lg p-6 border border-card-border shadow-xl">
        <h3 className="text-xl font-bold text-text-primary mb-4 flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-accent-primary" />
          Confusion Matrix
        </h3>
        <img 
          src={`${API_BASE_URL}${dashboardData.images.confusion_matrix}?t=${Date.now()}`}
          alt="Confusion Matrix" 
          className="w-full rounded-lg border border-card-border"
        />
      </div>

      {/* Feature Importance */}
      <div className="bg-card-bg/80 backdrop-blur-sm rounded-lg p-6 border border-card-border shadow-xl">
        <h3 className="text-xl font-bold text-text-primary mb-4 flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-accent-primary" />
          Feature Importance
        </h3>
        <img 
          src={`${API_BASE_URL}${dashboardData.images.feature_importance}?t=${Date.now()}`}
          alt="Feature Importance" 
          className="w-full rounded-lg border border-card-border"
        />
      </div>
    </div>
  );
};

// Data Input Page - Connected to backend
const DataInputPage = () => {
  const { setThreatLogs } = useAppContext();
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null); // Track which row is expanded
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file.name.endsWith('.csv')) {
      setError('Please upload a CSV file.');
      return;
    }

    setUploading(true);
    setError(null);
    setResults(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${API_BASE_URL}/api/detect`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Detection failed');
      }

      const data = await response.json();
      setResults(data);

      // Update threat logs in context
      const newLogs = data.intrusions.map((intrusion, idx) => ({
        id: Date.now() + idx,
        timestamp: new Date().toISOString(),
        sourceIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        destIp: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        protocol: 'TCP',
        classification: 'Intrusion',
        confidence: intrusion.intrusion_probability,
        action: intrusion.explanation,
        resolved: false,
        severity_name: intrusion.severity_name
      }));

      setThreatLogs(prev => [...newLogs, ...prev]);

    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="p-6 space-y-6">
      <h2 className="text-3xl font-bold text-text-primary">Network Flow Input</h2>

      <div
        className={`border-2 border-dashed rounded-lg p-12 text-center transition-all ${
          dragActive ? 'border-accent-primary bg-accent-primary/10' : 'border-card-border bg-card-bg'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        {uploading ? (
          <>
            <RefreshCw className="w-16 h-16 text-accent-primary mx-auto mb-4 animate-spin" />
            <p className="text-text-primary text-lg mb-2">Processing CSV file...</p>
            <p className="text-text-muted text-sm">This may take a few minutes for large files</p>
          </>
        ) : (
          <>
            <Upload className="w-16 h-16 text-accent-primary mx-auto mb-4" />
            <p className="text-text-primary text-lg mb-2">Drop CSV file here or click to upload</p>
            <p className="text-text-muted text-sm">Batch analyze network flows from CSV datasets</p>
            <input 
              type="file" 
              accept=".csv" 
              className="hidden" 
              ref={fileInputRef}
              onChange={handleFileSelect}
            />
            <button 
              onClick={handleBrowseClick}
              className="mt-4 px-6 py-2 bg-btn-primary text-white rounded-lg hover:bg-btn-primary-hover transition-colors shadow-lg shadow-neon-blue"
              disabled={uploading}
            >
              Browse Files
            </button>
          </>
        )}
      </div>

      {error && (
        <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-4">
          <p className="text-severity-high font-medium">{error}</p>
        </div>
      )}

      {results && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-card-bg rounded-lg p-6 border border-card-border">
              <p className="text-text-secondary text-sm mb-2">Total Samples</p>
              <p className="text-3xl font-bold text-text-primary">{results.summary.total_samples}</p>
            </div>
            <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-6">
              <p className="text-text-secondary text-sm mb-2">Intrusions Detected</p>
              <p className="text-3xl font-bold text-severity-high">{results.summary.intrusions}</p>
            </div>
            <div className="bg-toast-success-bg border border-toast-success-border rounded-lg p-6">
              <p className="text-text-secondary text-sm mb-2">Normal Traffic</p>
              <p className="text-3xl font-bold text-severity-benign">{results.summary.normals}</p>
            </div>
          </div>

          {/* Intrusions List */}
          {results.intrusions.length > 0 && (
            <div className="bg-card-bg rounded-lg p-6 border border-card-border">
              <h3 className="text-xl font-bold text-text-primary mb-4 flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-severity-high" />
                Detected Intrusions ({results.intrusions.length})
              </h3>
              <div className="space-y-3 max-h-[600px] overflow-y-auto">
                {results.intrusions.slice(0, 50).map((intrusion, idx) => (
                  <div key={idx} className="bg-bg-primary rounded-lg border border-card-border hover:border-accent-primary transition-all">
                    {/* Clickable Header */}
                    <div 
                      className="p-4 cursor-pointer"
                      onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <p className="text-text-primary font-semibold">Sample #{intrusion.sample_index}</p>
                            <span className={`inline-block px-3 py-1 rounded text-xs font-bold ${
                              intrusion.severity_level === 3 ? 'bg-severity-critical text-white' :
                              intrusion.severity_level === 2 ? 'bg-severity-high text-white' :
                              'bg-severity-medium text-bg-primary'
                            }`}>
                              {intrusion.severity_name}
                            </span>
                            <span className="text-text-secondary text-sm">
                              {(intrusion.intrusion_probability * 100).toFixed(1)}% confidence
                            </span>
                          </div>
                          <p className="text-text-muted text-sm">
                            Click to {expandedRow === idx ? 'collapse' : 'expand'} details
                          </p>
                        </div>
                        <div className="text-accent-primary">
                          {expandedRow === idx ? '▼' : '▶'}
                        </div>
                      </div>
                    </div>
                    
                    {/* Expanded Details */}
                    {expandedRow === idx && (
                      <div className="px-4 pb-4 space-y-4 border-t border-card-border pt-4">
                        {/* Analysis */}
                        {intrusion.explanation && (
                          <div className="bg-toast-info-bg border border-toast-info-border rounded-lg p-3">
                            <p className="text-xs font-semibold text-accent-primary mb-2 flex items-center gap-2">
                              <Activity className="w-4 h-4" />
                              ANALYSIS
                            </p>
                            <p className="text-sm text-text-primary">{intrusion.explanation}</p>
                          </div>
                        )}
                        
                        {/* Immediate Actions */}
                        {intrusion.immediate_actions && intrusion.immediate_actions.length > 0 && (
                          <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-3">
                            <p className="text-xs font-semibold text-severity-high mb-2 flex items-center gap-2">
                              <AlertCircle className="w-4 h-4" />
                              IMMEDIATE ACTIONS REQUIRED
                            </p>
                            <ol className="text-sm text-text-primary space-y-1 list-decimal list-inside">
                              {intrusion.immediate_actions.map((action, i) => (
                                <li key={i}>{action}</li>
                              ))}
                            </ol>
                          </div>
                        )}
                        
                        {/* Monitoring Recommendations */}
                        {intrusion.monitoring_actions && intrusion.monitoring_actions.length > 0 && (
                          <div className="bg-toast-warning-bg border border-toast-warning-border rounded-lg p-3">
                            <p className="text-xs font-semibold text-text-secondary mb-2 flex items-center gap-2">
                              <Shield className="w-4 h-4" />
                              MONITORING RECOMMENDATIONS
                            </p>
                            <ol className="text-sm text-text-primary space-y-1 list-decimal list-inside">
                              {intrusion.monitoring_actions.map((action, i) => (
                                <li key={i}>{action}</li>
                              ))}
                            </ol>
                          </div>
                        )}
                        
                        {/* Network Features (if available) */}
                        {intrusion.network_features && Object.keys(intrusion.network_features).length > 0 && (
                          <div className="bg-bg-secondary border border-card-border rounded-lg p-3">
                            <p className="text-xs font-semibold text-accent-secondary mb-2 flex items-center gap-2">
                              <Network className="w-4 h-4" />
                              SUSPICIOUS INDICATORS
                            </p>
                            <div className="grid grid-cols-2 gap-2 text-xs">
                              {Object.entries(intrusion.network_features).slice(0, 6).map(([key, value]) => (
                                <div key={key} className="flex justify-between">
                                  <span className="text-text-muted">{key}:</span>
                                  <span className="text-text-primary font-mono">{typeof value === 'number' ? value.toFixed(2) : value}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {/* Action Summary */}
                        {intrusion.action && (
                          <div className="bg-card-bg border border-accent-primary/30 rounded-lg p-3">
                            <p className="text-xs font-semibold text-text-secondary mb-2">ACTION SUMMARY</p>
                            <p className="text-sm text-text-primary">{intrusion.action}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Threat Log Page - Connected to backend
const ThreatLogPage = () => {
  const { threatLogs } = useAppContext();
  const [blockchainData, setBlockchainData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ protocol: 'All', search: '' });
  const [currentPageNum, setCurrentPageNum] = useState(1);
  const itemsPerPage = 10;

  useEffect(() => {
    fetchBlockchainData();
  }, []);

  const fetchBlockchainData = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/threat-log/latest`);
      const data = await response.json();
      setBlockchainData(data);
    } catch (err) {
      console.error('Error fetching blockchain:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadJSON = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/threat-log/latest?download=true`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `blockchain_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  const displayLogs = blockchainData?.blocks || threatLogs;
  const filteredLogs = displayLogs.filter(log => {
    if (filters.search && !log.sourceIp?.includes(filters.search) && !log.destIp?.includes(filters.search)) return false;
    return true;
  });

  const paginatedLogs = filteredLogs.slice((currentPageNum - 1) * itemsPerPage, currentPageNum * itemsPerPage);
  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <RefreshCw className="w-12 h-12 text-accent-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold text-text-primary">Blockchain Threat Log</h2>
        <button 
          onClick={handleDownloadJSON}
          className="px-4 py-2 bg-btn-primary text-white rounded-lg hover:bg-btn-primary-hover flex items-center gap-2 shadow-lg shadow-neon-blue"
          disabled={!blockchainData?.file}
        >
          <Download className="w-4 h-4" />
          Download JSON
        </button>
      </div>

      {blockchainData?.info && (
        <div className="bg-card-bg rounded-lg p-6 border border-accent-primary/50">
          <h3 className="text-lg font-bold text-text-primary mb-3 flex items-center gap-2">
            <Lock className="w-5 h-5 text-accent-primary" />
            Blockchain Info
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-text-secondary text-sm">Total Blocks</p>
              <p className="text-xl font-bold text-text-primary">{blockchainData.info.total_blocks || 0}</p>
            </div>
            <div>
              <p className="text-text-secondary text-sm">Intrusions Logged</p>
              <p className="text-xl font-bold text-severity-high">{blockchainData.info.total_intrusions || 0}</p>
            </div>
            <div>
              <p className="text-text-secondary text-sm">Chain Valid</p>
              <p className="text-xl font-bold text-severity-benign">
                {blockchainData.info.is_valid ? '✅ Yes' : '❌ No'}
              </p>
            </div>
            <div>
              <p className="text-text-secondary text-sm">Export Time</p>
              <p className="text-sm font-mono text-text-secondary">
                {blockchainData.info.export_timestamp ? new Date(blockchainData.info.export_timestamp).toLocaleString() : 'N/A'}
              </p>
            </div>
          </div>
        </div>
      )}

      {paginatedLogs.length === 0 ? (
        <div className="bg-card-bg rounded-lg p-12 text-center border border-card-border">
          <FileText className="w-16 h-16 text-text-muted mx-auto mb-4" />
          <p className="text-text-secondary">No threat logs found</p>
          <p className="text-text-muted text-sm mt-2">Upload a CSV in Data Input to generate logs</p>
        </div>
      ) : (
        <>
          <div className="bg-card-bg rounded-lg border border-card-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-table-header-bg">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm font-medium text-table-header-text">Timestamp</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-table-header-text">Sample</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-table-header-text">Severity</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-table-header-text">Confidence</th>
                    <th className="px-4 py-3 text-left text-sm font-medium text-table-header-text">Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-table-border">
                  {paginatedLogs.map((log, idx) => (
                    <tr key={log.id || idx} className="bg-table-row-bg hover:bg-table-row-hover transition-colors">
                      <td className="px-4 py-3 text-sm text-text-secondary">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-sm text-accent-primary font-mono">
                        {log.sample_index !== undefined ? `#${log.sample_index}` : log.id}
                      </td>
                      <td className="px-4 py-3 text-sm">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          log.type?.includes('HIGH') || log.severity_name?.includes('HIGH') ? 'bg-severity-high/20 text-severity-high' :
                          log.type?.includes('MEDIUM') || log.severity_name?.includes('MEDIUM') ? 'bg-severity-medium/20 text-severity-medium' :
                          'bg-severity-low/20 text-severity-low'
                        }`}>
                          {log.type || log.severity_name || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-text-secondary">
                        {((log.confidence || 0) * 100).toFixed(1)}%
                      </td>
                      <td className="px-4 py-3 text-xs text-ai-cyan font-mono">
                        {log.hash ? `${log.hash.substring(0, 20)}...` : 'N/A'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="flex justify-between items-center">
            <p className="text-text-secondary text-sm">
              Showing {(currentPageNum - 1) * itemsPerPage + 1} to {Math.min(currentPageNum * itemsPerPage, filteredLogs.length)} of {filteredLogs.length} entries
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentPageNum(Math.max(1, currentPageNum - 1))}
                disabled={currentPageNum === 1}
                className="px-4 py-2 bg-panel-bg text-text-secondary rounded-lg hover:bg-table-row-hover disabled:opacity-50"
              >
                Previous
              </button>
              <span className="px-4 py-2 bg-card-bg text-text-secondary rounded-lg">
                Page {currentPageNum} of {totalPages || 1}
              </span>
              <button
                onClick={() => setCurrentPageNum(Math.min(totalPages, currentPageNum + 1))}
                disabled={currentPageNum === totalPages}
                className="px-4 py-2 bg-panel-bg text-text-secondary rounded-lg hover:bg-table-row-hover disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

// Analytics Page - Connected to backend
const AnalyticsPage = () => {
  const [uploading, setUploading] = useState(false);
  const [analytics, setAnalytics] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileUpload = async (file) => {
    if (!file.name.endsWith('.csv')) {
      setError('Please upload a CSV file.');
      return;
    }

    setUploading(true);
    setError(null);
    setAnalytics(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${API_BASE_URL}/api/analytics/shap`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'SHAP analysis failed');
      }

      const data = await response.json();
      setAnalytics(data);

    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h2 className="text-3xl font-bold text-text-primary">Analytics & Explainability</h2>

      {/* Upload Section */}
      <div className="bg-card-bg rounded-lg p-6 border border-card-border">
        <h3 className="text-lg font-bold text-text-primary mb-4">Upload CSV for SHAP Analysis</h3>
        <input 
          type="file" 
          accept=".csv" 
          className="hidden" 
          ref={fileInputRef}
          onChange={(e) => e.target.files[0] && handleFileUpload(e.target.files[0])}
        />
        <button 
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="px-6 py-2 bg-btn-primary text-white rounded-lg hover:bg-btn-primary-hover disabled:opacity-50 flex items-center gap-2"
        >
          {uploading ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Processing (this may take several minutes)...
            </>
          ) : (
            <>
              <Upload className="w-4 h-4" />
              Select CSV File
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-4">
          <p className="text-severity-high font-medium">{error}</p>
        </div>
      )}

      {analytics && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-card-bg rounded-lg p-6 border border-card-border">
              <p className="text-text-secondary text-sm mb-2">Total Samples</p>
              <p className="text-3xl font-bold text-text-primary">{analytics.summary.total}</p>
            </div>
            <div className="bg-toast-error-bg border border-toast-error-border rounded-lg p-6">
              <p className="text-text-secondary text-sm mb-2">Intrusions</p>
              <p className="text-3xl font-bold text-severity-high">{analytics.summary.intrusions}</p>
            </div>
            <div className="bg-toast-success-bg border border-toast-success-border rounded-lg p-6">
              <p className="text-text-secondary text-sm mb-2">Normal Traffic</p>
              <p className="text-3xl font-bold text-severity-benign">{analytics.summary.normals}</p>
            </div>
          </div>

          {/* SHAP Visualizations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {analytics.images.global_importance && (
              <div className="bg-card-bg rounded-lg p-6 border border-card-border">
                <h3 className="text-xl font-bold text-text-primary mb-4">Global Feature Importance</h3>
                <img 
                  src={`${API_BASE_URL}${analytics.images.global_importance}?t=${Date.now()}`}
                  alt="Global Feature Importance" 
                  className="w-full rounded-lg border border-card-border"
                />
              </div>
            )}

            {analytics.images.category_importance && (
              <div className="bg-card-bg rounded-lg p-6 border border-card-border">
                <h3 className="text-xl font-bold text-text-primary mb-4">Category Importance</h3>
                <img 
                  src={`${API_BASE_URL}${analytics.images.category_importance}?t=${Date.now()}`}
                  alt="Category Importance" 
                  className="w-full rounded-lg border border-card-border"
                />
              </div>
            )}
          </div>

          {/* SHAP Summary Plots */}
          <div className="grid grid-cols-1 gap-6">
            {analytics.images.shap_beeswarm && (
              <div className="bg-card-bg rounded-lg p-6 border border-card-border">
                <h3 className="text-xl font-bold text-text-primary mb-4">SHAP Beeswarm Plot</h3>
                <img 
                  src={`${API_BASE_URL}${analytics.images.shap_beeswarm}?t=${Date.now()}`}
                  alt="SHAP Beeswarm" 
                  className="w-full rounded-lg border border-card-border"
                />
              </div>
            )}

            {analytics.images.intrusion_vs_normal && (
              <div className="bg-card-bg rounded-lg p-6 border border-card-border">
                <h3 className="text-xl font-bold text-text-primary mb-4">Intrusion vs Normal Comparison</h3>
                <img 
                  src={`${API_BASE_URL}${analytics.images.intrusion_vs_normal}?t=${Date.now()}`}
                  alt="Intrusion vs Normal" 
                  className="w-full rounded-lg border border-card-border"
                />
              </div>
            )}
          </div>

          {/* SHAP Log Output */}
          {analytics.log && (
            <div className="bg-card-bg rounded-lg p-6 border border-card-border">
              <h3 className="text-xl font-bold text-text-primary mb-4 flex items-center gap-2">
                <FileText className="w-5 h-5 text-accent-primary" />
                Analysis Log
              </h3>
              <pre className="bg-bg-primary text-text-secondary text-xs p-4 rounded-lg border border-card-border max-h-80 overflow-auto whitespace-pre-wrap font-mono">
                {analytics.log}
              </pre>
            </div>
          )}

          {/* Model Explanation */}
          <div className="bg-card-bg rounded-lg p-6 border border-card-border">
            <h3 className="text-xl font-bold text-text-primary mb-4">Model Explanation</h3>
            <div className="space-y-3">
              <details className="bg-bg-primary rounded-lg overflow-hidden">
                <summary className="px-4 py-3 cursor-pointer hover:bg-table-row-hover transition-colors text-text-secondary font-medium">
                  How does SHAP explain feature importance?
                </summary>
                <div className="px-4 py-3 text-text-secondary text-sm border-t border-card-border">
                  SHAP (SHapley Additive exPlanations) values show how much each feature contributed to pushing the model's prediction toward intrusion or normal. 
                  Positive SHAP values push toward intrusion detection, while negative values push toward normal classification. 
                  The magnitude indicates the strength of the feature's impact on the prediction.
                </div>
              </details>
              <details className="bg-bg-primary rounded-lg overflow-hidden">
                <summary className="px-4 py-3 cursor-pointer hover:bg-table-row-hover transition-colors text-text-secondary font-medium">
                  What do the visualizations mean?
                </summary>
                <div className="px-4 py-3 text-text-secondary text-sm border-t border-card-border">
                  The beeswarm plot shows feature importance across all samples - red dots indicate high feature values, blue indicates low values.
                  The category importance chart groups related network features (traffic volume, connection metrics, etc.) to show which types of features 
                  are most critical for intrusion detection in your dataset.
                </div>
              </details>
              <details className="bg-bg-primary rounded-lg overflow-hidden">
                <summary className="px-4 py-3 cursor-pointer hover:bg-table-row-hover transition-colors text-text-secondary font-medium">
                  How can I use these insights?
                </summary>
                <div className="px-4 py-3 text-text-secondary text-sm border-t border-card-border">
                  Understanding which features are most important helps you focus monitoring efforts on the most critical network indicators.
                  If certain features consistently trigger intrusion detection, you can create targeted alerts or policies around those specific metrics.
                  The intrusion vs normal comparison shows you what distinguishes malicious traffic from legitimate traffic in your network.
                </div>
              </details>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Main App Component
const App = () => {
  const { currentPage } = useAppContext();

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard': return <DashboardPage />;
      case 'input': return <DataInputPage />;
      case 'logs': return <ThreatLogPage />;
      case 'analytics': return <AnalyticsPage />;
      default: return <DashboardPage />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-bg-primary via-bg-secondary to-bg-primary">
      <Navigation />
      <main className="max-w-7xl mx-auto">
        {renderPage()}
      </main>
    </div>
  );
};

// Root Component with Provider
export default function Root() {
  return (
    <AppProvider>
      <App />
    </AppProvider>
  );
}