import React, { useState, useEffect, useCallback, memo } from 'react';
import axios from 'axios';
import ReactFlow, {
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    Handle,
    Position,
    MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import './App.css';

const API_URL = 'http://192.168.46.129:5001/api'; // Ensure this is your VM's IP

const filterVulnerabilities = (eventEntry) => eventEntry[0] && eventEntry[0].vulnerability;

// Custom Node Component for React Flow
const CustomNode = memo(({ data }) => { 
    let icon = '❓';
    let nodeClass = 'node-default';

    if (data.type === 'controller') {
        icon = '🧠'; 
        nodeClass = 'node-controller';
    } else if (data.type === 'switch') {
        icon = '⇄'; 
        nodeClass = 'node-switch';
    } else if (data.type === 'host') {
        icon = '💻'; 
        nodeClass = 'node-host';
    }

    return (
        <div className={`custom-node ${nodeClass}`} title={data.raw_label || data.label}> {/* Tooltip shows raw_label */}
            <div className="node-icon">{icon}</div>
            <div className="node-label-main">{data.label}</div> {/* Main display label (e.g., "Controller", "Host X") */}
            {/* Handles for edges - adjust as needed for your desired layout and connection points */}
            <Handle type="target" position={Position.Top} id={`${data.type}-target-top`} />
            <Handle type="source" position={Position.Bottom} id={`${data.type}-source-bottom`} />
            {data.type === 'switch' && ( // Switches might need more connection points
                <>
                    <Handle type="target" position={Position.Left} id="switch-target-left" />
                    <Handle type="source" position={Position.Left} id="switch-source-left" />
                    <Handle type="target" position={Position.Right} id="switch-target-right" />
                    <Handle type="source" position={Position.Right} id="switch-source-right" />
                </>
            )}
        </div>
    );
});

const nodeTypes = {
    custom: CustomNode,
};

const Dashboard = ({ handleFixClick }) => {
    const [data, setData] = useState({ timestamp: 'N/A', events: [] });
    const fetchDashboardData = useCallback(() => {
        axios.get(`${API_URL}/dashboard`)
            .then(res => setData(res.data))
            .catch(err => {
                console.error("Error fetching dashboard data:", err);
                setData({ timestamp: 'Error loading data', events: [] });
            });
    }, []);
    useEffect(() => {
        fetchDashboardData();
        const interval = setInterval(fetchDashboardData, 7000);
        return () => clearInterval(interval);
    }, [fetchDashboardData]);
    const vulnerabilities = Array.isArray(data.events) ? data.events.filter(filterVulnerabilities) : [];
    return (
        <div className="tab-content">
            <h2>Dashboard - Latest Scan</h2>
            <p className="timestamp">Last Scan: {data.timestamp || 'Not available'}</p>
            <table>
                <thead>
                    <tr>
                        <th>Target IP</th><th>Vulnerability</th><th>Severity</th><th>Details / Outcome</th><th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {vulnerabilities.length > 0 ? vulnerabilities.map((event, index) => {
                        const [scanData, actionAttempted, actionOutcome] = event;
                        return (
                            <tr key={index} className={`severity-${scanData.severity?.toLowerCase()}`}>
                                <td>{scanData.ip || 'N/A'}</td><td>{scanData.vulnerability}</td>
                                <td>{scanData.severity || 'N/A'}</td><td>{actionOutcome || scanData.details}</td>
                                <td><button onClick={() => handleFixClick(scanData)} className="fix-button">Attempt Fix</button></td>
                            </tr>
                        );
                    }) : <tr><td colSpan="5">No new vulnerabilities found in the last scan.</td></tr>}
                </tbody>
            </table>
        </div>
    );
};

const Logs = () => {
    const [logData, setLogData] = useState([]);
    useEffect(() => {
        axios.get(`${API_URL}/logs`)
            .then(res => setLogData(Array.isArray(res.data) ? res.data.reverse() : []))
            .catch(err => { console.error("Error fetching log data:", err); setLogData([]); });
    }, []);
    return (
        <div className="tab-content">
            <h2>Event Logs</h2>
            {logData.length > 0 ? logData.map((logEntry, i) => (
                <div key={i} className="log-entry">
                    <h3>Scan from: {logEntry.timestamp}</h3>
                    <table>
                         <thead><tr><th>Target IP</th><th>Vulnerability</th><th>Severity</th><th>Details / Outcome</th></tr></thead>
                        <tbody>
                            {Array.isArray(logEntry.events) && logEntry.events.filter(filterVulnerabilities).map((event, j) => {
                                const [scanData, actionAttempted, actionOutcome] = event;
                                return (
                                    <tr key={j} className={`severity-${scanData.severity?.toLowerCase()}`}>
                                        <td>{scanData.ip || 'N/A'}</td><td>{scanData.vulnerability}</td>
                                        <td>{scanData.severity || 'N/A'}</td><td>{actionOutcome || scanData.details}</td>
                                    </tr>);
                            })}
                            {(!Array.isArray(logEntry.events) || logEntry.events.filter(filterVulnerabilities).length === 0) &&
                                <tr><td colSpan="4">No vulnerabilities reported in this scan cycle.</td></tr>}
                        </tbody>
                    </table>
                </div>
            )) : <p>No logs available.</p>}
        </div>
    );
};

const NetworkDiagram = () => {
    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);

    const fetchTopology = useCallback(() => {
        axios.get(`${API_URL}/network_topology`)
            .then(res => {
                const topology = res.data; 
                const newNodes = [];
                const newEdges = [];
                
                const yPositions = { controller: 50, switch: 200, host: 350 };
                const xSpacing = 200; 
                let counts = { controller: 0, switch: 0, host: 0 };
                const diagramWidth = 800; // Assumed width for centering

                if (topology.nodes && Array.isArray(topology.nodes)) {
                    // Calculate horizontal positions
                    const controllers = topology.nodes.filter(n => n.type === 'controller');
                    const switches = topology.nodes.filter(n => n.type === 'switch');
                    const hosts = topology.nodes.filter(n => n.type === 'host');

                    controllers.forEach((node, i) => {
                        newNodes.push({
                            id: node.id, type: 'custom',
                            data: { label: node.data.label, raw_label: node.data.raw_label, type: node.type },
                            position: { x: diagramWidth / 2 - 70 , y: yPositions.controller } // Centered
                        });
                    });

                    switches.forEach((node, i) => {
                        const totalSwitches = switches.length;
                        const xPos = (diagramWidth / (totalSwitches + 1)) * (i + 1) - 70; // Spread switches
                        newNodes.push({
                            id: node.id, type: 'custom',
                            data: { label: node.data.label, raw_label: node.data.raw_label, type: node.type },
                            position: { x: xPos, y: yPositions.switch }
                        });
                    });
                    
                    hosts.forEach((node, i) => {
                        const totalHosts = hosts.length;
                        const xPos = (diagramWidth / (totalHosts + 1)) * (i + 1) - 70; // Spread hosts
                        newNodes.push({
                            id: node.id, type: 'custom',
                            data: { label: node.data.label, raw_label: node.data.raw_label, type: node.type },
                            position: { x: xPos, y: yPositions.host }
                        });
                    });
                }

                if (topology.links && Array.isArray(topology.links)) {
                    topology.links.forEach((link) => {
                        newEdges.push({
                            id: link.id || `e-${link.source}-${link.target}-${Math.random()}`,
                            source: link.source,
                            target: link.target,
                            label: link.label || '',
                            type: 'smoothstep', 
                            animated: false, 
                            markerEnd: { type: MarkerType.ArrowClosed, width: 15, height: 15, color: '#555' },
                            style: { stroke: '#555', strokeWidth: 1.5 }
                        });
                    });
                }
                setNodes(newNodes);
                setEdges(newEdges);
            })
            .catch(err => console.error("Error fetching network topology:", err));
    }, [setNodes, setEdges]);

    useEffect(() => {
        fetchTopology();
        const interval = setInterval(fetchTopology, 10000); 
        return () => clearInterval(interval);
    }, [fetchTopology]);

    return (
        <div className="tab-content network-diagram-container">
            <h2>Network Topology View</h2>
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                fitView
                attributionPosition="bottom-right"
                className="react-flow-canvas"
            >
                <MiniMap nodeStrokeWidth={3} zoomable pannable />
                <Controls />
                <Background color="#e0e0e0" gap={20} variant="lines" />
            </ReactFlow>
        </div>
    );
};

const Information = ({activeVulnerabilities}) => {
    const [keywords, setKeywords] = useState('');
    const [cveResults, setCveResults] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    
    const predefinedKeywords = ["IoT", "Open Ports", "Weak Credentials", "SSH", "Telnet", "DDoS", "MQTT", "Firmware"];

    const fetchCVEs = useCallback((searchTerms) => {
        if (!searchTerms) {
            setCveResults([]);
            setError('');
            return;
        }
        setIsLoading(true);
        setError('');
        axios.get(`${API_URL}/cve_info`, { params: { keywords: searchTerms } })
            .then(res => { setCveResults(res.data); setIsLoading(false); })
            .catch(err => {
                setError('Failed to fetch CVE information. ' + (err.response?.data?.error || err.message));
                setIsLoading(false); setCveResults([]);
            });
    }, []);
    
    // Automatically search based on active vulnerabilities when tab becomes active or vulns change
     useEffect(() => {
        if (activeVulnerabilities && activeVulnerabilities.length > 0) {
            const primaryVulnType = activeVulnerabilities[0][0]?.vulnerability || "IoT";
            const searchTerms = primaryVulnType.replace(/_/g, ' ').split(' ')[0]; // Take first word
            setKeywords(searchTerms); // Update input field
            fetchCVEs(searchTerms);
        } else {
            fetchCVEs("IoT security"); // Default search if no active vulns
        }
    }, [activeVulnerabilities, fetchCVEs]);


    const handleKeywordClick = (keyword) => {
        setKeywords(keyword); // Update input field
        fetchCVEs(keyword);
    };
    const handleSearchSubmit = (e) => { 
        e.preventDefault(); 
        fetchCVEs(keywords); 
    };

    return (
        <div className="tab-content">
            <h2>Vulnerability Information Center (NIST CVE)</h2>
            <div className="keyword-search">
                <p>Quick search common terms:</p>
                <div className="predefined-keywords">
                    {predefinedKeywords.map(kw => (
                        <button key={kw} onClick={() => handleKeywordClick(kw)} className="keyword-button">
                            {kw}
                        </button>
                    ))}
                </div>
                <form onSubmit={handleSearchSubmit} style={{ marginTop: '1em', display: 'flex', gap: '0.5rem' }}>
                    <input type="text" value={keywords} onChange={(e) => setKeywords(e.target.value)}
                           placeholder="Enter keywords (e.g., MQTT)" style={{flexGrow: 1}} />
                    <button type="submit" disabled={isLoading} className="search-button">
                        {isLoading ? 'Searching...' : 'Search NIST CVEs'}
                    </button>
                </form>
            </div>
            {error && <p className="error-message">{error}</p>}
            <div className="cve-results">
                {cveResults.length > 0 ? cveResults.map(cve => (
                    <div key={cve.id} className="cve-entry">
                        <h4><a href={cve.link} target="_blank" rel="noopener noreferrer">{cve.id}</a> (Score: {cve.score || 'N/A'})</h4>
                        <p>{cve.description}</p>
                    </div>
                )) : !isLoading && <p>No CVEs found for "{keywords}". Try broader terms or check your spelling.</p>}
            </div>
        </div>
    );
};


function App() {
    const [activeTab, setActiveTab] = useState('dashboard');
    const [message, setMessage] = useState('');
    const [dashboardEvents, setDashboardEvents] = useState([]); // To pass to Information tab

    // Fetch dashboard data once here to pass to Information tab
    useEffect(() => {
        if (activeTab === 'information' || activeTab === 'dashboard') { // Fetch if either tab is active or becomes active
            axios.get(`${API_URL}/dashboard`)
                .then(res => {
                    if (res.data && Array.isArray(res.data.events)) {
                        setDashboardEvents(res.data.events.filter(filterVulnerabilities));
                    }
                })
                .catch(err => console.error("Error fetching dashboard data for App state:", err));
        }
    }, [activeTab]);


    const handleFixClick = useCallback((vulnerability) => {
        setMessage(`Attempting to fix ${vulnerability.vulnerability} on ${vulnerability.ip}...`);
        axios.post(`${API_URL}/fix`, vulnerability)
            .then(res => { setMessage(res.data.message || 'Fix command sent!'); setTimeout(() => setMessage(''), 4000); })
            .catch(err => {
                setMessage('Error sending fix command. ' + (err.response?.data?.error || err.message));
                console.error("Error sending fix command:", err);
            });
    }, []);

    return (
        <div className="App">
            <header className="app-header">
                <h1>IoT Sentinel 🛡️</h1>
                <nav className="tabs">
                    <button onClick={() => setActiveTab('dashboard')} className={activeTab === 'dashboard' ? 'active' : ''}>Dashboard</button>
                    <button onClick={() => setActiveTab('logs')} className={activeTab === 'logs' ? 'active' : ''}>Event Logs</button>
                    <button onClick={() => setActiveTab('network')} className={activeTab === 'network' ? 'active' : ''}>Network View</button>
                    <button onClick={() => setActiveTab('information')} className={activeTab === 'information' ? 'active' : ''}>CVE Info</button>
                </nav>
            </header>
            {message && <div className="message-bar">{message}</div>}
            <main>
                {activeTab === 'dashboard' && <Dashboard handleFixClick={handleFixClick} />}
                {activeTab === 'logs' && <Logs />}
                {activeTab === 'network' && <NetworkDiagram />}
                {activeTab === 'information' && <Information activeVulnerabilities={dashboardEvents} />}
            </main>
            <footer className="app-footer">
                <p>&copy; {new Date().getFullYear()} IoT Sentinel Project</p>
            </footer>
        </div>
    );
}

export default App;
