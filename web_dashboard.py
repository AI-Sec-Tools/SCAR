#!/usr/bin/env python3
"""
Web Dashboard for SCAR
Interactive web interface for security code analysis with file upload and real-time scanning
"""

import os
import json
import logging
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from flask import Flask, render_template_string, request, jsonify, send_file, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# Import SCAR modules
from scar import SCARAnalyzer
from owasp_patterns import OWASPScanner
from ast_analyzer import UnifiedASTAnalyzer
from flow_analyzer import LogicFlowEngine
from report_generator import ReportManager

logger = logging.getLogger('SCAR.WebDashboard')

class SCARWebDashboard:
    """Main web dashboard application"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'scar_security_dashboard_2023'
        self.app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
        
        # Enable CORS for API endpoints
        CORS(self.app, origins=['*'])
        
        # Initialize SCAR components
        self.scar_analyzer = SCARAnalyzer()
        self.owasp_scanner = OWASPScanner()
        self.ast_analyzer = UnifiedASTAnalyzer()
        self.flow_engine = LogicFlowEngine()
        self.report_manager = ReportManager()
        
        # Configure upload settings
        self.upload_folder = Path(tempfile.gettempdir()) / 'scar_uploads'
        self.upload_folder.mkdir(exist_ok=True)
        self.allowed_extensions = {'.py', '.java', '.zip'}
        
        # Scan history storage
        self.scan_history = []
        
        self._setup_routes()
        self._create_templates()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return render_template_string(self.dashboard_template)
        
        @self.app.route('/api/upload', methods=['POST'])
        def upload_file():
            """Handle file upload"""
            try:
                if 'file' not in request.files:
                    return jsonify({'error': 'No file provided'}), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                if not self._allowed_file(file.filename):
                    return jsonify({'error': 'File type not supported'}), 400
                
                # Save uploaded file
                filename = secure_filename(file.filename)
                scan_id = str(uuid.uuid4())
                scan_dir = self.upload_folder / scan_id
                scan_dir.mkdir(exist_ok=True)
                
                file_path = scan_dir / filename
                file.save(str(file_path))
                
                # Extract if ZIP file
                if filename.endswith('.zip'):
                    extract_dir = scan_dir / 'extracted'
                    extract_dir.mkdir(exist_ok=True)
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    scan_path = extract_dir
                else:
                    scan_path = file_path
                
                session['current_scan_id'] = scan_id
                session['scan_path'] = str(scan_path)
                
                return jsonify({
                    'success': True,
                    'scan_id': scan_id,
                    'filename': filename,
                    'message': 'File uploaded successfully'
                })
                
            except RequestEntityTooLarge:
                return jsonify({'error': 'File too large. Maximum size is 100MB'}), 413
            except Exception as e:
                logger.error(f"Upload error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            """Start security scan"""
            try:
                scan_id = session.get('current_scan_id')
                scan_path = session.get('scan_path')
                
                if not scan_id or not scan_path:
                    return jsonify({'error': 'No file uploaded for scanning'}), 400
                
                scan_options = request.json or {}
                
                # Perform comprehensive scan
                results = self._perform_comprehensive_scan(
                    Path(scan_path), 
                    scan_id, 
                    scan_options
                )
                
                # Store in history
                self.scan_history.append(results)
                
                return jsonify({
                    'success': True,
                    'scan_id': scan_id,
                    'results': results
                })
                
            except Exception as e:
                logger.error(f"Scan error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/<scan_id>')
        def get_scan_results(scan_id):
            """Get scan results by ID"""
            try:
                for scan in self.scan_history:
                    if scan['scan_id'] == scan_id:
                        return jsonify(scan)
                
                return jsonify({'error': 'Scan not found'}), 404
                
            except Exception as e:
                logger.error(f"Get results error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/history')
        def get_scan_history():
            """Get scan history"""
            try:
                # Return summary of all scans
                history_summary = []
                for scan in self.scan_history:
                    summary = {
                        'scan_id': scan['scan_id'],
                        'timestamp': scan['timestamp'],
                        'project_name': scan['project_name'],
                        'total_vulnerabilities': len(scan['vulnerabilities']),
                        'critical_count': len([v for v in scan['vulnerabilities'] if v.get('severity') == 'Critical']),
                        'high_count': len([v for v in scan['vulnerabilities'] if v.get('severity') == 'High']),
                        'files_scanned': scan['total_files']
                    }
                    history_summary.append(summary)
                
                return jsonify(history_summary)
                
            except Exception as e:
                logger.error(f"History error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/report/<scan_id>/<format>')
        def download_report(scan_id, format):
            """Download report in specified format"""
            try:
                # Find scan results
                scan_results = None
                for scan in self.scan_history:
                    if scan['scan_id'] == scan_id:
                        scan_results = scan
                        break
                
                if not scan_results:
                    return jsonify({'error': 'Scan not found'}), 404
                
                # Generate report
                report_dir = self.upload_folder / scan_id / 'reports'
                reports = self.report_manager.create_comprehensive_report(
                    scan_results, 
                    report_dir, 
                    [format]
                )
                
                if format in reports:
                    return send_file(
                        str(reports[format]), 
                        as_attachment=True,
                        download_name=f"scar_report_{scan_id}.{format}"
                    )
                else:
                    return jsonify({'error': 'Report format not available'}), 404
                    
            except Exception as e:
                logger.error(f"Report download error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/statistics')
        def get_statistics():
            """Get overall statistics"""
            try:
                if not self.scan_history:
                    return jsonify({
                        'total_scans': 0,
                        'total_vulnerabilities': 0,
                        'avg_vulnerabilities_per_scan': 0,
                        'most_common_vulnerability': 'None'
                    })
                
                total_scans = len(self.scan_history)
                all_vulnerabilities = []
                for scan in self.scan_history:
                    all_vulnerabilities.extend(scan['vulnerabilities'])
                
                total_vulnerabilities = len(all_vulnerabilities)
                avg_vulnerabilities = total_vulnerabilities / total_scans if total_scans > 0 else 0
                
                # Find most common vulnerability type
                vuln_types = {}
                for vuln in all_vulnerabilities:
                    vuln_type = vuln.get('owasp_category', vuln.get('type', 'Unknown'))
                    vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                most_common = max(vuln_types.items(), key=lambda x: x[1], default=('None', 0))
                
                return jsonify({
                    'total_scans': total_scans,
                    'total_vulnerabilities': total_vulnerabilities,
                    'avg_vulnerabilities_per_scan': round(avg_vulnerabilities, 2),
                    'most_common_vulnerability': most_common[0],
                    'vulnerability_distribution': vuln_types
                })
                
            except Exception as e:
                logger.error(f"Statistics error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.errorhandler(413)
        def too_large(e):
            return jsonify({'error': 'File too large. Maximum size is 100MB'}), 413
        
        @self.app.errorhandler(404)
        def not_found(e):
            return jsonify({'error': 'Endpoint not found'}), 404
        
        @self.app.errorhandler(500)
        def server_error(e):
            return jsonify({'error': 'Internal server error'}), 500
    
    def _allowed_file(self, filename):
        """Check if file extension is allowed"""
        return Path(filename).suffix.lower() in self.allowed_extensions
    
    def _perform_comprehensive_scan(self, scan_path: Path, scan_id: str, options: Dict) -> Dict[str, Any]:
        """Perform comprehensive security scan"""
        start_time = datetime.now()
        
        results = {
            'scan_id': scan_id,
            'timestamp': start_time.isoformat(),
            'project_name': scan_path.name,
            'project_path': str(scan_path),
            'vulnerabilities': [],
            'total_files': 0,
            'scan_duration': 0.0,
            'confidence_score': 0.85,
            'coverage_percentage': 85.0
        }
        
        try:
            if scan_path.is_file():
                # Single file scan
                results['total_files'] = 1
                vulnerabilities = self._scan_single_file(scan_path)
                results['vulnerabilities'].extend(vulnerabilities)
            else:
                # Directory scan
                file_count = 0
                for file_path in scan_path.rglob('*'):
                    if (file_path.is_file() and 
                        file_path.suffix in self.scar_analyzer.supported_extensions):
                        file_count += 1
                        vulnerabilities = self._scan_single_file(file_path)
                        results['vulnerabilities'].extend(vulnerabilities)
                
                results['total_files'] = file_count
            
            # Calculate scan duration
            end_time = datetime.now()
            results['scan_duration'] = (end_time - start_time).total_seconds()
            
            # Add flow analysis if enabled
            if options.get('enable_flow_analysis', True) and scan_path.suffix == '.py':
                flow_results = self.flow_engine.analyze_file(scan_path)
                if flow_results['data_flow_vulnerabilities']:
                    for flow_vuln in flow_results['data_flow_vulnerabilities']:
                        vuln_dict = {
                            'type': flow_vuln.vuln_type,
                            'severity': flow_vuln.risk_level.value,
                            'file_path': str(scan_path),
                            'line_number': flow_vuln.source_node.line_number,
                            'description': flow_vuln.description,
                            'owasp_category': 'A03_Injection',  # Most flow vulns are injection
                            'recommendation': flow_vuln.remediation,
                            'code_snippet': flow_vuln.source_node.context,
                            'confidence': flow_vuln.confidence
                        }
                        results['vulnerabilities'].append(vuln_dict)
            
            logger.info(f"Scan completed: {scan_id}, found {len(results['vulnerabilities'])} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan error for {scan_id}: {e}")
            results['error'] = str(e)
        
        return results
    
    def _scan_single_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file with all analyzers"""
        vulnerabilities = []
        
        try:
            # SCAR basic scan
            basic_vulns = self.scar_analyzer.scan_file(file_path)
            for vuln in basic_vulns:
                vuln_dict = {
                    'type': vuln.type,
                    'severity': vuln.severity,
                    'file_path': vuln.file_path,
                    'line_number': vuln.line_number,
                    'description': vuln.description,
                    'owasp_category': vuln.owasp_category,
                    'recommendation': vuln.recommendation,
                    'code_snippet': vuln.code_snippet
                }
                vulnerabilities.append(vuln_dict)
            
            # OWASP pattern scan
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            owasp_matches = self.owasp_scanner.scan_content(content, str(file_path))
            for match in owasp_matches:
                vuln_dict = {
                    'type': match['pattern'],
                    'severity': match['severity'],
                    'file_path': match['filename'],
                    'line_number': match.get('line_start', 1),
                    'description': match['description'],
                    'owasp_category': match['category'],
                    'recommendation': match['remediation'],
                    'code_snippet': match['pattern']
                }
                vulnerabilities.append(vuln_dict)
            
            # AST analysis
            ast_vulns = self.ast_analyzer.analyze_file(file_path)
            for ast_vuln in ast_vulns:
                vuln_dict = {
                    'type': ast_vuln.node_type,
                    'severity': 'High' if ast_vuln.complexity_score > 7 else 'Medium',
                    'file_path': str(file_path),
                    'line_number': getattr(ast_vuln, 'line_number', 1),
                    'description': f"AST analysis detected {ast_vuln.node_type}",
                    'owasp_category': self._map_ast_to_owasp(ast_vuln.node_type),
                    'recommendation': f"Review {ast_vuln.node_type} usage",
                    'code_snippet': ' '.join(ast_vuln.context_lines[:2]) if ast_vuln.context_lines else ''
                }
                vulnerabilities.append(vuln_dict)
                
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    def _map_ast_to_owasp(self, node_type: str) -> str:
        """Map AST vulnerability type to OWASP category"""
        mapping = {
            'SQLInjection': 'A03_Injection',
            'CommandInjection': 'A03_Injection',
            'CodeInjection': 'A03_Injection',
            'XSS': 'A03_Injection',
            'HardcodedCredentials': 'A07_Auth_Failures',
            'InsecureDeserialization': 'A08_Integrity_Failures',
            'PathTraversal': 'A01_Broken_Access_Control'
        }
        return mapping.get(node_type, 'A04_Insecure_Design')
    
    def _create_templates(self):
        """Create HTML templates"""
        self.dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCAR - Security Code Analysis Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
        .header h1 { display: flex; align-items: center; gap: 10px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: white; border-radius: 10px; padding: 20px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .upload-area { border: 2px dashed #667eea; border-radius: 10px; padding: 40px; text-align: center; transition: all 0.3s; }
        .upload-area:hover { border-color: #764ba2; background: #f8f9ff; }
        .upload-area.dragover { border-color: #28a745; background: #f0fff4; }
        .btn { padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5a6fd8; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s; }
        .vulnerability-item { border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; background: #fff5f5; border-radius: 5px; }
        .vulnerability-item.high { border-color: #fd7e14; background: #fff8f0; }
        .vulnerability-item.medium { border-color: #ffc107; background: #fffbf0; }
        .vulnerability-item.low { border-color: #28a745; background: #f0fff4; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-card { text-align: center; padding: 20px; }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        .scan-history { max-height: 400px; overflow-y: auto; }
        .history-item { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .history-item:last-child { border-bottom: none; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 12px 24px; background: #f8f9fa; border: 1px solid #ddd; cursor: pointer; border-bottom: none; }
        .tab.active { background: #667eea; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .hidden { display: none; }
        .loading { text-align: center; padding: 40px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .alert-error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .file-input { display: none; }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🛡️ SCAR Security Dashboard</h1>
            <p>Comprehensive Security Code Analysis & Review</p>
        </div>
    </div>
    
    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="showTab('upload')">Upload & Scan</div>
            <div class="tab" onclick="showTab('results')">Results</div>
            <div class="tab" onclick="showTab('history')">History</div>
            <div class="tab" onclick="showTab('statistics')">Statistics</div>
        </div>
        
        <!-- Upload Tab -->
        <div id="upload" class="tab-content active">
            <div class="card">
                <h2>Upload Code for Analysis</h2>
                <div class="upload-area" id="uploadArea">
                    <div>
                        <h3>📁 Drop files here or click to browse</h3>
                        <p>Supported formats: .py, .java, .zip (up to 100MB)</p>
                        <input type="file" id="fileInput" class="file-input" accept=".py,.java,.zip">
                        <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                            Choose Files
                        </button>
                    </div>
                </div>
                
                <div id="uploadProgress" class="hidden">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <p id="uploadStatus">Uploading...</p>
                </div>
                
                <div id="scanOptions" class="hidden">
                    <h3>Scan Options</h3>
                    <label>
                        <input type="checkbox" id="enableFlowAnalysis" checked> Enable Flow Analysis
                    </label><br>
                    <label>
                        <input type="checkbox" id="enableASTAnalysis" checked> Enable AST Analysis
                    </label><br>
                    <button class="btn btn-success" onclick="startScan()" id="scanButton">
                        🔍 Start Security Scan
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Results Tab -->
        <div id="results" class="tab-content">
            <div class="card">
                <h2>Scan Results</h2>
                <div id="scanResults">
                    <p>No scan results available. Please upload and scan code first.</p>
                </div>
            </div>
        </div>
        
        <!-- History Tab -->
        <div id="history" class="tab-content">
            <div class="card">
                <h2>Scan History</h2>
                <div class="scan-history" id="scanHistory">
                    <p>No scan history available.</p>
                </div>
            </div>
        </div>
        
        <!-- Statistics Tab -->
        <div id="statistics" class="tab-content">
            <div class="card">
                <h2>Overall Statistics</h2>
                <div class="stats-grid" id="statsGrid">
                    <div class="stat-card">
                        <div class="stat-number" id="totalScans">0</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="totalVulns">0</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="avgVulns">0</div>
                        <div class="stat-label">Avg per Scan</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="commonVuln">-</div>
                        <div class="stat-label">Most Common</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
            
            if (tabName === 'history') loadScanHistory();
            if (tabName === 'statistics') loadStatistics();
        }
        
        // File upload handling
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                uploadFile(files[0]);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                uploadFile(e.target.files[0]);
            }
        });
        
        function uploadFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            
            document.getElementById('uploadProgress').classList.remove('hidden');
            document.getElementById('uploadStatus').textContent = 'Uploading...';
            
            fetch('/api/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentScanId = data.scan_id;
                    document.getElementById('uploadStatus').textContent = 'Upload successful!';
                    document.getElementById('scanOptions').classList.remove('hidden');
                    showAlert('File uploaded successfully! You can now start the scan.', 'success');
                } else {
                    showAlert('Upload failed: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('Upload error: ' + error.message, 'error');
            });
        }
        
        function startScan() {
            if (!currentScanId) {
                showAlert('Please upload a file first', 'error');
                return;
            }
            
            const options = {
                enable_flow_analysis: document.getElementById('enableFlowAnalysis').checked,
                enable_ast_analysis: document.getElementById('enableASTAnalysis').checked
            };
            
            document.getElementById('scanButton').disabled = true;
            document.getElementById('scanButton').innerHTML = '<div class="spinner"></div> Scanning...';
            
            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(options)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayScanResults(data.results);
                    showTab('results');
                    showAlert('Scan completed successfully!', 'success');
                } else {
                    showAlert('Scan failed: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showAlert('Scan error: ' + error.message, 'error');
            })
            .finally(() => {
                document.getElementById('scanButton').disabled = false;
                document.getElementById('scanButton').innerHTML = '🔍 Start Security Scan';
            });
        }
        
        function displayScanResults(results) {
            const resultsDiv = document.getElementById('scanResults');
            const vulns = results.vulnerabilities || [];
            
            let html = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${vulns.length}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${vulns.filter(v => v.severity === 'Critical').length}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${vulns.filter(v => v.severity === 'High').length}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${results.total_files}</div>
                        <div class="stat-label">Files Scanned</div>
                    </div>
                </div>
                
                <div style="margin: 20px 0;">
                    <button class="btn btn-primary" onclick="downloadReport('${results.scan_id}', 'html')">📄 Download HTML Report</button>
                    <button class="btn btn-primary" onclick="downloadReport('${results.scan_id}', 'json')">📋 Download JSON Report</button>
                    <button class="btn btn-primary" onclick="downloadReport('${results.scan_id}', 'executive')">📋 Executive Summary</button>
                </div>
                
                <h3>Vulnerabilities Found:</h3>
            `;
            
            if (vulns.length === 0) {
                html += '<p>No vulnerabilities found! 🎉</p>';
            } else {
                vulns.forEach(vuln => {
                    const severityClass = vuln.severity.toLowerCase();
                    html += `
                        <div class="vulnerability-item ${severityClass}">
                            <h4>${vuln.owasp_category || vuln.type}</h4>
                            <p><strong>Severity:</strong> ${vuln.severity}</p>
                            <p><strong>File:</strong> ${vuln.file_path}:${vuln.line_number}</p>
                            <p><strong>Description:</strong> ${vuln.description}</p>
                            <p><strong>Code:</strong> <code>${vuln.code_snippet}</code></p>
                            <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                        </div>
                    `;
                });
            }
            
            resultsDiv.innerHTML = html;
        }
        
        function downloadReport(scanId, format) {
            window.open(`/api/report/${scanId}/${format}`, '_blank');
        }
        
        function loadScanHistory() {
            fetch('/api/history')
            .then(response => response.json())
            .then(data => {
                const historyDiv = document.getElementById('scanHistory');
                if (data.length === 0) {
                    historyDiv.innerHTML = '<p>No scan history available.</p>';
                    return;
                }
                
                let html = '';
                data.forEach(scan => {
                    html += `
                        <div class="history-item">
                            <div>
                                <strong>${scan.project_name}</strong><br>
                                <small>${new Date(scan.timestamp).toLocaleString()}</small><br>
                                <span>${scan.total_vulnerabilities} vulnerabilities (${scan.critical_count} critical, ${scan.high_count} high)</span>
                            </div>
                            <div>
                                <button class="btn btn-primary" onclick="loadScanResults('${scan.scan_id}')">View Results</button>
                            </div>
                        </div>
                    `;
                });
                
                historyDiv.innerHTML = html;
            })
            .catch(error => {
                console.error('Error loading history:', error);
            });
        }
        
        function loadScanResults(scanId) {
            fetch(`/api/scan/${scanId}`)
            .then(response => response.json())
            .then(data => {
                displayScanResults(data);
                showTab('results');
            })
            .catch(error => {
                showAlert('Error loading scan results: ' + error.message, 'error');
            });
        }
        
        function loadStatistics() {
            fetch('/api/statistics')
            .then(response => response.json())
            .then(data => {
                document.getElementById('totalScans').textContent = data.total_scans;
                document.getElementById('totalVulns').textContent = data.total_vulnerabilities;
                document.getElementById('avgVulns').textContent = data.avg_vulnerabilities_per_scan;
                document.getElementById('commonVuln').textContent = data.most_common_vulnerability;
            })
            .catch(error => {
                console.error('Error loading statistics:', error);
            });
        }
        
        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            
            document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.tabs'));
            
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }
        
        // Load initial data
        loadStatistics();
    </script>
</body>
</html>
        """
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Run the web dashboard"""
        logger.info(f"Starting SCAR Web Dashboard on http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main entry point for web dashboard"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SCAR Web Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    dashboard = SCARWebDashboard()
    dashboard.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main() 