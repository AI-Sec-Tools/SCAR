#!/usr/bin/env python3
"""
Integration Tests for SCAR
Comprehensive test suite for all SCAR components
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime

# Import SCAR modules
from scar import SCARAnalyzer, Vulnerability, ScanResult
from owasp_patterns import OWASPScanner
from ast_analyzer import UnifiedASTAnalyzer
from flow_analyzer import LogicFlowEngine
from report_generator import ReportManager
from web_dashboard import SCARWebDashboard

class TestSCARIntegration:
    """Integration tests for SCAR components"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            yield Path(tmp_dir)
    
    @pytest.fixture
    def vulnerable_python_code(self):
        """Sample vulnerable Python code for testing"""
        return '''
import os
import subprocess
import pickle
from flask import request, render_template_string

# SQL Injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection vulnerability
def backup_file(filename):
    os.system("cp " + filename + " /backup/")

# Hardcoded credentials
password = "admin123"
secret_key = "hardcoded_secret_2023"

# Insecure deserialization
def load_data(data):
    return pickle.loads(data)

# XSS vulnerability
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return render_template_string('<h1>Hello ' + name + '</h1>')

# Debug mode enabled
app.run(debug=True)
        '''
    
    @pytest.fixture
    def vulnerable_java_code(self):
        """Sample vulnerable Java code for testing"""
        return '''
import java.sql.*;
import java.io.*;

public class VulnerableApp {
    private static final String PASSWORD = "admin123";
    
    // SQL Injection
    public User getUser(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }
    
    // Command Injection
    public void executeCommand(String userInput) {
        Runtime.getRuntime().exec("ping " + userInput);
    }
    
    // Path Traversal
    public String readFile(String filename) {
        File file = new File("/app/files/" + filename);
        // ... read file
    }
    
    // Weak cryptography
    MessageDigest md = MessageDigest.getInstance("MD5");
    
    // Debug information
    public void handleError(Exception e) {
        e.printStackTrace();
        System.out.println("Error: " + e.getMessage());
    }
}
        '''
    
    def test_scar_analyzer_basic_scan(self, temp_dir, vulnerable_python_code):
        """Test basic SCAR analyzer functionality"""
        # Create test file
        test_file = temp_dir / "vulnerable.py"
        test_file.write_text(vulnerable_python_code)
        
        # Initialize analyzer
        analyzer = SCARAnalyzer()
        
        # Scan file
        vulnerabilities = analyzer.scan_file(test_file)
        
        # Assertions
        assert len(vulnerabilities) > 0, "Should find vulnerabilities in sample code"
        
        # Check for specific vulnerability types
        vuln_types = [v.type for v in vulnerabilities]
        assert any('debug' in vtype.lower() for vtype in vuln_types), "Should detect debug configuration"
        
        # Test directory scan
        scan_result = analyzer.scan_directory(temp_dir)
        assert scan_result.total_files >= 1
        assert len(scan_result.vulnerabilities) > 0
    
    def test_owasp_scanner_patterns(self, vulnerable_python_code, vulnerable_java_code):
        """Test OWASP pattern scanner"""
        scanner = OWASPScanner()
        
        # Test Python code
        python_matches = scanner.scan_content(vulnerable_python_code, "test.py")
        assert len(python_matches) > 0, "Should find OWASP vulnerabilities"
        
        # Check for specific OWASP categories
        categories = [match['category'] for match in python_matches]
        assert any('A03_Injection' in cat for cat in categories), "Should detect injection vulnerabilities"
        assert any('A07_Auth_Failures' in cat for cat in categories), "Should detect auth failures"
        
        # Test Java code
        java_matches = scanner.scan_content(vulnerable_java_code, "test.java")
        assert len(java_matches) > 0, "Should find Java vulnerabilities"
        
        # Get statistics
        stats = scanner.get_statistics()
        assert stats['files_scanned'] > 0
        assert stats['vulnerabilities_found'] > 0
    
    def test_ast_analyzer(self, temp_dir, vulnerable_python_code):
        """Test AST analyzer functionality"""
        test_file = temp_dir / "ast_test.py"
        test_file.write_text(vulnerable_python_code)
        
        analyzer = UnifiedASTAnalyzer()
        vulnerabilities = analyzer.analyze_file(test_file)
        
        assert len(vulnerabilities) >= 0, "AST analyzer should complete without errors"
        
        # Test directory analysis
        results = analyzer.analyze_directory(temp_dir)
        assert isinstance(results, dict)
    
    def test_flow_analyzer(self, temp_dir):
        """Test logic flow analyzer"""
        # Create a more specific flow test
        flow_test_code = '''
from flask import request
import subprocess

def vulnerable_endpoint():
    user_input = request.args.get('cmd')
    subprocess.call(user_input, shell=True)

def safe_endpoint():
    user_input = request.args.get('data')
    clean_input = sanitize(user_input)
    process_data(clean_input)
        '''
        
        test_file = temp_dir / "flow_test.py"
        test_file.write_text(flow_test_code)
        
        flow_engine = LogicFlowEngine()
        results = flow_engine.analyze_file(test_file)
        
        assert 'data_flow_vulnerabilities' in results
        assert 'flow_statistics' in results
        assert results['flow_statistics']['total_flow_nodes'] >= 0
    
    def test_report_generation(self, temp_dir, vulnerable_python_code):
        """Test report generation system"""
        # Create test scan results
        test_file = temp_dir / "report_test.py"
        test_file.write_text(vulnerable_python_code)
        
        analyzer = SCARAnalyzer()
        vulnerabilities = analyzer.scan_file(test_file)
        
        scan_results = {
            'scan_id': 'test_scan_001',
            'project_path': str(temp_dir),
            'vulnerabilities': [
                {
                    'type': v.type,
                    'severity': v.severity,
                    'file_path': v.file_path,
                    'line_number': v.line_number,
                    'description': v.description,
                    'owasp_category': v.owasp_category,
                    'recommendation': v.recommendation,
                    'code_snippet': v.code_snippet
                } for v in vulnerabilities
            ],
            'total_files': 1
        }
        
        # Test report generation
        report_manager = ReportManager()
        report_dir = temp_dir / 'reports'
        
        generated_reports = report_manager.create_comprehensive_report(
            scan_results, 
            report_dir, 
            ['json', 'executive']
        )
        
        assert 'json' in generated_reports
        assert 'executive' in generated_reports
        assert generated_reports['json'].exists()
        assert generated_reports['executive'].exists()
        
        # Verify JSON report content
        with open(generated_reports['json'], 'r') as f:
            json_data = json.load(f)
            assert 'vulnerabilities' in json_data
            assert 'summary' in json_data
    
    def test_web_dashboard_initialization(self):
        """Test web dashboard initialization"""
        dashboard = SCARWebDashboard()
        
        # Test app configuration
        assert dashboard.app is not None
        assert dashboard.app.config['MAX_CONTENT_LENGTH'] == 100 * 1024 * 1024
        
        # Test component initialization
        assert dashboard.scar_analyzer is not None
        assert dashboard.owasp_scanner is not None
        assert dashboard.ast_analyzer is not None
        assert dashboard.flow_engine is not None
        assert dashboard.report_manager is not None
        
        # Test allowed file extensions
        assert dashboard._allowed_file('test.py')
        assert dashboard._allowed_file('test.java')
        assert dashboard._allowed_file('test.zip')
        assert not dashboard._allowed_file('test.txt')
    
    def test_comprehensive_scan_workflow(self, temp_dir, vulnerable_python_code):
        """Test complete scan workflow"""
        # Create test files
        test_file1 = temp_dir / "app.py"
        test_file1.write_text(vulnerable_python_code)
        
        test_file2 = temp_dir / "utils.py"
        test_file2.write_text('''
import hashlib

def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def better_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()
        ''')
        
        # Initialize all components
        scar_analyzer = SCARAnalyzer()
        owasp_scanner = OWASPScanner()
        ast_analyzer = UnifiedASTAnalyzer()
        report_manager = ReportManager()
        
        # Perform comprehensive scan
        scan_result = scar_analyzer.scan_directory(temp_dir)
        
        # Verify scan results
        assert scan_result.total_files == 2
        assert len(scan_result.vulnerabilities) > 0
        
        # Test OWASP scanning on all files
        total_owasp_matches = 0
        for file_path in temp_dir.rglob('*.py'):
            with open(file_path, 'r') as f:
                content = f.read()
            matches = owasp_scanner.scan_content(content, str(file_path))
            total_owasp_matches += len(matches)
        
        assert total_owasp_matches > 0, "Should find OWASP vulnerabilities across files"
        
        # Test report generation with combined results
        combined_results = {
            'scan_id': scan_result.scan_id,
            'project_path': str(temp_dir),
            'vulnerabilities': [
                {
                    'type': v.type,
                    'severity': v.severity,
                    'file_path': v.file_path,
                    'line_number': v.line_number,
                    'description': v.description,
                    'owasp_category': v.owasp_category,
                    'recommendation': v.recommendation,
                    'code_snippet': v.code_snippet
                } for v in scan_result.vulnerabilities
            ],
            'total_files': scan_result.total_files
        }
        
        report_dir = temp_dir / 'final_reports'
        reports = report_manager.create_comprehensive_report(
            combined_results,
            report_dir,
            ['html', 'json', 'executive']
        )
        
        # Verify all report formats generated
        assert len(reports) == 3
        for report_path in reports.values():
            assert report_path.exists()
            assert report_path.stat().st_size > 0

class TestSCARPerformance:
    """Performance tests for SCAR"""
    
    def test_large_file_handling(self, temp_dir):
        """Test handling of large files"""
        # Create a large Python file
        large_code = '''
# Large file test
import os
import sys

''' + '\n'.join([f'def function_{i}():\n    return {i}' for i in range(1000)])
        
        large_file = temp_dir / "large_test.py"
        large_file.write_text(large_code)
        
        analyzer = SCARAnalyzer()
        start_time = datetime.now()
        
        vulnerabilities = analyzer.scan_file(large_file)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # Performance assertions
        assert scan_duration < 10.0, f"Large file scan took too long: {scan_duration}s"
        assert isinstance(vulnerabilities, list)
    
    def test_multiple_files_performance(self, temp_dir):
        """Test performance with multiple files"""
        # Create multiple test files
        for i in range(20):
            test_file = temp_dir / f"test_{i}.py"
            test_file.write_text(f'''
import os
# File {i}
password = "test{i}"
os.system("echo test{i}")
            ''')
        
        analyzer = SCARAnalyzer()
        start_time = datetime.now()
        
        scan_result = analyzer.scan_directory(temp_dir)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # Performance assertions
        assert scan_duration < 30.0, f"Multi-file scan took too long: {scan_duration}s"
        assert scan_result.total_files == 20
        assert len(scan_result.vulnerabilities) > 0

class TestSCARErrorHandling:
    """Error handling and edge case tests"""
    
    def test_malformed_python_file(self, temp_dir):
        """Test handling of malformed Python files"""
        malformed_code = '''
import os
def incomplete_function(
    # Missing closing parenthesis and body
if missing_colon
    print("malformed")
        '''
        
        malformed_file = temp_dir / "malformed.py"
        malformed_file.write_text(malformed_code)
        
        analyzer = SCARAnalyzer()
        # Should handle malformed files gracefully
        vulnerabilities = analyzer.scan_file(malformed_file)
        assert isinstance(vulnerabilities, list)
    
    def test_empty_files(self, temp_dir):
        """Test handling of empty files"""
        empty_file = temp_dir / "empty.py"
        empty_file.write_text("")
        
        analyzer = SCARAnalyzer()
        vulnerabilities = analyzer.scan_file(empty_file)
        assert vulnerabilities == []
    
    def test_binary_files(self, temp_dir):
        """Test handling of binary files"""
        binary_file = temp_dir / "binary.py"
        binary_file.write_bytes(b'\xff\xfe\x00\x01\x02\x03')
        
        analyzer = SCARAnalyzer()
        # Should handle binary files gracefully
        vulnerabilities = analyzer.scan_file(binary_file)
        assert isinstance(vulnerabilities, list)
    
    def test_nonexistent_file(self):
        """Test handling of nonexistent files"""
        analyzer = SCARAnalyzer()
        nonexistent_file = Path("/nonexistent/path/file.py")
        
        vulnerabilities = analyzer.scan_file(nonexistent_file)
        assert vulnerabilities == []

@pytest.fixture(scope="session")
def integration_test_setup():
    """Setup for integration tests"""
    print("Setting up SCAR integration tests...")
    yield
    print("Cleaning up SCAR integration tests...")

def test_full_scar_pipeline(integration_test_setup, tmp_path):
    """Test the complete SCAR pipeline end-to-end"""
    # Create a realistic project structure
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    
    # Create main application file
    (project_dir / "app.py").write_text('''
from flask import Flask, request, render_template_string
import os
import sqlite3

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login successful"
    return "Login failed"

@app.route('/exec')
def exec_command():
    cmd = request.args.get('cmd')
    # Command injection vulnerability
    os.system(cmd)
    return "Command executed"

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production
    ''')
    
    # Create utility file
    (project_dir / "utils.py").write_text('''
import hashlib
import pickle

# Weak cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Insecure deserialization
def load_user_data(data):
    return pickle.loads(data)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
    ''')
    
    # Run complete SCAR analysis
    analyzer = SCARAnalyzer()
    owasp_scanner = OWASPScanner()
    report_manager = ReportManager()
    
    # Scan directory
    scan_result = analyzer.scan_directory(project_dir)
    
    # Additional OWASP scanning
    all_vulnerabilities = list(scan_result.vulnerabilities)
    for file_path in project_dir.rglob('*.py'):
        with open(file_path, 'r') as f:
            content = f.read()
        owasp_matches = owasp_scanner.scan_content(content, str(file_path))
        
        # Convert OWASP matches to Vulnerability objects
        for match in owasp_matches:
            vuln = Vulnerability(
                type=match['pattern'],
                severity=match['severity'],
                file_path=match['filename'],
                line_number=match.get('line_start', 1),
                description=match['description'],
                owasp_category=match['category'],
                recommendation=match['remediation'],
                code_snippet=match['pattern']
            )
            all_vulnerabilities.append(vuln)
    
    # Generate comprehensive report
    final_results = {
        'scan_id': scan_result.scan_id,
        'project_path': str(project_dir),
        'vulnerabilities': [
            {
                'type': v.type,
                'severity': v.severity,
                'file_path': v.file_path,
                'line_number': v.line_number,
                'description': v.description,
                'owasp_category': v.owasp_category,
                'recommendation': v.recommendation,
                'code_snippet': v.code_snippet
            } for v in all_vulnerabilities
        ],
        'total_files': scan_result.total_files
    }
    
    report_dir = tmp_path / 'pipeline_reports'
    reports = report_manager.create_comprehensive_report(
        final_results,
        report_dir,
        ['html', 'json', 'executive']
    )
    
    # Comprehensive assertions
    assert scan_result.total_files == 2, f"Expected 2 files, got {scan_result.total_files}"
    assert len(all_vulnerabilities) > 5, f"Expected multiple vulnerabilities, got {len(all_vulnerabilities)}"
    
    # Verify specific vulnerability types were found
    vuln_categories = [v.owasp_category for v in all_vulnerabilities if hasattr(v, 'owasp_category')]
    assert any('A03_Injection' in cat for cat in vuln_categories), "Should detect injection vulnerabilities"
    assert any('A02_Cryptographic' in cat for cat in vuln_categories), "Should detect crypto failures"
    assert any('A07_Auth' in cat for cat in vuln_categories), "Should detect auth failures"
    
    # Verify reports were generated
    assert len(reports) == 3, f"Expected 3 reports, got {len(reports)}"
    for report_type, report_path in reports.items():
        assert report_path.exists(), f"{report_type} report was not generated"
        assert report_path.stat().st_size > 100, f"{report_type} report is too small"
    
    print(f"✅ Full pipeline test completed successfully!")
    print(f"   Files scanned: {scan_result.total_files}")
    print(f"   Vulnerabilities found: {len(all_vulnerabilities)}")
    print(f"   Reports generated: {len(reports)}")

if __name__ == '__main__':
    pytest.main([__file__, '-v']) 