#!/usr/bin/env python3
"""
Report Generation System for SCAR
Comprehensive security analysis reporting with multiple output formats
"""

import json
import logging
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader
import pandas as pd

logger = logging.getLogger('SCAR.Reports')

@dataclass
class VulnerabilitySummary:
    """Summary statistics for vulnerabilities"""
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    by_category: Dict[str, int]
    by_file: Dict[str, int]
    trend_data: List[Dict[str, Any]]

@dataclass
class ScanMetrics:
    """Metrics from the security scan"""
    files_scanned: int
    lines_analyzed: int
    scan_duration: float
    coverage_percentage: float
    false_positive_rate: float
    confidence_score: float

@dataclass
class ReportData:
    """Complete report data structure"""
    scan_id: str
    timestamp: datetime
    project_name: str
    project_path: str
    summary: VulnerabilitySummary
    metrics: ScanMetrics
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]
    compliance_status: Dict[str, Any]

class HTMLReportGenerator:
    """Generates HTML reports with interactive elements"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        self._create_templates()
        
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
    
    def _create_templates(self):
        """Create HTML report templates"""
        
        # Main report template
        main_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCAR Security Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border-left: 4px solid #667eea; }
        .summary-card h3 { color: #667eea; margin-bottom: 10px; }
        .summary-card .number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .vulnerability-list { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .vulnerability-item { border-bottom: 1px solid #eee; padding: 15px 0; }
        .vulnerability-item:last-child { border-bottom: none; }
        .vuln-header { display: flex; justify-content: between; align-items: center; margin-bottom: 10px; }
        .vuln-title { font-weight: bold; font-size: 1.1em; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; color: white; font-size: 0.8em; font-weight: bold; }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #333; }
        .severity-low { background-color: #28a745; }
        .vuln-details { margin: 10px 0; color: #666; }
        .vuln-location { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; font-family: monospace; }
        .recommendations { background: #e7f3ff; border-left: 4px solid #007bff; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .chart-container { margin: 20px 0; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 0.9em; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #f8f9fa; border: 1px solid #ddd; cursor: pointer; }
        .tab.active { background: #667eea; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SCAR Security Analysis Report</h1>
            <div class="subtitle">
                Project: {{ report.project_name }} | Scan ID: {{ report.scan_id }} | 
                Generated: {{ report.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('overview')">Overview</div>
            <div class="tab" onclick="showTab('vulnerabilities')">Vulnerabilities</div>
            <div class="tab" onclick="showTab('metrics')">Metrics</div>
            <div class="tab" onclick="showTab('compliance')">Compliance</div>
        </div>

        <div id="overview" class="tab-content active">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="number">{{ report.summary.total_vulnerabilities }}</div>
                    <div>Across {{ report.metrics.files_scanned }} files</div>
                </div>
                <div class="summary-card">
                    <h3>Critical Issues</h3>
                    <div class="number critical">{{ report.summary.critical_count }}</div>
                    <div>Require immediate attention</div>
                </div>
                <div class="summary-card">
                    <h3>High Risk</h3>
                    <div class="number high">{{ report.summary.high_count }}</div>
                    <div>Security vulnerabilities</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Quality</h3>
                    <div class="number">{{ "%.1f"|format(report.metrics.confidence_score * 100) }}%</div>
                    <div>Confidence score</div>
                </div>
            </div>

            <div class="chart-container">
                <h3>Vulnerability Distribution by Severity</h3>
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>

            <div class="chart-container">
                <h3>Vulnerabilities by OWASP Category</h3>
                <canvas id="categoryChart" width="400" height="200"></canvas>
            </div>
        </div>

        <div id="vulnerabilities" class="tab-content">
            <div class="vulnerability-list">
                <h2>Detailed Vulnerability Analysis</h2>
                {% for vuln in report.vulnerabilities[:20] %}
                <div class="vulnerability-item">
                    <div class="vuln-header">
                        <div class="vuln-title">{{ vuln.owasp_category or vuln.type }}</div>
                        <span class="severity-badge severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span>
                    </div>
                    <div class="vuln-details">{{ vuln.description }}</div>
                    <div class="vuln-location">
                        📁 {{ vuln.file_path }}:{{ vuln.line_number }}<br>
                        💻 <code>{{ vuln.code_snippet }}</code>
                    </div>
                    <div class="recommendations">
                        <strong>Remediation:</strong> {{ vuln.recommendation }}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <div id="metrics" class="tab-content">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Files Analyzed</h3>
                    <div class="number">{{ report.metrics.files_scanned }}</div>
                </div>
                <div class="summary-card">
                    <h3>Lines of Code</h3>
                    <div class="number">{{ "{:,}"|format(report.metrics.lines_analyzed) }}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="number">{{ "%.2f"|format(report.metrics.scan_duration) }}s</div>
                </div>
                <div class="summary-card">
                    <h3>Coverage</h3>
                    <div class="number">{{ "%.1f"|format(report.metrics.coverage_percentage) }}%</div>
                </div>
            </div>
        </div>

        <div id="compliance" class="tab-content">
            <div class="summary-card">
                <h3>OWASP Top 10 Compliance Status</h3>
                {% for category, status in report.compliance_status.items() %}
                <div style="margin: 10px 0;">
                    <strong>{{ category }}:</strong> 
                    <span class="{{ 'high' if not status.compliant else 'low' }}">
                        {{ 'Non-Compliant' if not status.compliant else 'Compliant' }}
                    </span>
                    ({{ status.issues_found }} issues)
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="footer">
            <p>Generated by SCAR v1.0.0 | Security Code Analysis & Review Tool</p>
            <p>For more information, visit: <a href="https://github.com/AI-Sec-Tools/SCAR">https://github.com/AI-Sec-Tools/SCAR</a></p>
        </div>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }

        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        {{ report.summary.critical_count }},
                        {{ report.summary.high_count }},
                        {{ report.summary.medium_count }},
                        {{ report.summary.low_count }}
                    ],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });

        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {
            type: 'bar',
            data: {
                labels: {{ report.summary.by_category.keys() | list | tojson }},
                datasets: [{
                    label: 'Vulnerabilities',
                    data: {{ report.summary.by_category.values() | list | tojson }},
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
        """
        
        with open(self.template_dir / "main_report.html", "w") as f:
            f.write(main_template)
    
    def generate_report(self, report_data: ReportData, output_path: Path) -> None:
        """Generate HTML report"""
        try:
            template = self.env.get_template("main_report.html")
            html_content = template.render(report=report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            logger.info(f"HTML report generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")

class JSONReportGenerator:
    """Generates detailed JSON reports"""
    
    def generate_report(self, report_data: ReportData, output_path: Path) -> None:
        """Generate JSON report"""
        try:
            # Convert dataclass to dict with proper serialization
            report_dict = asdict(report_data)
            report_dict['timestamp'] = report_data.timestamp.isoformat()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
                
            logger.info(f"JSON report generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")

class ExecutiveSummaryGenerator:
    """Generates executive summary reports"""
    
    def generate_summary(self, report_data: ReportData) -> str:
        """Generate executive summary text"""
        summary = f"""
SCAR SECURITY ANALYSIS - EXECUTIVE SUMMARY
==========================================

Project: {report_data.project_name}
Scan Date: {report_data.timestamp.strftime('%Y-%m-%d')}
Scan ID: {report_data.scan_id}

RISK ASSESSMENT
---------------
Overall Security Risk: {self._calculate_risk_level(report_data)}
Files Analyzed: {report_data.metrics.files_scanned}
Total Vulnerabilities: {report_data.summary.total_vulnerabilities}

CRITICAL FINDINGS
-----------------
Critical Issues: {report_data.summary.critical_count}
High Risk Issues: {report_data.summary.high_count}

{self._get_top_vulnerabilities(report_data)}

RECOMMENDATIONS
---------------
{self._format_recommendations(report_data.recommendations)}

COMPLIANCE STATUS
-----------------
{self._format_compliance_status(report_data.compliance_status)}

Next Steps:
1. Address all Critical and High severity vulnerabilities immediately
2. Implement security code review process
3. Set up automated security scanning in CI/CD pipeline
4. Provide security training for development team

Generated by SCAR v1.0.0
        """
        return summary.strip()
    
    def _calculate_risk_level(self, report_data: ReportData) -> str:
        """Calculate overall risk level"""
        if report_data.summary.critical_count > 0:
            return "CRITICAL"
        elif report_data.summary.high_count > 5:
            return "HIGH"
        elif report_data.summary.high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_top_vulnerabilities(self, report_data: ReportData) -> str:
        """Get top vulnerability types"""
        top_categories = sorted(
            report_data.summary.by_category.items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]
        
        result = "Top Vulnerability Categories:\n"
        for category, count in top_categories:
            result += f"- {category}: {count} issues\n"
        
        return result
    
    def _format_recommendations(self, recommendations: List[str]) -> str:
        """Format recommendations list"""
        if not recommendations:
            return "No specific recommendations generated."
        
        return "\n".join(f"• {rec}" for rec in recommendations[:5])
    
    def _format_compliance_status(self, compliance_status: Dict[str, Any]) -> str:
        """Format compliance status"""
        result = ""
        for category, status in compliance_status.items():
            compliance_text = "✓ Compliant" if status.get('compliant', False) else "✗ Non-Compliant"
            result += f"{category}: {compliance_text}\n"
        
        return result

class TrendAnalyzer:
    """Analyzes trends across multiple scans"""
    
    def __init__(self):
        self.historical_data = []
    
    def add_scan_data(self, report_data: ReportData):
        """Add scan data for trend analysis"""
        self.historical_data.append({
            'timestamp': report_data.timestamp,
            'total_vulnerabilities': report_data.summary.total_vulnerabilities,
            'critical_count': report_data.summary.critical_count,
            'high_count': report_data.summary.high_count,
            'medium_count': report_data.summary.medium_count,
            'low_count': report_data.summary.low_count,
            'files_scanned': report_data.metrics.files_scanned
        })
    
    def generate_trend_data(self) -> List[Dict[str, Any]]:
        """Generate trend analysis data"""
        if len(self.historical_data) < 2:
            return []
        
        trends = []
        for i in range(1, len(self.historical_data)):
            current = self.historical_data[i]
            previous = self.historical_data[i-1]
            
            trend = {
                'timestamp': current['timestamp'],
                'vulnerability_change': current['total_vulnerabilities'] - previous['total_vulnerabilities'],
                'critical_change': current['critical_count'] - previous['critical_count'],
                'improvement_rate': self._calculate_improvement_rate(current, previous)
            }
            trends.append(trend)
        
        return trends
    
    def _calculate_improvement_rate(self, current: Dict, previous: Dict) -> float:
        """Calculate improvement rate between scans"""
        if previous['total_vulnerabilities'] == 0:
            return 0.0
        
        return ((previous['total_vulnerabilities'] - current['total_vulnerabilities']) / 
                previous['total_vulnerabilities']) * 100

class ReportManager:
    """Main report management system"""
    
    def __init__(self):
        self.html_generator = HTMLReportGenerator()
        self.json_generator = JSONReportGenerator()
        self.executive_generator = ExecutiveSummaryGenerator()
        self.trend_analyzer = TrendAnalyzer()
    
    def create_comprehensive_report(self, scan_results: Dict[str, Any], 
                                  output_dir: Path, formats: List[str] = None) -> Dict[str, Path]:
        """Create comprehensive reports in multiple formats"""
        
        if formats is None:
            formats = ['html', 'json', 'executive']
        
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_files = {}
        
        # Prepare report data
        report_data = self._prepare_report_data(scan_results)
        
        # Generate reports in requested formats
        if 'html' in formats:
            html_path = output_dir / f"scar_report_{report_data.scan_id}.html"
            self.html_generator.generate_report(report_data, html_path)
            generated_files['html'] = html_path
        
        if 'json' in formats:
            json_path = output_dir / f"scar_report_{report_data.scan_id}.json"
            self.json_generator.generate_report(report_data, json_path)
            generated_files['json'] = json_path
        
        if 'executive' in formats:
            exec_path = output_dir / f"executive_summary_{report_data.scan_id}.txt"
            summary = self.executive_generator.generate_summary(report_data)
            with open(exec_path, 'w', encoding='utf-8') as f:
                f.write(summary)
            generated_files['executive'] = exec_path
        
        # Add to trend analysis
        self.trend_analyzer.add_scan_data(report_data)
        
        logger.info(f"Generated {len(generated_files)} report files in {output_dir}")
        return generated_files
    
    def _prepare_report_data(self, scan_results: Dict[str, Any]) -> ReportData:
        """Prepare structured report data from scan results"""
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Calculate summary statistics
        summary = VulnerabilitySummary(
            total_vulnerabilities=len(vulnerabilities),
            critical_count=len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            high_count=len([v for v in vulnerabilities if v.get('severity') == 'High']),
            medium_count=len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            low_count=len([v for v in vulnerabilities if v.get('severity') == 'Low']),
            by_category=self._count_by_category(vulnerabilities),
            by_file=self._count_by_file(vulnerabilities),
            trend_data=self.trend_analyzer.generate_trend_data()
        )
        
        # Create metrics
        metrics = ScanMetrics(
            files_scanned=scan_results.get('total_files', 0),
            lines_analyzed=scan_results.get('lines_analyzed', 0),
            scan_duration=scan_results.get('scan_duration', 0.0),
            coverage_percentage=scan_results.get('coverage_percentage', 85.0),
            false_positive_rate=scan_results.get('false_positive_rate', 0.1),
            confidence_score=scan_results.get('confidence_score', 0.85)
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(summary)
        
        # Check compliance status
        compliance_status = self._check_compliance_status(vulnerabilities)
        
        return ReportData(
            scan_id=scan_results.get('scan_id', f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
            timestamp=datetime.now(),
            project_name=scan_results.get('project_path', 'Unknown Project').split('/')[-1],
            project_path=scan_results.get('project_path', ''),
            summary=summary,
            metrics=metrics,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            compliance_status=compliance_status
        )
    
    def _count_by_category(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by category"""
        categories = {}
        for vuln in vulnerabilities:
            category = vuln.get('owasp_category', vuln.get('type', 'Unknown'))
            categories[category] = categories.get(category, 0) + 1
        return categories
    
    def _count_by_file(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by file"""
        files = {}
        for vuln in vulnerabilities:
            file_path = vuln.get('file_path', 'unknown')
            files[file_path] = files.get(file_path, 0) + 1
        return files
    
    def _generate_recommendations(self, summary: VulnerabilitySummary) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if summary.critical_count > 0:
            recommendations.append("Immediately address all Critical severity vulnerabilities")
        
        if summary.high_count > 5:
            recommendations.append("Implement automated security testing in CI/CD pipeline")
        
        if summary.total_vulnerabilities > 20:
            recommendations.append("Conduct comprehensive security code review")
            recommendations.append("Provide security training for development team")
        
        # Add category-specific recommendations
        top_category = max(summary.by_category.items(), key=lambda x: x[1], default=(None, 0))
        if top_category[0] and top_category[1] > 3:
            if 'Injection' in top_category[0]:
                recommendations.append("Implement input validation and parameterized queries")
            elif 'Access_Control' in top_category[0]:
                recommendations.append("Review and strengthen authorization mechanisms")
            elif 'Cryptographic' in top_category[0]:
                recommendations.append("Update cryptographic implementations to use secure algorithms")
        
        recommendations.append("Schedule regular security assessments")
        recommendations.append("Implement security monitoring and logging")
        
        return recommendations
    
    def _check_compliance_status(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Check OWASP Top 10 compliance status"""
        owasp_categories = [
            'A01_Broken_Access_Control',
            'A02_Cryptographic_Failures',
            'A03_Injection',
            'A04_Insecure_Design',
            'A05_Security_Misconfiguration',
            'A06_Vulnerable_Components',
            'A07_Auth_Failures',
            'A08_Integrity_Failures',
            'A09_Logging_Failures',
            'A10_SSRF'
        ]
        
        compliance_status = {}
        for category in owasp_categories:
            issues = [v for v in vulnerabilities if v.get('owasp_category') == category]
            compliance_status[category] = {
                'compliant': len(issues) == 0,
                'issues_found': len(issues),
                'critical_issues': len([v for v in issues if v.get('severity') == 'Critical'])
            }
        
        return compliance_status 