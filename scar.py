#!/usr/bin/env python3
"""
SCAR - Security Code Analysis & Review Tool
A comprehensive static analysis tool for detecting OWASP Top 10 vulnerabilities
in Java and Python codebases.

Author: Manan Wason & Dewank Pant
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SCAR')

@dataclass
class Vulnerability:
    """Data class to represent a security vulnerability"""
    type: str
    severity: str  # Critical, High, Medium, Low
    file_path: str
    line_number: int
    description: str
    owasp_category: str
    recommendation: str
    code_snippet: str

@dataclass
class ScanResult:
    """Data class to represent scan results"""
    scan_id: str
    timestamp: datetime
    project_path: str
    total_files: int
    vulnerabilities: List[Vulnerability]
    summary: Dict[str, int]

class SCARAnalyzer:
    """Main SCAR security analyzer class"""
    
    def __init__(self):
        self.supported_extensions = {'.py', '.java'}
        self.owasp_patterns = self._initialize_owasp_patterns()
        self.scan_results: List[ScanResult] = []
    
    def _initialize_owasp_patterns(self) -> Dict[str, Dict]:
        """Initialize OWASP Top 10 vulnerability patterns"""
        return {
            'A01_Broken_Access_Control': {
                'patterns': ['@PreAuthorize', 'hasRole', 'permitAll'],
                'severity': 'High',
                'description': 'Potential broken access control vulnerability'
            },
            'A02_Cryptographic_Failures': {
                'patterns': ['MD5', 'SHA1', 'DES', 'ECB'],
                'severity': 'High', 
                'description': 'Weak cryptographic implementation detected'
            },
            'A03_Injection': {
                'patterns': ['execute(', 'eval(', 'exec(', 'Runtime.getRuntime'],
                'severity': 'Critical',
                'description': 'Potential code injection vulnerability'
            },
            'A04_Insecure_Design': {
                'patterns': ['TODO', 'FIXME', 'XXX'],
                'severity': 'Medium',
                'description': 'Insecure design pattern or incomplete implementation'
            },
            'A05_Security_Misconfiguration': {
                'patterns': ['debug=True', 'DEBUG=true', 'printStackTrace'],
                'severity': 'Medium',
                'description': 'Security misconfiguration detected'
            }
        }
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower().strip()
                
                for owasp_cat, pattern_info in self.owasp_patterns.items():
                    for pattern in pattern_info['patterns']:
                        if pattern.lower() in line_lower:
                            vuln = Vulnerability(
                                type=pattern,
                                severity=pattern_info['severity'],
                                file_path=str(file_path),
                                line_number=line_num,
                                description=pattern_info['description'],
                                owasp_category=owasp_cat,
                                recommendation=f"Review and secure usage of '{pattern}'",
                                code_snippet=line.strip()
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            
        return vulnerabilities
    
    def scan_directory(self, directory_path: Path) -> ScanResult:
        """Scan entire directory for vulnerabilities"""
        logger.info(f"Starting security scan of: {directory_path}")
        
        all_vulnerabilities = []
        file_count = 0
        
        for file_path in directory_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in self.supported_extensions:
                file_count += 1
                vulnerabilities = self.scan_file(file_path)
                all_vulnerabilities.extend(vulnerabilities)
        
        # Generate summary
        summary = {
            'Critical': len([v for v in all_vulnerabilities if v.severity == 'Critical']),
            'High': len([v for v in all_vulnerabilities if v.severity == 'High']),
            'Medium': len([v for v in all_vulnerabilities if v.severity == 'Medium']),
            'Low': len([v for v in all_vulnerabilities if v.severity == 'Low'])
        }
        
        scan_result = ScanResult(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now(),
            project_path=str(directory_path),
            total_files=file_count,
            vulnerabilities=all_vulnerabilities,
            summary=summary
        )
        
        self.scan_results.append(scan_result)
        logger.info(f"Scan completed. Found {len(all_vulnerabilities)} vulnerabilities in {file_count} files")
        
        return scan_result
    
    def export_json(self, scan_result: ScanResult, output_path: Path) -> None:
        """Export scan results to JSON"""
        try:
            # Convert dataclass to dict with custom datetime serialization
            result_dict = asdict(scan_result)
            result_dict['timestamp'] = scan_result.timestamp.isoformat()
            
            with open(output_path, 'w') as f:
                json.dump(result_dict, f, indent=2)
                
            logger.info(f"Results exported to: {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting results: {e}")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='SCAR - Security Code Analysis & Review Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scar.py --scan /path/to/project
  scar.py --scan /path/to/project --output results.json
  scar.py --scan /path/to/project --format json
        """
    )
    
    parser.add_argument(
        '--scan', '-s',
        type=str,
        required=True,
        help='Path to directory or file to scan'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='scar_results.json',
        help='Output file path (default: scar_results.json)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'console'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize analyzer
    analyzer = SCARAnalyzer()
    
    # Perform scan
    scan_path = Path(args.scan)
    if not scan_path.exists():
        logger.error(f"Path does not exist: {scan_path}")
        sys.exit(1)
    
    if scan_path.is_file():
        # Scan single file
        vulnerabilities = analyzer.scan_file(scan_path)
        scan_result = ScanResult(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now(),
            project_path=str(scan_path),
            total_files=1,
            vulnerabilities=vulnerabilities,
            summary={
                'Critical': len([v for v in vulnerabilities if v.severity == 'Critical']),
                'High': len([v for v in vulnerabilities if v.severity == 'High']),
                'Medium': len([v for v in vulnerabilities if v.severity == 'Medium']),
                'Low': len([v for v in vulnerabilities if v.severity == 'Low'])
            }
        )
    else:
        # Scan directory
        scan_result = analyzer.scan_directory(scan_path)
    
    # Output results
    if args.format == 'json':
        analyzer.export_json(scan_result, Path(args.output))
    else:
        # Console output
        print(f"\n{'='*60}")
        print(f"SCAR Security Analysis Report")
        print(f"{'='*60}")
        print(f"Scan ID: {scan_result.scan_id}")
        print(f"Timestamp: {scan_result.timestamp}")
        print(f"Project: {scan_result.project_path}")
        print(f"Files Scanned: {scan_result.total_files}")
        print(f"\nVulnerability Summary:")
        print(f"  Critical: {scan_result.summary['Critical']}")
        print(f"  High: {scan_result.summary['High']}")
        print(f"  Medium: {scan_result.summary['Medium']}")
        print(f"  Low: {scan_result.summary['Low']}")
        print(f"  Total: {len(scan_result.vulnerabilities)}")
        
        if scan_result.vulnerabilities:
            print(f"\nDetailed Findings:")
            print(f"{'-'*60}")
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                print(f"{i}. {vuln.owasp_category} - {vuln.severity}")
                print(f"   File: {vuln.file_path}:{vuln.line_number}")
                print(f"   Description: {vuln.description}")
                print(f"   Code: {vuln.code_snippet}")
                print(f"   Recommendation: {vuln.recommendation}")
                print()

if __name__ == '__main__':
    main()