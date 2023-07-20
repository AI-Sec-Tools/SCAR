#!/usr/bin/env python3
"""
OWASP Top 10 Vulnerability Patterns Module for SCAR
Comprehensive patterns for detecting all OWASP Top 10 2021 vulnerabilities
"""

import re
import logging
from typing import Dict, List, Any, Optional, Pattern
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger('SCAR.OWASP')

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class OWASPPattern:
    """OWASP vulnerability pattern definition"""
    category: str
    subcategory: str
    patterns: List[str]
    regex_patterns: List[Pattern]
    severity: Severity
    description: str
    impact: str
    remediation: str
    references: List[str]
    cwe_ids: List[int]

class OWASPPatternDatabase:
    """Comprehensive OWASP Top 10 pattern database"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.compiled_patterns = self._compile_patterns()
    
    def _initialize_patterns(self) -> Dict[str, List[OWASPPattern]]:
        """Initialize all OWASP Top 10 2021 patterns"""
        
        patterns = {
            # A01: Broken Access Control
            "A01_Broken_Access_Control": [
                OWASPPattern(
                    category="A01_Broken_Access_Control",
                    subcategory="Missing Authorization",
                    patterns=[
                        "@RequestMapping", "@GetMapping", "@PostMapping", 
                        "@PutMapping", "@DeleteMapping", "app.route",
                        "flask.route", "def get(", "def post(", "def put(", "def delete("
                    ],
                    regex_patterns=[
                        re.compile(r'@(Get|Post|Put|Delete|Request)Mapping(?!\s*\([^)]*authorize)', re.IGNORECASE),
                        re.compile(r'@app\.route(?!\s*\([^)]*login_required)', re.IGNORECASE),
                        re.compile(r'def\s+(get|post|put|delete)\s*\([^)]*\):(?!.*@login_required)', re.IGNORECASE | re.DOTALL)
                    ],
                    severity=Severity.HIGH,
                    description="Endpoint without explicit authorization checks",
                    impact="Unauthorized access to sensitive functionality",
                    remediation="Add proper authorization decorators (@PreAuthorize, @login_required)",
                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    cwe_ids=[284, 285, 862]
                ),
                OWASPPattern(
                    category="A01_Broken_Access_Control",
                    subcategory="IDOR Vulnerability",
                    patterns=[
                        "findById", "getById", "getUserById", "request.args.get('id')",
                        "request.form['id']", "params.get('id')", "request.GET['id']"
                    ],
                    regex_patterns=[
                        re.compile(r'(findById|getById|getUserById)\s*\(\s*request\.(args|form|GET)', re.IGNORECASE),
                        re.compile(r'(SELECT|DELETE|UPDATE).*WHERE.*id\s*=\s*[\'"]?\$\{?[^}]*\}?[\'"]?', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Potential Insecure Direct Object Reference vulnerability",
                    impact="Access to unauthorized resources via object reference manipulation",
                    remediation="Implement proper access controls and validate object ownership",
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
                    cwe_ids=[639, 22]
                )
            ],
            
            # A02: Cryptographic Failures
            "A02_Cryptographic_Failures": [
                OWASPPattern(
                    category="A02_Cryptographic_Failures",
                    subcategory="Weak Hashing",
                    patterns=[
                        "MD5", "SHA1", "md5", "sha1", "hashlib.md5", "hashlib.sha1",
                        "MessageDigest.getInstance(\"MD5\")", "MessageDigest.getInstance(\"SHA-1\")"
                    ],
                    regex_patterns=[
                        re.compile(r'(MD5|SHA-?1|md5|sha1)', re.IGNORECASE),
                        re.compile(r'MessageDigest\.getInstance\s*\(\s*[\'\"](MD5|SHA-?1)[\'\"]', re.IGNORECASE),
                        re.compile(r'hashlib\.(md5|sha1)', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Use of weak cryptographic hash functions",
                    impact="Vulnerable to collision attacks and rainbow table attacks",
                    remediation="Use SHA-256 or stronger hash functions (SHA-3, Blake2)",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                    cwe_ids=[327, 328, 916]
                ),
                OWASPPattern(
                    category="A02_Cryptographic_Failures",
                    subcategory="Weak Encryption",
                    patterns=[
                        "DES", "3DES", "RC4", "ECB", "Cipher.getInstance(\"DES",
                        "Cipher.getInstance(\"AES/ECB", "PyCrypto", "pycrypto"
                    ],
                    regex_patterns=[
                        re.compile(r'Cipher\.getInstance\s*\(\s*[\'\"](DES|3DES|RC4|AES/ECB)', re.IGNORECASE),
                        re.compile(r'(DES|3DES|RC4|ECB)(?!cription|crypt)', re.IGNORECASE),
                        re.compile(r'from\s+Crypto(?!graphy)', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Use of weak encryption algorithms or modes",
                    impact="Data can be easily decrypted by attackers",
                    remediation="Use AES-256 with GCM or CBC mode with proper IV",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                    cwe_ids=[327, 326, 328]
                )
            ],
            
            # A03: Injection
            "A03_Injection": [
                OWASPPattern(
                    category="A03_Injection",
                    subcategory="SQL Injection",
                    patterns=[
                        "Statement.executeQuery", "Statement.execute", "cursor.execute",
                        "query = \"SELECT", "query = 'SELECT", "sql = \"INSERT", "sql = 'UPDATE"
                    ],
                    regex_patterns=[
                        re.compile(r'(execute|executeQuery|executeBatch)\s*\(\s*[\'\"]\s*(SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+', re.IGNORECASE | re.DOTALL),
                        re.compile(r'(SELECT|INSERT|UPDATE|DELETE).*[\'\"]\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*', re.IGNORECASE),
                        re.compile(r'cursor\.execute\s*\(\s*[\'\"f].*%[sd]', re.IGNORECASE),
                        re.compile(r'(query|sql)\s*=\s*[\'\"f].*\{.*\}', re.IGNORECASE)
                    ],
                    severity=Severity.CRITICAL,
                    description="Potential SQL injection vulnerability",
                    impact="Complete database compromise, data theft, data manipulation",
                    remediation="Use parameterized queries or prepared statements",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                    cwe_ids=[89, 564, 943]
                ),
                OWASPPattern(
                    category="A03_Injection",
                    subcategory="Command Injection",
                    patterns=[
                        "Runtime.getRuntime().exec", "ProcessBuilder", "subprocess.call",
                        "subprocess.run", "subprocess.Popen", "os.system", "os.popen", "eval(", "exec("
                    ],
                    regex_patterns=[
                        re.compile(r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.(call|run|Popen)|os\.(system|popen))\s*\([^)]*[+&|]', re.IGNORECASE),
                        re.compile(r'(eval|exec)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*', re.IGNORECASE),
                        re.compile(r'shell\s*=\s*True', re.IGNORECASE)
                    ],
                    severity=Severity.CRITICAL,
                    description="Potential command injection vulnerability",
                    impact="Remote code execution, system compromise",
                    remediation="Avoid dynamic command execution, use parameterized commands",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                    cwe_ids=[78, 77, 94]
                )
            ],
            
            # A04: Insecure Design
            "A04_Insecure_Design": [
                OWASPPattern(
                    category="A04_Insecure_Design",
                    subcategory="Missing Security Controls",
                    patterns=[
                        "TODO", "FIXME", "XXX", "HACK", "BUG", "password", "secret", "debug"
                    ],
                    regex_patterns=[
                        re.compile(r'(TODO|FIXME|XXX|HACK|BUG).*security', re.IGNORECASE),
                        re.compile(r'(password|secret|key|token)\s*=\s*[\'\"]\w+[\'\"]\s*;?\s*#?\s*(TODO|FIXME)', re.IGNORECASE),
                        re.compile(r'debug\s*=\s*True', re.IGNORECASE)
                    ],
                    severity=Severity.MEDIUM,
                    description="Insecure design patterns or incomplete security implementation",
                    impact="Various security vulnerabilities due to design flaws",
                    remediation="Complete security implementation and remove debug code",
                    references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                    cwe_ids=[656, 657, 693]
                )
            ],
            
            # A05: Security Misconfiguration
            "A05_Security_Misconfiguration": [
                OWASPPattern(
                    category="A05_Security_Misconfiguration",
                    subcategory="Debug Configuration",
                    patterns=[
                        "debug=True", "DEBUG=true", "printStackTrace", "console.log",
                        "System.out.println", "print(", "echo "
                    ],
                    regex_patterns=[
                        re.compile(r'(debug|DEBUG)\s*=\s*(True|true|1)', re.IGNORECASE),
                        re.compile(r'printStackTrace\s*\(\s*\)', re.IGNORECASE),
                        re.compile(r'(console\.log|System\.out\.println|print)\s*\([^)]*(?:password|secret|key|token)', re.IGNORECASE)
                    ],
                    severity=Severity.MEDIUM,
                    description="Debug configuration enabled in production",
                    impact="Information disclosure, stack trace exposure",
                    remediation="Disable debug mode and remove debug statements in production",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    cwe_ids=[489, 532, 215]
                )
            ],
            
            # A06: Vulnerable and Outdated Components
            "A06_Vulnerable_Components": [
                OWASPPattern(
                    category="A06_Vulnerable_Components",
                    subcategory="Outdated Dependencies",
                    patterns=[
                        "spring-core:4", "spring-web:4", "django==1", "flask==0", "requests==2.0",
                        "jackson-databind:2.9", "struts2-core"
                    ],
                    regex_patterns=[
                        re.compile(r'(spring-core|spring-web):[0-4]\.', re.IGNORECASE),
                        re.compile(r'django==[01]\.', re.IGNORECASE),
                        re.compile(r'flask==[0]\.', re.IGNORECASE),
                        re.compile(r'jackson-databind:2\.[0-9]\.', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Use of vulnerable or outdated components",
                    impact="Known security vulnerabilities in dependencies",
                    remediation="Update to latest secure versions of dependencies",
                    references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
                    cwe_ids=[1104, 1035, 937]
                )
            ],
            
            # A07: Identification and Authentication Failures
            "A07_Auth_Failures": [
                OWASPPattern(
                    category="A07_Auth_Failures",
                    subcategory="Weak Authentication",
                    patterns=[
                        "password", "123456", "admin", "root", "guest", "hardcoded"
                    ],
                    regex_patterns=[
                        re.compile(r'(password|passwd|pwd)\s*=\s*[\'\"](?![\$\{])(admin|root|123456?|password|pass|guest|test)[\'\"]', re.IGNORECASE),
                        re.compile(r'if\s+password\s*==\s*[\'\"][^\'\"]{1,8}[\'\"]', re.IGNORECASE),
                        re.compile(r'(login|authenticate)\([^)]*[\'\"][^\'\"]{1,8}[\'\"]', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Weak or hardcoded authentication credentials",
                    impact="Easy authentication bypass, unauthorized access",
                    remediation="Use strong passwords, secure password storage (bcrypt, scrypt)",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                    cwe_ids=[798, 259, 521]
                )
            ],
            
            # A08: Software and Data Integrity Failures
            "A08_Integrity_Failures": [
                OWASPPattern(
                    category="A08_Integrity_Failures",
                    subcategory="Insecure Deserialization",
                    patterns=[
                        "pickle.loads", "pickle.load", "yaml.load", "ObjectInputStream",
                        "readObject", "Serializable", "eval(", "json.loads"
                    ],
                    regex_patterns=[
                        re.compile(r'pickle\.(loads?|dump)\s*\([^)]*user_input', re.IGNORECASE),
                        re.compile(r'yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)', re.IGNORECASE),
                        re.compile(r'ObjectInputStream.*readObject\s*\(\)', re.IGNORECASE),
                        re.compile(r'eval\s*\(\s*json\.loads', re.IGNORECASE)
                    ],
                    severity=Severity.CRITICAL,
                    description="Insecure deserialization of untrusted data",
                    impact="Remote code execution, data tampering",
                    remediation="Use safe deserialization methods, validate serialized data",
                    references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
                    cwe_ids=[502, 494, 829]
                )
            ],
            
            # A09: Security Logging and Monitoring Failures
            "A09_Logging_Failures": [
                OWASPPattern(
                    category="A09_Logging_Failures",
                    subcategory="Missing Security Logging",
                    patterns=[
                        "login", "authentication", "authorization", "admin", "privilege"
                    ],
                    regex_patterns=[
                        re.compile(r'(login|authenticate|authorize)(?!.*log)', re.IGNORECASE),
                        re.compile(r'@(Pre|Post)Authorize(?!.*audit)', re.IGNORECASE),
                        re.compile(r'(failed|success).*login(?!.*log)', re.IGNORECASE)
                    ],
                    severity=Severity.MEDIUM,
                    description="Missing security event logging",
                    impact="Inability to detect and respond to security incidents",
                    remediation="Implement comprehensive security logging and monitoring",
                    references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
                    cwe_ids=[778, 223, 532]
                )
            ],
            
            # A10: Server-Side Request Forgery (SSRF)
            "A10_SSRF": [
                OWASPPattern(
                    category="A10_SSRF",
                    subcategory="SSRF Vulnerability",
                    patterns=[
                        "requests.get", "requests.post", "urllib.request", "HttpURLConnection",
                        "RestTemplate", "WebClient", "fetch(", "axios.get"
                    ],
                    regex_patterns=[
                        re.compile(r'(requests\.(get|post)|urllib\.request\.urlopen|HttpURLConnection)\s*\([^)]*[+&].*user_input', re.IGNORECASE),
                        re.compile(r'(RestTemplate|WebClient|fetch|axios)\.[a-zA-Z]+\s*\(\s*[^)]*\+', re.IGNORECASE),
                        re.compile(r'(http://|https://)[^\'\"]*\{[^}]*\}', re.IGNORECASE)
                    ],
                    severity=Severity.HIGH,
                    description="Potential Server-Side Request Forgery vulnerability",
                    impact="Access to internal systems, port scanning, data exfiltration",
                    remediation="Validate and whitelist URLs, use network segmentation",
                    references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                    cwe_ids=[918, 611, 441]
                )
            ]
        }
        
        return patterns
    
    def _compile_patterns(self) -> Dict[str, List[Pattern]]:
        """Compile all regex patterns for performance"""
        compiled = {}
        for category, pattern_list in self.patterns.items():
            compiled[category] = []
            for pattern in pattern_list:
                compiled[category].extend(pattern.regex_patterns)
        return compiled
    
    def get_patterns_by_category(self, category: str) -> List[OWASPPattern]:
        """Get patterns for specific OWASP category"""
        return self.patterns.get(category, [])
    
    def get_all_patterns(self) -> Dict[str, List[OWASPPattern]]:
        """Get all OWASP patterns"""
        return self.patterns
    
    def match_patterns(self, content: str, category: str = None) -> List[Dict[str, Any]]:
        """Match content against OWASP patterns"""
        matches = []
        
        categories_to_check = [category] if category else self.patterns.keys()
        
        for cat in categories_to_check:
            if cat not in self.patterns:
                continue
                
            for pattern in self.patterns[cat]:
                # Check string patterns
                for string_pattern in pattern.patterns:
                    if string_pattern.lower() in content.lower():
                        matches.append({
                            'category': pattern.category,
                            'subcategory': pattern.subcategory,
                            'pattern': string_pattern,
                            'severity': pattern.severity.value,
                            'description': pattern.description,
                            'remediation': pattern.remediation,
                            'cwe_ids': pattern.cwe_ids
                        })
                
                # Check regex patterns
                for regex_pattern in pattern.regex_patterns:
                    regex_matches = regex_pattern.finditer(content)
                    for match in regex_matches:
                        matches.append({
                            'category': pattern.category,
                            'subcategory': pattern.subcategory,
                            'pattern': match.group(),
                            'severity': pattern.severity.value,
                            'description': pattern.description,
                            'remediation': pattern.remediation,
                            'cwe_ids': pattern.cwe_ids,
                            'line_start': content[:match.start()].count('\n') + 1,
                            'match_start': match.start(),
                            'match_end': match.end()
                        })
        
        return matches

class OWASPScanner:
    """OWASP-focused vulnerability scanner"""
    
    def __init__(self):
        self.pattern_db = OWASPPatternDatabase()
        self.total_scanned = 0
        self.total_vulnerabilities = 0
    
    def scan_content(self, content: str, filename: str = None) -> List[Dict[str, Any]]:
        """Scan content for OWASP vulnerabilities"""
        self.total_scanned += 1
        matches = self.pattern_db.match_patterns(content)
        self.total_vulnerabilities += len(matches)
        
        # Add filename to matches
        for match in matches:
            match['filename'] = filename or 'unknown'
        
        return matches
    
    def get_statistics(self) -> Dict[str, int]:
        """Get scanning statistics"""
        return {
            'files_scanned': self.total_scanned,
            'vulnerabilities_found': self.total_vulnerabilities
        }
    
    def get_owasp_coverage(self) -> Dict[str, bool]:
        """Get OWASP Top 10 coverage status"""
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
        
        return {cat: cat in self.pattern_db.patterns for cat in owasp_categories} 