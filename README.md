# SCAR - Security Code Analysis & Review Tool

![SCAR Logo](https://img.shields.io/badge/SCAR-Security%20Analysis-red)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive static analysis tool for detecting OWASP Top 10 vulnerabilities in Java and Python codebases.

## 🔍 Features

- **OWASP Top 10 Detection**: Identifies security vulnerabilities based on OWASP Top 10 2021 standards
- **Multi-Language Support**: Supports Java and Python with language-agnostic architecture
- **CLI Interface**: Command-line tool for automated security scanning
- **Web Dashboard**: Interactive web interface for file uploads and result visualization
- **JSON Export**: Export scan results in JSON format for integration with other tools
- **Detailed Reporting**: Comprehensive vulnerability reports with remediation suggestions

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/SCAR.git
cd SCAR

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x scar.py
```

### CLI Usage

```bash
# Scan a directory
python scar.py --scan /path/to/your/project

# Scan with JSON output
python scar.py --scan /path/to/your/project --format json --output results.json

# Verbose output
python scar.py --scan /path/to/your/project --verbose
```

### Web Dashboard

```bash
# Launch web dashboard (coming soon)
python web_dashboard.py
```

## 🛡️ OWASP Top 10 Coverage

SCAR currently detects vulnerabilities in the following OWASP Top 10 categories:

1. **A01: Broken Access Control** - Detects improper authorization patterns
2. **A02: Cryptographic Failures** - Identifies weak cryptographic implementations
3. **A03: Injection** - Finds code injection vulnerabilities
4. **A04: Insecure Design** - Identifies design flaws and incomplete implementations
5. **A05: Security Misconfiguration** - Detects configuration security issues

*Additional categories will be added in future releases.*

## 📊 Sample Output

```
============================================================
SCAR Security Analysis Report
============================================================
Scan ID: scan_20240506_100000
Timestamp: 2023-05-06 10:00:00
Project: /path/to/project
Files Scanned: 25

Vulnerability Summary:
  Critical: 3
  High: 7
  Medium: 12
  Low: 2
  Total: 24

Detailed Findings:
------------------------------------------------------------
1. A03_Injection - Critical
   File: src/main/java/DataProcessor.java:45
   Description: Potential code injection vulnerability
   Code: Runtime.getRuntime().exec(userInput);
   Recommendation: Review and secure usage of 'Runtime.getRuntime'
```

## 🔧 Configuration

SCAR can be configured using a YAML configuration file:

```yaml
# scar_config.yaml
analysis:
  supported_extensions: ['.py', '.java']
  severity_levels: ['Critical', 'High', 'Medium', 'Low']
  
owasp_patterns:
  A03_Injection:
    enabled: true
    severity: 'Critical'
    custom_patterns: []
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Manan Wason** - Initial architecture and core development
- **Dewank Pant** - Security patterns and web interface

## 🔄 Version History

- **v1.0.0** (May 2023) - Initial release with CLI interface and basic OWASP detection
- More versions coming soon...

## 🐛 Bug Reports

Please report bugs and feature requests through [GitHub Issues](https://github.com/your-org/SCAR/issues).

## ⚠️ Disclaimer

SCAR is a static analysis tool and may produce false positives. Always review findings manually and conduct additional security testing for production systems. 