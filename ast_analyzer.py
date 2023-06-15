#!/usr/bin/env python3
"""
AST Analyzer Module for SCAR
Advanced Abstract Syntax Tree analysis for detecting complex vulnerabilities
"""

import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger('SCAR.AST')

@dataclass
class ASTVulnerability:
    """Enhanced vulnerability class with AST context"""
    node_type: str
    function_name: Optional[str]
    class_name: Optional[str]
    variables_used: List[str]
    call_chain: List[str]
    complexity_score: int
    context_lines: List[str]

class PythonASTAnalyzer:
    """Python-specific AST analyzer"""
    
    def __init__(self):
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__', 'getattr', 'setattr',
            'delattr', 'hasattr', 'globals', 'locals', 'vars', 'open'
        }
        self.sql_patterns = [
            r'execute\s*\(',
            r'executemany\s*\(',
            r'raw\s*\(',
            r'extra\s*\(',
            r'SELECT.*FROM',
            r'INSERT.*INTO',
            r'UPDATE.*SET',
            r'DELETE.*FROM'
        ]
        
    def analyze_file(self, file_path: Path) -> List[ASTVulnerability]:
        """Analyze Python file using AST"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            tree = ast.parse(content, filename=str(file_path))
            visitor = VulnerabilityVisitor(lines, str(file_path))
            visitor.visit(tree)
            vulnerabilities.extend(visitor.vulnerabilities)
            
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            
        return vulnerabilities
    
    def detect_sql_injection(self, node: ast.AST, source_lines: List[str]) -> Optional[ASTVulnerability]:
        """Detect potential SQL injection vulnerabilities"""
        if isinstance(node, ast.Call):
            # Check for string formatting in SQL contexts
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['execute', 'executemany']:
                    for arg in node.args:
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                            return ASTVulnerability(
                                node_type='SQLInjection',
                                function_name=node.func.attr,
                                class_name=None,
                                variables_used=self._extract_variables(arg),
                                call_chain=[node.func.attr],
                                complexity_score=8,
                                context_lines=self._get_context_lines(node, source_lines)
                            )
        return None

    def _extract_variables(self, node: ast.AST) -> List[str]:
        """Extract variable names from AST node"""
        variables = []
        if isinstance(node, ast.Name):
            variables.append(node.id)
        elif hasattr(node, 'left') and hasattr(node, 'right'):
            variables.extend(self._extract_variables(node.left))
            variables.extend(self._extract_variables(node.right))
        elif hasattr(node, 'args'):
            for arg in node.args:
                variables.extend(self._extract_variables(arg))
        return variables
    
    def _get_context_lines(self, node: ast.AST, source_lines: List[str]) -> List[str]:
        """Get context lines around AST node"""
        if hasattr(node, 'lineno'):
            start = max(0, node.lineno - 3)
            end = min(len(source_lines), node.lineno + 2)
            return source_lines[start:end]
        return []

class VulnerabilityVisitor(ast.NodeVisitor):
    """AST visitor to detect vulnerabilities"""
    
    def __init__(self, source_lines: List[str], filename: str):
        self.source_lines = source_lines
        self.filename = filename
        self.vulnerabilities = []
        self.current_function = None
        self.current_class = None
        self.call_stack = []
        
    def visit_FunctionDef(self, node):
        """Visit function definitions"""
        old_function = self.current_function
        self.current_function = node.name
        
        # Check for dangerous function names or patterns
        if node.name.startswith('_') and not node.name.startswith('__'):
            # Potential private method exposure
            vuln = ASTVulnerability(
                node_type='InsecureDesign',
                function_name=node.name,
                class_name=self.current_class,
                variables_used=[],
                call_chain=self.call_stack.copy(),
                complexity_score=3,
                context_lines=self._get_node_context(node)
            )
            self.vulnerabilities.append(vuln)
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_ClassDef(self, node):
        """Visit class definitions"""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    
    def visit_Call(self, node):
        """Visit function calls"""
        self.call_stack.append(self._get_call_name(node))
        
        # Check for dangerous function calls
        call_name = self._get_call_name(node)
        if call_name in ['eval', 'exec', 'compile']:
            vuln = ASTVulnerability(
                node_type='CodeInjection',
                function_name=self.current_function,
                class_name=self.current_class,
                variables_used=self._extract_call_variables(node),
                call_chain=self.call_stack.copy(),
                complexity_score=9,
                context_lines=self._get_node_context(node)
            )
            self.vulnerabilities.append(vuln)
        
        # Check for subprocess calls with shell=True
        if call_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen']:
            for keyword in node.keywords:
                if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        vuln = ASTVulnerability(
                            node_type='CommandInjection',
                            function_name=self.current_function,
                            class_name=self.current_class,
                            variables_used=self._extract_call_variables(node),
                            call_chain=self.call_stack.copy(),
                            complexity_score=8,
                            context_lines=self._get_node_context(node)
                        )
                        self.vulnerabilities.append(vuln)
        
        self.generic_visit(node)
        self.call_stack.pop()
    
    def visit_Import(self, node):
        """Visit import statements"""
        for alias in node.names:
            if alias.name in ['pickle', 'cPickle', 'dill']:
                vuln = ASTVulnerability(
                    node_type='InsecureDeserialization',
                    function_name=self.current_function,
                    class_name=self.current_class,
                    variables_used=[alias.name],
                    call_chain=self.call_stack.copy(),
                    complexity_score=6,
                    context_lines=self._get_node_context(node)
                )
                self.vulnerabilities.append(vuln)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """Visit variable assignments"""
        # Check for hardcoded secrets
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value.lower()
            secret_patterns = ['password', 'secret', 'key', 'token', 'api_key']
            
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if any(pattern in var_name for pattern in secret_patterns):
                        vuln = ASTVulnerability(
                            node_type='HardcodedCredentials',
                            function_name=self.current_function,
                            class_name=self.current_class,
                            variables_used=[target.id],
                            call_chain=self.call_stack.copy(),
                            complexity_score=7,
                            context_lines=self._get_node_context(node)
                        )
                        self.vulnerabilities.append(vuln)
        
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function call name"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            else:
                return node.func.attr
        return "unknown"
    
    def _extract_call_variables(self, node: ast.Call) -> List[str]:
        """Extract variables used in function call"""
        variables = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                variables.append(arg.id)
        return variables
    
    def _get_node_context(self, node: ast.AST) -> List[str]:
        """Get source code context for AST node"""
        if hasattr(node, 'lineno'):
            start = max(0, node.lineno - 2)
            end = min(len(self.source_lines), node.lineno + 1)
            return self.source_lines[start:end]
        return []

class JavaASTAnalyzer:
    """Java-specific code analyzer (regex-based for now)"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'SQLInjection': [
                r'Statement\.execute\([^)]*\+',
                r'PreparedStatement\.setString\([^)]*\+',
                r'createQuery\([^)]*\+',
                r'createNativeQuery\([^)]*\+'
            ],
            'CommandInjection': [
                r'Runtime\.getRuntime\(\)\.exec\(',
                r'ProcessBuilder\([^)]*\+',
                r'new\s+ProcessBuilder\([^)]*\+'
            ],
            'XSS': [
                r'response\.getWriter\(\)\.write\([^)]*\+',
                r'response\.getWriter\(\)\.print\([^)]*\+',
                r'PrintWriter\.write\([^)]*\+'
            ],
            'PathTraversal': [
                r'new\s+File\([^)]*\+',
                r'Paths\.get\([^)]*\+',
                r'Files\.newInputStream\([^)]*\+'
            ]
        }
    
    def analyze_file(self, file_path: Path) -> List[ASTVulnerability]:
        """Analyze Java file using regex patterns"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        vuln = ASTVulnerability(
                            node_type=vuln_type,
                            function_name=self._extract_java_method(lines, line_num),
                            class_name=self._extract_java_class(lines, line_num),
                            variables_used=self._extract_java_variables(match.group()),
                            call_chain=[],
                            complexity_score=self._calculate_complexity(vuln_type),
                            context_lines=self._get_java_context(lines, line_num)
                        )
                        vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error analyzing Java file {file_path}: {e}")
        
        return vulnerabilities
    
    def _extract_java_method(self, lines: List[str], line_num: int) -> Optional[str]:
        """Extract Java method name from context"""
        for i in range(line_num - 1, max(0, line_num - 20), -1):
            line = lines[i].strip()
            method_match = re.search(r'(public|private|protected)?\s*\w+\s+(\w+)\s*\(', line)
            if method_match:
                return method_match.group(2)
        return None
    
    def _extract_java_class(self, lines: List[str], line_num: int) -> Optional[str]:
        """Extract Java class name from context"""
        for i in range(line_num - 1, max(0, line_num - 50), -1):
            line = lines[i].strip()
            class_match = re.search(r'class\s+(\w+)', line)
            if class_match:
                return class_match.group(1)
        return None
    
    def _extract_java_variables(self, code_snippet: str) -> List[str]:
        """Extract variable names from Java code snippet"""
        variables = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code_snippet)
        return [var for var in variables if var not in ['new', 'public', 'private', 'protected', 'static', 'final']]
    
    def _calculate_complexity(self, vuln_type: str) -> int:
        """Calculate complexity score based on vulnerability type"""
        complexity_map = {
            'SQLInjection': 9,
            'CommandInjection': 8,
            'XSS': 7,
            'PathTraversal': 6
        }
        return complexity_map.get(vuln_type, 5)
    
    def _get_java_context(self, lines: List[str], line_num: int) -> List[str]:
        """Get context lines around Java vulnerability"""
        start = max(0, line_num - 3)
        end = min(len(lines), line_num + 2)
        return lines[start:end]

class UnifiedASTAnalyzer:
    """Unified analyzer that handles both Python and Java"""
    
    def __init__(self):
        self.python_analyzer = PythonASTAnalyzer()
        self.java_analyzer = JavaASTAnalyzer()
    
    def analyze_file(self, file_path: Path) -> List[ASTVulnerability]:
        """Analyze file based on its extension"""
        if file_path.suffix == '.py':
            return self.python_analyzer.analyze_file(file_path)
        elif file_path.suffix == '.java':
            return self.java_analyzer.analyze_file(file_path)
        else:
            logger.warning(f"Unsupported file type: {file_path}")
            return []
    
    def analyze_directory(self, directory_path: Path) -> Dict[str, List[ASTVulnerability]]:
        """Analyze all supported files in directory"""
        results = {}
        
        for file_path in directory_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.java']:
                vulnerabilities = self.analyze_file(file_path)
                if vulnerabilities:
                    results[str(file_path)] = vulnerabilities
        
        return results 