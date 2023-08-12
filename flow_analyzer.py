#!/usr/bin/env python3
"""
Logic Flow Analysis Engine for SCAR
Advanced data flow and control flow analysis for complex vulnerability detection
"""

import ast
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx

logger = logging.getLogger('SCAR.Flow')

class FlowType(Enum):
    """Types of data flow"""
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    ENCRYPTED = "encrypted"
    VALIDATED = "validated"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    """Risk levels for flow analysis"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

@dataclass
class DataFlowNode:
    """Represents a node in the data flow graph"""
    node_id: str
    variable_name: str
    line_number: int
    flow_type: FlowType
    source_type: str  # user_input, database, file, etc.
    operations: List[str] = field(default_factory=list)
    context: str = ""

@dataclass
class FlowVulnerability:
    """Vulnerability found through flow analysis"""
    vuln_type: str
    risk_level: RiskLevel
    source_node: DataFlowNode
    sink_node: DataFlowNode
    flow_path: List[DataFlowNode]
    description: str
    remediation: str
    confidence: float

class DataFlowAnalyzer:
    """Analyzes data flow to detect security vulnerabilities"""
    
    def __init__(self):
        self.flow_graph = nx.DiGraph()
        self.taint_sources = {
            'request.args.get', 'request.form.get', 'request.json.get',
            'input(', 'raw_input(', 'sys.argv', 'os.environ',
            'request.GET', 'request.POST', 'request.FILES',
            'HttpServletRequest.getParameter', 'HttpServletRequest.getHeader'
        }
        self.sanitization_functions = {
            'html.escape', 'urllib.parse.quote', 'escape', 'bleach.clean',
            'validator.escape', 'sanitize', 'clean', 'filter'
        }
        self.dangerous_sinks = {
            'eval', 'exec', 'compile', 'subprocess.call', 'subprocess.run',
            'os.system', 'os.popen', 'Runtime.getRuntime().exec',
            'Statement.execute', 'cursor.execute', 'query'
        }
        self.node_counter = 0
        
    def analyze_python_file(self, file_path: Path) -> List[FlowVulnerability]:
        """Analyze Python file for data flow vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            tree = ast.parse(content, filename=str(file_path))
            visitor = FlowVisitor(self, lines, str(file_path))
            visitor.visit(tree)
            
            # Analyze flows for vulnerabilities
            vulnerabilities = self._analyze_flows()
            
        except Exception as e:
            logger.error(f"Error analyzing flow in {file_path}: {e}")
        
        return vulnerabilities
    
    def add_flow_node(self, variable: str, line_num: int, flow_type: FlowType, 
                     source_type: str, context: str = "") -> DataFlowNode:
        """Add a node to the flow graph"""
        self.node_counter += 1
        node_id = f"node_{self.node_counter}"
        
        node = DataFlowNode(
            node_id=node_id,
            variable_name=variable,
            line_number=line_num,
            flow_type=flow_type,
            source_type=source_type,
            context=context
        )
        
        self.flow_graph.add_node(node_id, data=node)
        return node
    
    def add_flow_edge(self, from_node: DataFlowNode, to_node: DataFlowNode, 
                     operation: str = ""):
        """Add an edge between flow nodes"""
        self.flow_graph.add_edge(from_node.node_id, to_node.node_id, operation=operation)
        if operation:
            to_node.operations.append(operation)
    
    def _analyze_flows(self) -> List[FlowVulnerability]:
        """Analyze the flow graph for vulnerabilities"""
        vulnerabilities = []
        
        # Find all tainted sources
        tainted_nodes = [
            node_data['data'] for node_id, node_data in self.flow_graph.nodes(data=True)
            if node_data['data'].flow_type == FlowType.TAINTED
        ]
        
        # Find all dangerous sinks
        sink_nodes = [
            node_data['data'] for node_id, node_data in self.flow_graph.nodes(data=True)
            if any(sink in node_data['data'].context for sink in self.dangerous_sinks)
        ]
        
        # Check for paths from tainted sources to dangerous sinks
        for tainted_node in tainted_nodes:
            for sink_node in sink_nodes:
                try:
                    if nx.has_path(self.flow_graph, tainted_node.node_id, sink_node.node_id):
                        path_nodes = nx.shortest_path(self.flow_graph, tainted_node.node_id, sink_node.node_id)
                        flow_path = [self.flow_graph.nodes[node_id]['data'] for node_id in path_nodes]
                        
                        # Check if data is sanitized along the path
                        is_sanitized = any(
                            any(san_func in node.context for san_func in self.sanitization_functions)
                            for node in flow_path
                        )
                        
                        if not is_sanitized:
                            vuln = self._create_flow_vulnerability(tainted_node, sink_node, flow_path)
                            vulnerabilities.append(vuln)
                            
                except nx.NetworkXNoPath:
                    continue
        
        return vulnerabilities
    
    def _create_flow_vulnerability(self, source: DataFlowNode, sink: DataFlowNode, 
                                 path: List[DataFlowNode]) -> FlowVulnerability:
        """Create a vulnerability from flow analysis"""
        
        # Determine vulnerability type based on sink
        vuln_type = "Unknown"
        if any(sql_keyword in sink.context.lower() for sql_keyword in ['execute', 'query', 'sql']):
            vuln_type = "SQL Injection"
        elif any(cmd_keyword in sink.context.lower() for cmd_keyword in ['exec', 'system', 'subprocess']):
            vuln_type = "Command Injection"
        elif any(eval_keyword in sink.context.lower() for eval_keyword in ['eval', 'compile']):
            vuln_type = "Code Injection"
        
        # Calculate confidence based on path length and operations
        confidence = max(0.3, 1.0 - (len(path) * 0.1))
        
        # Determine risk level
        risk_level = RiskLevel.HIGH
        if vuln_type in ["SQL Injection", "Command Injection", "Code Injection"]:
            risk_level = RiskLevel.CRITICAL
        elif len(path) > 5:
            risk_level = RiskLevel.MEDIUM
        
        return FlowVulnerability(
            vuln_type=vuln_type,
            risk_level=risk_level,
            source_node=source,
            sink_node=sink,
            flow_path=path,
            description=f"Tainted data flows from {source.source_type} to {vuln_type.lower()} sink",
            remediation="Sanitize user input before using in sensitive operations",
            confidence=confidence
        )

class FlowVisitor(ast.NodeVisitor):
    """AST visitor for flow analysis"""
    
    def __init__(self, analyzer: DataFlowAnalyzer, source_lines: List[str], filename: str):
        self.analyzer = analyzer
        self.source_lines = source_lines
        self.filename = filename
        self.variable_flows: Dict[str, DataFlowNode] = {}
        self.current_function = None
        
    def visit_Assign(self, node):
        """Visit variable assignments"""
        if isinstance(node.value, ast.Call):
            call_name = self._get_call_name(node.value)
            
            # Check if this is a taint source
            if any(source in call_name for source in self.analyzer.taint_sources):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        taint_node = self.analyzer.add_flow_node(
                            variable=target.id,
                            line_num=node.lineno,
                            flow_type=FlowType.TAINTED,
                            source_type="user_input",
                            context=call_name
                        )
                        self.variable_flows[target.id] = taint_node
            
            # Check if this is a sanitization function
            elif any(san_func in call_name for san_func in self.analyzer.sanitization_functions):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Find the source variable being sanitized
                        source_var = None
                        if node.value.args:
                            first_arg = node.value.args[0]
                            if isinstance(first_arg, ast.Name):
                                source_var = first_arg.id
                        
                        sanitized_node = self.analyzer.add_flow_node(
                            variable=target.id,
                            line_num=node.lineno,
                            flow_type=FlowType.SANITIZED,
                            source_type="sanitized",
                            context=call_name
                        )
                        
                        # Connect to source if available
                        if source_var and source_var in self.variable_flows:
                            self.analyzer.add_flow_edge(
                                self.variable_flows[source_var],
                                sanitized_node,
                                "sanitization"
                            )
                        
                        self.variable_flows[target.id] = sanitized_node
            
            # Regular assignment - track flow
            else:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if value comes from a tracked variable
                        source_vars = self._extract_variables_from_value(node.value)
                        
                        if source_vars:
                            # Create new node for this assignment
                            new_node = self.analyzer.add_flow_node(
                                variable=target.id,
                                line_num=node.lineno,
                                flow_type=FlowType.UNKNOWN,
                                source_type="assignment",
                                context=self._get_source_line(node.lineno)
                            )
                            
                            # Connect to source variables
                            for source_var in source_vars:
                                if source_var in self.variable_flows:
                                    self.analyzer.add_flow_edge(
                                        self.variable_flows[source_var],
                                        new_node,
                                        "assignment"
                                    )
                                    # Propagate taint
                                    if self.variable_flows[source_var].flow_type == FlowType.TAINTED:
                                        new_node.flow_type = FlowType.TAINTED
                            
                            self.variable_flows[target.id] = new_node
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Visit function calls - potential sinks"""
        call_name = self._get_call_name(node)
        
        # Check if this is a dangerous sink
        if any(sink in call_name for sink in self.analyzer.dangerous_sinks):
            # Check arguments for tainted variables
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.variable_flows:
                    sink_node = self.analyzer.add_flow_node(
                        variable=f"sink_{arg.id}",
                        line_num=node.lineno,
                        flow_type=FlowType.UNKNOWN,
                        source_type="sink",
                        context=call_name
                    )
                    
                    self.analyzer.add_flow_edge(
                        self.variable_flows[arg.id],
                        sink_node,
                        "sink_usage"
                    )
        
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
        return "unknown_call"
    
    def _extract_variables_from_value(self, value_node: ast.AST) -> List[str]:
        """Extract variable names from a value expression"""
        variables = []
        
        if isinstance(value_node, ast.Name):
            variables.append(value_node.id)
        elif isinstance(value_node, ast.BinOp):
            variables.extend(self._extract_variables_from_value(value_node.left))
            variables.extend(self._extract_variables_from_value(value_node.right))
        elif isinstance(value_node, ast.Call):
            for arg in value_node.args:
                variables.extend(self._extract_variables_from_value(arg))
        
        return variables
    
    def _get_source_line(self, line_num: int) -> str:
        """Get source code line"""
        if 1 <= line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

class ControlFlowAnalyzer:
    """Analyzes control flow for security issues"""
    
    def __init__(self):
        self.control_flow_graph = nx.DiGraph()
        self.security_critical_blocks = []
    
    def analyze_control_flow(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze control flow for security issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=str(file_path))
            
            # Build control flow graph
            self._build_cfg(tree)
            
            # Analyze for security issues
            issues.extend(self._detect_unreachable_security_code())
            issues.extend(self._detect_missing_error_handling())
            issues.extend(self._detect_race_conditions())
            
        except Exception as e:
            logger.error(f"Error in control flow analysis of {file_path}: {e}")
        
        return issues
    
    def _build_cfg(self, tree: ast.AST):
        """Build control flow graph from AST"""
        # Simplified CFG construction
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.Try)):
                self._add_control_node(node)
    
    def _add_control_node(self, node: ast.AST):
        """Add control flow node"""
        node_id = f"cfg_{id(node)}"
        self.control_flow_graph.add_node(node_id, ast_node=node)
    
    def _detect_unreachable_security_code(self) -> List[Dict[str, Any]]:
        """Detect unreachable security-critical code"""
        issues = []
        # Implementation would analyze CFG for unreachable security checks
        return issues
    
    def _detect_missing_error_handling(self) -> List[Dict[str, Any]]:
        """Detect missing error handling around security operations"""
        issues = []
        # Implementation would check for try-catch around security operations
        return issues
    
    def _detect_race_conditions(self) -> List[Dict[str, Any]]:
        """Detect potential race conditions"""
        issues = []
        # Implementation would analyze shared resource access patterns
        return issues

class LogicFlowEngine:
    """Main logic flow analysis engine"""
    
    def __init__(self):
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.control_flow_analyzer = ControlFlowAnalyzer()
    
    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Perform complete flow analysis on a file"""
        results = {
            'file_path': str(file_path),
            'data_flow_vulnerabilities': [],
            'control_flow_issues': [],
            'flow_statistics': {}
        }
        
        if file_path.suffix == '.py':
            # Data flow analysis
            results['data_flow_vulnerabilities'] = self.data_flow_analyzer.analyze_python_file(file_path)
            
            # Control flow analysis
            results['control_flow_issues'] = self.control_flow_analyzer.analyze_control_flow(file_path)
            
            # Statistics
            results['flow_statistics'] = {
                'total_flow_nodes': self.data_flow_analyzer.flow_graph.number_of_nodes(),
                'total_flow_edges': self.data_flow_analyzer.flow_graph.number_of_edges(),
                'tainted_sources': len([
                    n for n in self.data_flow_analyzer.flow_graph.nodes(data=True)
                    if n[1]['data'].flow_type == FlowType.TAINTED
                ]),
                'vulnerabilities_found': len(results['data_flow_vulnerabilities'])
            }
        
        return results
    
    def analyze_directory(self, directory_path: Path) -> Dict[str, Any]:
        """Analyze all Python files in directory"""
        all_results = []
        
        for file_path in directory_path.rglob('*.py'):
            if file_path.is_file():
                results = self.analyze_file(file_path)
                all_results.append(results)
        
        # Aggregate statistics
        total_stats = {
            'files_analyzed': len(all_results),
            'total_vulnerabilities': sum(len(r['data_flow_vulnerabilities']) for r in all_results),
            'total_control_issues': sum(len(r['control_flow_issues']) for r in all_results),
            'critical_vulnerabilities': sum(
                len([v for v in r['data_flow_vulnerabilities'] if v.risk_level == RiskLevel.CRITICAL])
                for r in all_results
            )
        }
        
        return {
            'summary': total_stats,
            'file_results': all_results
        } 