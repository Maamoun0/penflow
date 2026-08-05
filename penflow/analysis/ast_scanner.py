"""
Hybrid SAST AST Source Code Security Analyzer for PenFlow.

Parses source code using Python Abstract Syntax Trees (AST) to identify:
  - Dangerous sink function calls (eval, exec, os.system, subprocess with shell=True)
  - Unsafe SQL query construction (string formatting/interpolation in DB execute calls)
  - Hardcoded credentials, secrets, and API tokens
  - Insecure deserialization patterns (pickle.loads, yaml.load without SafeLoader)
"""
import ast
import os
import re
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.analysis.ast_scanner")

SECRET_VAR_PATTERN = re.compile(r"(?i)(password|secret|api_key|access_token|auth_token|private_key|jwt_secret)")
DANGEROUS_CALLS = {
    "eval": ("CRITICAL", "Dynamic code execution via eval() detected."),
    "exec": ("CRITICAL", "Dynamic code execution via exec() detected."),
    "os.system": ("HIGH", "Command execution via os.system() detected."),
    "os.popen": ("HIGH", "Command execution via os.popen() detected."),
    "pickle.loads": ("HIGH", "Unsafe deserialization via pickle.loads() detected."),
    "pickle.load": ("HIGH", "Unsafe deserialization via pickle.load() detected."),
    "yaml.load": ("HIGH", "YAML deserialization detected. Ensure SafeLoader is used."),
}


class ASTSecurityVisitor(ast.NodeVisitor):
    """
    AST Visitor that inspects nodes for common security vulnerabilities.
    """

    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[Dict[str, Any]] = []

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            val = node.func.value
            prefix = ""
            if isinstance(val, ast.Name):
                prefix = val.id + "."
            return prefix + node.func.attr
        return ""

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node)

        # 1. Check known dangerous function calls
        if call_name in DANGEROUS_CALLS:
            severity, desc = DANGEROUS_CALLS[call_name]
            self._add_finding(node.lineno, "dangerous_function_call", severity, desc, call_name)

        # 2. Check subprocess calls with shell=True
        if call_name.startswith("subprocess.") or call_name in ("Popen", "run", "call"):
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add_finding(
                            node.lineno,
                            "command_injection_risk",
                            "HIGH",
                            f"Subprocess call '{call_name}' with shell=True detected.",
                            call_name
                        )

        # 3. Check SQL execution with string formatting / f-strings
        if call_name.endswith(".execute") or call_name == "execute":
            if node.args:
                first_arg = node.args[0]
                is_formatted = False
                if isinstance(first_arg, ast.JoinedStr):  # f-string
                    is_formatted = True
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):  # % or +
                    is_formatted = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_formatted = True

                if is_formatted:
                    self._add_finding(
                        node.lineno,
                        "sql_injection_sast",
                        "HIGH",
                        "SQL query constructed using string formatting/interpolation in execute() call.",
                        call_name
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Check for hardcoded secret variables
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if SECRET_VAR_PATTERN.search(var_name):
                    # Check if assigned to a non-empty string literal
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) >= 6 and not val.startswith("${") and not val.startswith("env:"):
                            self._add_finding(
                                node.lineno,
                                "hardcoded_secret_sast",
                                "MEDIUM",
                                f"Potential hardcoded secret assigned to variable '{var_name}'.",
                                var_name
                            )

        self.generic_visit(node)

    def _add_finding(self, line_num: int, vuln_type: str, severity: str, description: str, symbol: str):
        snippet = self.source_lines[line_num - 1].strip() if 0 < line_num <= len(self.source_lines) else ""
        finding = {
            "file": self.filename,
            "line": line_num,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "description": description,
            "symbol": symbol,
            "code_snippet": snippet
        }
        self.findings.append(finding)


class SourceCodeAnalyzer:
    """
    Main SAST Analyzer engine for walking project directories and running AST visitors.
    """

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scans a single Python file for security issues."""
        if not file_path.endswith(".py") or not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            source_lines = content.splitlines()
            tree = ast.parse(content, filename=file_path)
            visitor = ASTSecurityVisitor(file_path, source_lines)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError as e:
            logger.warning(f"[SAST] Syntax error parsing '{file_path}': {e}")
            return []
        except Exception as e:
            logger.error(f"[SAST] Error scanning file '{file_path}': {e}")
            return []

    def scan_directory(self, dir_path: str) -> Dict[str, Any]:
        """Recursively scans all Python files in a directory."""
        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0

        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    findings = self.scan_file(full_path)
                    if findings:
                        all_findings.extend(findings)
                    files_scanned += 1

        summary = {
            "directory": dir_path,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "critical_count": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium_count": sum(1 for f in all_findings if f["severity"] == "MEDIUM")
        }

        logger.info(f"[SAST] Scanned {files_scanned} files in '{dir_path}'. Found {len(all_findings)} security issues.")
        return summary
