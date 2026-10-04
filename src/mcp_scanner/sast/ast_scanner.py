import ast
import sys
from typing import List
from mcp_scanner.models import Severity, Finding, PolicyConfig


class AdvancedMCPToolVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, policy: PolicyConfig):
        self.file_path = file_path
        self.policy = policy
        self.findings: List[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._is_mcp_tool(node):
            self._check_type_annotations(node)
            self._check_dangerous_sinks(node)
        self.generic_visit(node)

    def _is_mcp_tool(self, node: ast.FunctionDef) -> bool:
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "mcp.tool":
                return True
            if isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
                return True
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Attribute) and func.attr == "tool":
                    return True
        return False

    def _check_type_annotations(self, node: ast.FunctionDef) -> None:
        for arg in node.args.args:
            if arg.arg != "self" and arg.annotation is None:
                self.findings.append(Finding(
                    rule_id="MCP-SEC-102",
                    severity=Severity.LOW,
                    message=f"Parameter '{arg.arg}' in tool '{node.name}' lacks type annotation.",
                    tool_name=node.name
                ))

    def _check_dangerous_sinks(self, node: ast.FunctionDef) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_call_name(child.func)
                self._evaluate_sink_call(func_name, child, node.name)

    def _evaluate_sink_call(self, func_name: str, call_node: ast.Call, tool_name: str) -> None:
        if func_name in self.policy.critical_sinks:
            self.findings.append(Finding(
                rule_id="MCP-SEC-101",
                severity=Severity.CRITICAL,
                message=f"Critical sink '{func_name}()' detected in tool '{tool_name}'.",
                tool_name=tool_name
            ))
        elif func_name in self.policy.high_risk_sinks:
            self.findings.append(Finding(
                rule_id="MCP-SEC-101",
                severity=Severity.HIGH,
                message=f"High-risk sink '{func_name}()' detected in tool '{tool_name}'.",
                tool_name=tool_name
            ))

        if func_name.startswith("subprocess."):
            self._check_subprocess_security(call_node, tool_name)

    def _check_subprocess_security(self, call_node: ast.Call, tool_name:str) -> None:
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call_node.keywords
        )

        uses_dynamic_formatting = False
        if call_node.args:
            first_arg = call_node.args[0]
            is_f_string = isinstance(first_arg, ast.JoinedStr)
            is_mod_format = isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod)
            is_dot_format = (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and first_arg.func.attr == "format"
            )
            uses_dynamic_formatting = is_f_string or is_mod_format or is_dot_format

        if shell_true and uses_dynamic_formatting:
            self.findings.append(Finding(
                rule_id="MCP-SEC-103",
                severity=Severity.CRITICAL,
                message=f"Command Injection Risk in tool '{tool_name}': Subprocess called with 'shell=True' and dynamic formatting.",
                tool_name=tool_name
            ))
        elif shell_true:
            self.findings.append(Finding(
                rule_id="MCP-SEC-103",
                severity=Severity.HIGH,
                message=f"Unsafe Subprocess invocation in tool '{tool_name}': 'shell=True' is enabled.",
                tool_name=tool_name
            ))

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value_name = self._get_call_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""


def scan_python_file(file_path: str, policy: PolicyConfig) -> List[Finding]:
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source_code = file.read()

        tree = ast.parse(source_code, filename=file_path)
        visitor = AdvancedMCPToolVisitor(file_path, policy)
        visitor.visit(tree)
        return visitor.findings

    except (SyntaxError, FileNotFoundError) as e:
        print(f"Error scanning Python file '{file_path}': {e}", file=sys.stderr)
        return []