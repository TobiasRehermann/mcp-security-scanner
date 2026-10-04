import json
import sys
from typing import List, Dict, Any
from mcp_scanner.models import Severity, Finding, PolicyConfig  


def _check_rule_001(element: Dict[str, Any], policy: PolicyConfig) -> List[Finding]:
    tool_name = element.get("name", "").lower()
    requires_approval = element.get("requires_approval", False)
    is_dangerous = any(verb in tool_name for verb in policy.dangerous_verbs)

    if is_dangerous and not requires_approval:
        return [Finding(
            rule_id="MCP-SEC-001",
            severity=Severity.HIGH,
            message=f"Tool '{element.get('name')}' contains high-risk actions but lacks 'requires_approval: true'.",
            tool_name=element.get("name", "UNKNOWN")
        )]
    return []


def _check_rule_002(element: Dict[str, Any]) -> List[Finding]:
    findings = []
    parameters = element.get("parameters", {})
    properties = parameters.get("properties", {}) if isinstance(parameters, dict) else {}

    for param_name, param_info in properties.items():
        if isinstance(param_info, dict) and param_info.get("type", "").lower() == "string":
            has_max_length = "maxLength" in param_info
            has_pattern = "pattern" in param_info
            has_enum = "enum" in param_info

            if not (has_max_length or has_pattern or has_enum):
                findings.append(Finding(
                    rule_id="MCP-SEC-002",
                    severity=Severity.MEDIUM,
                    message=f"Parameter '{param_name}' in tool '{element.get('name')}' is an unbounded string.",
                    tool_name=element.get("name", "UNKNOWN")
                ))
    return findings


def _check_rule_003(element: Dict[str, Any], policy: PolicyConfig) -> List[Finding]:
    findings = []
    tool_name = element.get("name", "").lower()
    is_read_only_named = any(tool_name.startswith(prefix) for prefix in policy.read_only_prefixes)

    if is_read_only_named:
        parameters = element.get("parameters", {})
        properties = parameters.get("properties", {}) if isinstance(parameters, dict) else {}
        for param_name in properties.keys():
            if any(keyword in param_name.lower() for keyword in policy.destructive_keywords):
                findings.append(Finding(
                    rule_id="MCP-SEC-003",
                    severity=Severity.HIGH,
                    message=f"Tool '{element.get('name')}' is named read-only but contains destructive parameter '{param_name}'.",
                    tool_name=element.get("name", "UNKNOWN")
                ))
    return findings


def scan_mcp_manifest(file_path: str, policy: PolicyConfig) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        tools = data.get("tools", []) if isinstance(data, dict) else data
        ingestion_tools, execution_tools = [], []

        for element in tools:
            name = element.get("name", "")
            tool_name_lower = name.lower()

            # Track for Toxic Combinations
            if any(k in tool_name_lower for k in policy.ingestion_keywords):
                ingestion_tools.append(name)
            if any(k in tool_name_lower for k in policy.execution_keywords):
                execution_tools.append(name)

            # Rule Evaluations
            findings.extend(_check_rule_001(element, policy))
            findings.extend(_check_rule_002(element))
            findings.extend(_check_rule_003(element, policy))

        # Toxic Combination Check (MCP-SEC-004)
        if ingestion_tools and execution_tools:
            findings.append(Finding(
                rule_id="MCP-SEC-004",
                severity=Severity.CRITICAL,
                message=f"Toxic Combination: Ingestion tools {ingestion_tools} alongside Execution tools {execution_tools}.",
                tool_name="MANIFEST_LEVEL"
            ))

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading manifest '{file_path}': {e}", file=sys.stderr)

    return findings