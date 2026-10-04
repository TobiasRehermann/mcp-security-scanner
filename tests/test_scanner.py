import json
import pytest
from mcp_scanner.models import Severity, Finding, PolicyConfig
from mcp_scanner.mcp_scanner import scan_mcp_manifest
from mcp_scanner.ast_scanner import scan_python_file


@pytest.fixture
def default_policy() -> PolicyConfig:
    """Erstellt eine Standard-PolicyConfig für die Unit-Tests."""
    return PolicyConfig(
        dangerous_verbs=["delete", "drop", "execute", "remove"],
        read_only_prefixes=["get_", "read_", "fetch_", "list_"],
        destructive_keywords=["delete", "drop", "purge"],
        ingestion_keywords=["fetch", "read", "get"],
        execution_keywords=["execute", "run", "eval"],
        critical_sinks=["eval", "exec"],
        high_risk_sinks=["subprocess.Popen", "os.system"]
    )


@pytest.fixture
def sample_manifest(tmp_path):
    """Erstellt eine temporäre JSON-Manifestdatei für Testzwecke."""
    def _create_manifest(tools_data):
        file_path = tmp_path / "test_mcp.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(tools_data, f)
        return str(file_path)
    return _create_manifest


def test_mcp_sec_001_missing_approval(sample_manifest, default_policy):
    data = [{
        "name": "delete_database",
        "requires_approval": False
    }]
    filePath = sample_manifest(data)
    findings = scan_mcp_manifest(filePath, default_policy)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-001"
    assert findings[0].severity == Severity.HIGH


def test_mcp_sec_002_unbounded_string(sample_manifest, default_policy):
    data = [{
        "name": "read_file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        }
    }]
    filePath = sample_manifest(data)
    findings = scan_mcp_manifest(filePath, default_policy)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-002"
    assert findings[0].severity == Severity.MEDIUM


def test_mcp_sec_003_scope_mismatch(sample_manifest, default_policy):
    data = [{
        "name": "get_user_logs",
        "parameters": {
            "type": "object",
            "properties": {
                "delete_after_read": {"type": "boolean"}
            }
        }
    }]
    filePath = sample_manifest(data)
    findings = scan_mcp_manifest(filePath, default_policy)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-003"
    assert findings[0].severity == Severity.HIGH

def test_ast_scanner_critical_sink(tmp_path, default_policy):
    code_file = tmp_path / "unsafe_code.py"
    code_file.write_text(
        "@mcp.tool()\ndef run_input(user_input: str):\n    eval(user_input)\n", 
        encoding="utf-8"
    )
    
    findings = scan_python_file(str(code_file), default_policy)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-101"
    assert findings[0].severity == Severity.CRITICAL


def test_ast_scanner_safe_code(tmp_path, default_policy):
    code_file = tmp_path / "safe_code.py"
    code_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    
    findings = scan_python_file(str(code_file), default_policy)
    
    assert len(findings) == 0