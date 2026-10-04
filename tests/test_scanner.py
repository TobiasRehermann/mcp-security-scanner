import pytest
import json
from mcp_scanner.models import Severity, Finding, PolicyConfig
from mcp_scanner.mcp_scanner import scan_mcp_manifest
from mcp_scanner.ast_scanner import scan_python_file
from mcp_scanner.rule_engine import load_policy

@pytest.fixture
def sample_manifest(tmp_path):
    def _create_manifest(tools_data):
        manifest_path = tmp_path / "test_mcp.json"
        manifest_path.write_text(json.dumps({"tools": tools_data}))
        return str(manifest_path)
    return _create_manifest

def test_mcp_sec_001_missing_approval(sample_manifest):
    data = [{
        "name": "delete_database",
        "requires_approval": False
    }]
    filePath = sample_manifest(data)
    findings = scan_mcp_manifest(filePath)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-001"
    assert findings[0].severity == Severity.HIGH

def test_mcp_sec_002_unbounded_string(sample_manifest):
    data = [{
        "name": "read_file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}  # No maxLength, pattern, or enum
            }
        }
    }]
    filePath = sample_manifest(data)
    findings = scan_mcp_manifest(filePath)
    
    assert any(f.rule_id == "MCP-SEC-002" for f in findings)

def test_mcp_sec_003_scope_mismatch(sample_manifest):
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
    findings = scan_mcp_manifest(filePath)
    
    assert any(f.rule_id == "MCP-SEC-003" for f in findings)