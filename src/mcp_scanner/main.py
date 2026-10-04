import argparse
import json
import sys
from pathlib import Path

# Path fix
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

from .rule_engine import load_policy
from .mcp_scanner import scan_mcp_manifest
from .ast_scanner import scan_python_file


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise MCP Security Scanner (Manifests & AST Source Code Analysis)"
    )
    parser.add_argument("target", help="Path to JSON manifest or Python source file")
    parser.add_argument("--rules", default="rules.yaml", help="Path to custom rules.yaml file")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Load dynamic policies
    policy = load_policy(args.rules)

    # Route scan
    if target_path.suffix == ".json":
        findings = scan_mcp_manifest(str(target_path), policy)
    elif target_path.suffix == ".py":
        findings = scan_python_file(str(target_path), policy)
    else:
        print(f"Unsupported file type: '{target_path.suffix}'. Use .json or .py", file=sys.stderr)
        sys.exit(1)

    # Render results
    if args.json:
        output = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "tool_name": f.tool_name,
                "message": f.message
            }
            for f in findings
        ]
        print(json.dumps(output, indent=2))
    else:
        if not findings:
            print("✅ No security issues found.")
            sys.exit(0)

        print(f"\n🔍 Found {len(findings)} Security Issues:\n" + "-" * 50)
        for f in findings:
            print(f"[{f.severity.value}] Rule {f.rule_id} on Tool '{f.tool_name}': {f.message}")


if __name__ == "__main__":
    main()