import argparse
import sys
from mcp_scanner.sast.rule_engine import load_policy
from mcp_scanner.sast.mcp_scanner import scan_mcp_manifest
from mcp_scanner.sast.ast_scanner import scan_python_file


def main():
    parser = argparse.ArgumentParser(description="MCP Security Framework CLI")
    parser.add_argument("--target", required=True, help="Path to manifest or Python file")
    parser.add_argument("--rules", default="rules.yaml", help="Path to rules YAML file")

    args = parser.parse_args()

    policy = load_policy(args.rules)

    if args.target.endswith(".json"):
        findings = scan_mcp_manifest(args.target, policy)
    elif args.target.endswith(".py"):
        findings = scan_python_file(args.target, policy)
    else:
        print(f"Unsupported target format: {args.target}")
        sys.exit(1)

    print(f"\n--- Scan Results for {args.target} ---")
    if not findings:
        print("✅ No vulnerabilities detected.")
    else:
        for finding in findings:
            print(f"❌ [{finding.severity.value}] {finding.rule_id}: {finding.description}")


if __name__ == "__main__":
    main()