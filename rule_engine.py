from pathlib import Path
import yaml
from mcp_scanner.models import PolicyConfig


def load_policy(policy_path: str = "rules.yaml") -> PolicyConfig:
    path = Path(policy_path)
    if not path.exists():
        # Fallback to defaults if rules.yaml is missing
        return PolicyConfig(
            dangerous_verbs=["delete", "execute", "drop", "write", "update", "remove"],
            read_only_prefixes=["get_", "read_", "fetch_", "list_", "search_"],
            destructive_keywords=["delete", "drop", "truncate", "overwrite"],
            ingestion_keywords=["fetch", "scrape", "web_search", "read"],
            execution_keywords=["execute", "sql_query", "run_script", "write"],
            critical_sinks=["eval", "exec"],
            high_risk_sinks=["os.system", "subprocess.Popen"]
        )

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    manifest_cfg = data.get("manifest_rules", {})
    toxic_cfg = manifest_cfg.get("toxic_combinations", {})
    ast_cfg = data.get("ast_rules", {})

    return PolicyConfig(
        dangerous_verbs=manifest_cfg.get("dangerous_verbs", []),
        read_only_prefixes=manifest_cfg.get("read_only_prefixes", []),
        destructive_keywords=manifest_cfg.get("destructive_keywords", []),
        ingestion_keywords=toxic_cfg.get("ingestion_keywords", []),
        execution_keywords=toxic_cfg.get("execution_keywords", []),
        critical_sinks=ast_cfg.get("critical_sinks", []),
        high_risk_sinks=ast_cfg.get("high_risk_sinks", [])
    )