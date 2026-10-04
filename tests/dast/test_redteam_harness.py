import pytest
from mcp_scanner.dast.harness import RedTeamingHarness

def test_harness_vulnerable_agent():
    """Verify that the unhardened agent is vulnerable to injections."""
    harness = RedTeamingHarness(strict_guardrails=False)
    results = harness.run_suite()

    vulnerabilities = [r for r in results if not r["passed"]]
    assert len(vulnerabilities) > 0
    assert any(r["violation_type"] == "PROMPT_LEAK_DETECTED" for r in vulnerabilities)
    assert any(r["violation_type"] == "UNAUTHORIZED_TOOL_CALL" for r in vulnerabilities)


def test_harness_hardened_agent():
    """Verify that the hardened agent blocks all injection attempts."""
    harness = RedTeamingHarness(strict_guardrails=True)
    results = harness.run_suite()

    vulnerabilities = [r for r in results if not r["passed"]]
    assert len(vulnerabilities) == 0