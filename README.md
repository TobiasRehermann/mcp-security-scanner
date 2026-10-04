# MCP Security Framework

A dual-purpose **Enterprise Security Framework** engineered for the Model Context Protocol (MCP) ecosystem and LLM agent architectures. The framework combines static code and configuration auditing (**SAST**) with an automated dynamic injection and red-teaming engine (**DAST**).

Designed for integration into CI/CD pipelines, SecOps workflows, and enterprise compliance auditing frameworks.

---

## 🏛️ Enterprise Architecture

The framework enforces a strict separation of concerns through a modular `src/`-layout. It isolates static rule validation engines from dynamic agent evaluation, making it scalable for multi-tenant and enterprise agent environments.

```text
mcp_scanner/
├── pyproject.toml              # Package configuration, entry points, and Pytest settings
├── rules.yaml                  # Enterprise SAST security policies
├── requirements.txt            # Project dependencies
├── README.md                   # Enterprise technical documentation
│
├── src/
│   └── mcp_scanner/            # Core package namespace
│       ├── __init__.py
│       ├── main.py             # CLI Entry point with exit-code handling
│       ├── models.py           # Core domain models (Finding, Severity, PolicyConfig)
│       │
│       ├── sast/               # Static Application Security Testing (SAST)
│       │   ├── __init__.py
│       │   ├── ast_scanner.py  # Python AST security visitor
│       │   ├── mcp_scanner.py  # MCP manifest structural & security validator
│       │   └── rule_engine.py  # YAML-based policy parsing & rule matching
│       │
│       └── dast/               # Dynamic Application Security Testing (DAST)
│           ├── __init__.py
│           ├── agent.py        # Agent execution harness & guardrail interfaces
│           ├── evaluator.py    # Deterministic attack detection & evaluation engine
│           ├── harness.py      # Automated red-teaming orchestration runner
│           └── payloads.py     # Indirect prompt injection vulnerability database
│
├── tests/                      # Enterprise test suite
│   ├── sast/                   # Unit tests for SAST AST and manifest validators
│   └── dast/                   # Integration tests for DAST harness and evaluation
│
└── examples/                   # Reference architectures and scan targets
    ├── data.json               # Sample MCP server manifest
    ├── test_injection.py      # Sample vulnerable target script
    └── test_target.py         # Sample clean target script

🔍 Core Features
1. Static Application Security Testing (SAST)

Inspects MCP server manifests (.json) and Python source code (.py) prior to deployment for static risks:

    Environment Variable Exposure: Detects unconstrained wildcard patterns (env.*) in manifests.

    Dangerous System Calls: Flags high-risk execution primitives (subprocess, os.system, shutil.rmtree).

    Severity Classification: Categorizes findings into standard severity levels (LOW, MEDIUM, HIGH, CRITICAL).

2. Dynamic Application Security Testing (DAST)

Simulates targeted Indirect Prompt Injection attacks against agent execution contexts and evaluates outputs:

    System Prompt Leaking: Verifies resistance against secret disclosure or confidential keyword leaks.

    Tool Hijacking: Detects unauthorized execution of system tools triggered by untrusted context.

    Data Exfiltration: Identifies exfiltration attempts targeting external channels.

🛠️ Installation & Setup

    Clone the repository and navigate to the project directory:
    Bash

    cd mcp_scanner

    Activate your virtual environment and install the package in editable mode:
    Bash

    pip install -e .

This registers the mcp-security command-line utility in your active terminal session.
🚀 Usage
Static Security Analysis (SAST)

Scan manifests or source files using the CLI tool:
Bash

# Scan an MCP manifest file
mcp-security --target ./examples/data.json --rules rules.yaml

# Scan a Python source file
mcp-security --target ./src/mcp_scanner/sast/ast_scanner.py --rules rules.yaml

Dynamic Red-Teaming (DAST)

Execute the automated attack simulation suite against the target agent:
Bash

python -m mcp_scanner.dast.harness

Note: The harness runs against an un-guarded mock agent by default. Reported vulnerabilities validate that the evaluator correctly detects policy violations.
🧪 Testing

Run the full automated test suite covering both SAST and DAST modules:
Bash

# Run all tests
pytest

# Run tests with verbose output
pytest -v