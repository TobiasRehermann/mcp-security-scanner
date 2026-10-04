# 🛡️ MCP Security Scanner

A deterministic, static analysis security tool designed to identify vulnerabilities and security anti-patterns in **Model Context Protocol (MCP)** tool definitions and Python agent integration code.

> **Zero LLM Overhead:** Built for CI/CD speed and deterministic results using Python Abstract Syntax Trees (AST) and strict JSON schema validation.

---

## 📐 Architecture & Scan Flow

```text
                  ┌──────────────────────────────┐
                  │ Target Input (.json or .py)  │
                  └──────────────┬───────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │       main.py (CLI Router)    │
                 └───────────────┬───────────────┘
                                 │
          ┌──────────────────────┴──────────────────────┐
          ▼                                             ▼
┌───────────────────────────┐                 ┌───────────────────────────┐
│     scanner.py (JSON)     │                 │   ast_scanner.py (AST)    │
├───────────────────────────┤                 ├───────────────────────────┤
│ • MCP-SEC-001 (Approval)  │                 │ • MCP-SEC-101 (Sinks)     │
│ • MCP-SEC-002 (Strings)   │                 │ • MCP-SEC-102 (Types)     │
│ • MCP-SEC-003 (Scope)     │                 │                           │
└─────────┬─────────────────┘                 └─────────┬─────────────────┘
          │                                             │
          └──────────────────────┬──────────────────────┘
                                 ▼
                     ┌────────────────────────┐
                     │ Structured Findings    │
                     │ (Console or JSON SARIF)│
                     └────────────────────────┘