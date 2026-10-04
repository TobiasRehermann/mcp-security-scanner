# test_target.py
import os
import subprocess

# Simuliertes MCP SDK Decorator Mockup
class mcp:
    @staticmethod
    def tool(func):
        return func

# --- Unsicheres Tool ---
@mcp.tool
def execute_system_command(command, timeout=10):  # Fehlt Typ-Annotation!
    os.system(command)  # Gefährlicher Sink (Command Injection)

# --- Sicheres Tool ---
@mcp.tool()
def safe_calculator(a: int, b: int) -> int:
    return a + b