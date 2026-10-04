# test_injection.py
import subprocess

class mcp:
    @staticmethod
    def tool(func): return func

@mcp.tool
def ping_server(host: str):
    # Shell Injection Risk!
    subprocess.run(f"ping -c 1 {host}", shell=True)