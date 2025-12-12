"""
MCP Security Gateway Test Client

Tests the 4-class detection system:
- BENIGN: Safe requests (should be ALLOWED)
- SENSITIVE: Policy-restricted (should be BLOCKED)
- MALICIOUS: Known attacks (should be BLOCKED)
- ANOMALOUS: Zero-day suspects (should be BLOCKED)
"""
import httpx
import json
import os
import sys

# Configuration
BRIDGE_URL = os.getenv("BRIDGE_URL", "http://mcp-bridge:8000/jsonrpc")

# ANSI Colors matching 4-class system
GREEN = "\033[92m"    # Benign
YELLOW = "\033[93m"   # Sensitive
RED = "\033[91m"      # Malicious
PURPLE = "\033[95m"   # Anomalous
BLUE = "\033[94m"     # Info
RESET = "\033[0m"

def send_jsonrpc(method, params, id=1):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": id
    }
    
    print(f"{BLUE}Sending Request:{RESET} {method} {json.dumps(params)}")
    
    try:
        response = httpx.post(BRIDGE_URL, json=payload)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            print(f"{RED}Response Error:{RESET} {json.dumps(data['error'], indent=2)}")
        else:
            print(f"{GREEN}Response Result:{RESET} {json.dumps(data['result'], indent=2)}")
            
    except Exception as e:
        print(f"{RED}Connection Error:{RESET} {e}")
    print("-" * 40)

def main():
    print(f"Testing MCP Bridge at {BRIDGE_URL}")
    print("="*60)
    print("4-Class Detection System Test Suite")
    print("="*60 + "\n")

    # =================================================================
    # BENIGN TESTS (Should be ALLOWED - Green)
    # =================================================================
    print(f"{GREEN}=== BENIGN TESTS (Expected: ALLOWED) ==={RESET}\n")

    print("Test 1: Benign File Read")
    send_jsonrpc("tools/call", {
        "name": "read_file",
        "arguments": {"path": "user_docs/notes.txt"}
    }, id=1)

    print("Test 2: Benign SQL Query")
    send_jsonrpc("tools/call", {
        "name": "read_query",
        "arguments": {"query": "SELECT * FROM products WHERE price > 50"}
    }, id=2)

    print("Test 3: Benign Time Query")
    send_jsonrpc("tools/call", {
        "name": "get_current_time",
        "arguments": {"timezone": "America/New_York"}
    }, id=3)

    # =================================================================
    # SENSITIVE TESTS (Should be BLOCKED - Yellow/Orange)
    # =================================================================
    print(f"\n{YELLOW}=== SENSITIVE TESTS (Expected: BLOCKED_SENSITIVE) ==={RESET}\n")

    print("Test 4: Sensitive File - Environment Variables")
    send_jsonrpc("tools/call", {
        "name": "read_file",
        "arguments": {"path": ".env"}
    }, id=4)

    print("Test 5: Sensitive SQL - User Credentials")
    send_jsonrpc("tools/call", {
        "name": "read_query",
        "arguments": {"query": "SELECT username, password_hash FROM users"}
    }, id=5)

    print("Test 6: Sensitive Directory - Secrets")
    send_jsonrpc("tools/call", {
        "name": "list_directory",
        "arguments": {"path": "./secrets"}
    }, id=6)

    # =================================================================
    # MALICIOUS TESTS (Should be BLOCKED - Red)
    # =================================================================
    print(f"\n{RED}=== MALICIOUS TESTS (Expected: BLOCKED_MALICIOUS) ==={RESET}\n")

    print("Test 7: Path Traversal Attack")
    send_jsonrpc("tools/call", {
        "name": "read_file",
        "arguments": {"path": "../../../etc/passwd"}
    }, id=7)

    print("Test 8: SQL Injection - Stacked Query")
    send_jsonrpc("tools/call", {
        "name": "read_query",
        "arguments": {"query": "SELECT * FROM users; DROP TABLE products;"}
    }, id=8)

    print("Test 9: Command Injection")
    send_jsonrpc("tools/call", {
        "name": "read_file",
        "arguments": {"path": "file.txt; rm -rf /"}
    }, id=9)

    print("Test 10: SSRF - Cloud Metadata")
    send_jsonrpc("tools/call", {
        "name": "fetch_url",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}
    }, id=10)

    # =================================================================
    # ANOMALOUS TESTS (Should be BLOCKED - Purple)
    # Zero-day style attacks not in training data
    # =================================================================
    print(f"\n{PURPLE}=== ANOMALOUS TESTS (Expected: BLOCKED_ANOMALOUS) ==={RESET}\n")

    print("Test 11: Novel Encoding - Unicode Traversal")
    send_jsonrpc("tools/call", {
        "name": "read_file",
        "arguments": {"path": "\u002e\u002e/\u002e\u002e/secret"}
    }, id=11)

    print("Test 12: Novel SQL - Hex Encoding")
    send_jsonrpc("tools/call", {
        "name": "read_query",
        "arguments": {"query": "0x53454C454354202A2046524F4D207573657273"}
    }, id=12)

    print("Test 13: Novel SSRF - IPv6 Mapped IPv4")
    send_jsonrpc("tools/call", {
        "name": "fetch_url",
        "arguments": {"url": "http://[::ffff:127.0.0.1]/admin"}
    }, id=13)

    print("="*60)
    print("Test Suite Complete")
    print("="*60)

if __name__ == "__main__":
    main()
