import sys
import json
import httpx
import logging

# This script runs on your LOCAL machine and bridges Stdio <-> Docker HTTP
BRIDGE_URL = "http://localhost:8000/jsonrpc"

logging.basicConfig(filename='adapter.log', level=logging.INFO)

def main():
    # Read from Stdin (from Claude Desktop)
    for line in sys.stdin:
        if not line.strip():
            continue
        
        try:
            request = json.loads(line)
            logging.info(f"Sent: {request.get('method')}")

            # Forward to Docker Bridge
            response = httpx.post(BRIDGE_URL, json=request, timeout=60.0)
            response.raise_for_status()
            
            # Write response to Stdout (to Claude Desktop)
            print(json.dumps(response.json()))
            sys.stdout.flush()
            
        except Exception as e:
            logging.error(f"Error: {e}")

if __name__ == "__main__":
    main()