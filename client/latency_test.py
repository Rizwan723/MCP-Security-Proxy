import time
import requests
import os
import json

# ------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------
# By default, we use the Bridge URL defined in your Docker Compose.
# To test raw LLM inference speed (bypassing bridge overhead), 
# change this to: "http://mcp-llm:8080/v1"
BASE_URL = os.getenv("BRIDGE_URL", "http://mcp-bridge:8000/v1") 

# A prompt long enough to generate significant tokens for measurement
PROMPT = "Write a Python function to calculate the Fibonacci sequence recursively."

def benchmark_inference(run_name):
    print(f"\n--- Starting Run: {run_name} ---")
    print(f"Target URL: {BASE_URL}/chat/completions")
    
    payload = {
        "messages": [
            {"role": "system", "content": "You are a helpful coding assistant."},
            {"role": "user", "content": PROMPT}
        ],
        "temperature": 0.1, # Low temp for consistent results
        "max_tokens": 200,  # Cap generation to keep test quick
        "stream": False     # False for simple total-time measurement
    }

    try:
        # 1. Start Clock
        start_time = time.perf_counter()
        
        # 2. Fire Request
        response = requests.post(
            f"{BASE_URL}/chat/completions", 
            json=payload, 
            timeout=60
        )
        
        # 3. Stop Clock
        end_time = time.perf_counter()
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return

        data = response.json()
        
        # 4. Analyze Metrics
        total_time = end_time - start_time
        
        # Usage metadata usually provided by OpenAI-compatible APIs (like llama-cpp-python)
        usage = data.get('usage', {})
        completion_tokens = usage.get('completion_tokens', 0)
        prompt_tokens = usage.get('prompt_tokens', 0)
        
        if completion_tokens > 0:
            tps = completion_tokens / total_time
        else:
            tps = 0

        # 5. Scientific Output
        print(f"Total Time:       {total_time:.4f} s")
        print(f"Tokens Generated: {completion_tokens}")
        print(f"Throughput:       {tps:.2f} tokens/sec")
        
        # Heuristic for GPU Verification
        if tps > 20:
            print(">> VERDICT: HIGH SPEED (Likely GPU Accelerated) 🚀")
        elif tps > 5:
            print(">> VERDICT: MODERATE SPEED (Possible partial offload or fast CPU)")
        else:
            print(">> VERDICT: LOW SPEED (Likely CPU only) 🐢")

    except Exception as e:
        print(f"Connection failed: {e}")
        print("Ensure the network alias 'mcp-bridge' (or 'mcp-llm') is resolvable.")

def benchmark_jsonrpc(run_name):
    print(f"\n--- Starting JSON-RPC Run: {run_name} ---")
    rpc_url = BASE_URL.replace("/v1", "/jsonrpc")
    print(f"Target URL: {rpc_url}")
    
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "user_docs/notes.txt"}
        },
        "id": 1
    }
    
    latencies = []
    for i in range(10):
        try:
            start = time.perf_counter()
            resp = requests.post(rpc_url, json=payload, timeout=5)
            end = time.perf_counter()
            if resp.status_code == 200:
                latencies.append((end - start) * 1000)
            else:
                print(f"Error {resp.status_code}")
        except Exception as e:
            print(f"Error: {e}")
            
    if latencies:
        avg_lat = sum(latencies) / len(latencies)
        print(f"Average Latency (10 runs): {avg_lat:.2f} ms")
        print(f"Min: {min(latencies):.2f} ms | Max: {max(latencies):.2f} ms")

if __name__ == "__main__":
    print(f"Benchmarking Llama-2-7b via {BASE_URL}...")
    
    # Run 1: Cold Start (Model loading into VRAM, allocating buffers)
    benchmark_inference("WARMUP RUN (Cold Cache)")
    
    # Run 2: Hot Run (Actual inference speed)
    benchmark_inference("TEST RUN (Warm Cache)")

    # Run 3: Bridge Overhead
    benchmark_jsonrpc("BRIDGE OVERHEAD (JSON-RPC)")

    # JSON-RPC Benchmarking
    benchmark_jsonrpc("JSON-RPC BENCHMARK")