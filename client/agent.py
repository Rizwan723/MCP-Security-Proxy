import os
import json
import re
import httpx
import argparse
import sys
from openai import OpenAI
from openai.types.chat import ChatCompletionMessageParam

# ------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------
# 1. The Bridge is ONLY used for Tools (Security Gate)
BRIDGE_RPC_URL = os.getenv("BRIDGE_RPC_URL", "http://localhost:8000/jsonrpc")

# 2. LLM Endpoints
# 'custom' refers to your self-hosted model (Llama/Mistral)
# 'cloud' refers to the provider wrapper (Gemini/OpenAI)
URLS = {
    "custom": os.getenv("CUSTOM_LLM_URL", "http://localhost:8080/v1"),
    "cloud": os.getenv("LLM_CLOUD_URL", "http://localhost:8081/v1")
}

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

SYSTEM_PROMPT = """
You are a helpful assistant with access to external tools.
To use a tool, you MUST respond with a JSON object in the following format ONLY.
Do not provide any explanation or text before or after the JSON object.

{
  "tool": "tool_name",
  "args": { "argument_name": "value" }
}

Available Tools:
1. read_file(path: str)
2. list_directory(path: str)
3. write_file(path: str, content: str)
4. read_query(query: str)
5. get_current_time(timezone: str)
6. convert_time(source_timezone: str, time: str, target_timezone: str)

If you do not need to use a tool, just respond with normal text.
"""

def safe_print(content):
    try:
        print(content)
    except UnicodeEncodeError:
        print(content.encode('utf-8', errors='replace').decode('utf-8'))

def extract_json_tool_call(text):
    """Robust JSON extraction from LLM response"""
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text)
    text = text.strip()

    start = text.find('{')
    end = text.rfind('}')
    
    if start != -1 and end != -1:
        json_str = text[start:end+1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    return None

def execute_tool_via_bridge(tool_name, args):
    """
    Traffic Path: Client -> Bridge -> Tool
    The Bridge performs security analysis here.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args
        },
        "id": 1
    }
    
    safe_print(f"{YELLOW}[Agent] Calling Bridge: {tool_name} {json.dumps(args)}{RESET}")
    
    try:
        response = httpx.post(BRIDGE_RPC_URL, json=payload, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            err = data['error']
            if err.get('code') == -32000:
                safe_print(f"{RED}[Security Block] {err['message']}{RESET}")
                if 'data' in err and 'reason' in err['data']:
                     safe_print(f"{RED}Reason: {err['data']['reason']}{RESET}")
                return f"SECURITY_ERROR: {err['message']}"
            else:
                return f"TOOL_ERROR: {err['message']}"
        
        result = data['result']
        if isinstance(result, dict) and 'content' in result:
             text_content = [c['text'] for c in result['content'] if c['type'] == 'text']
             return "\n".join(text_content)
        
        return str(result)

    except Exception as e:
        return f"BRIDGE_CONNECTION_ERROR: {str(e)}"

def run_chat_loop(mode="custom"):
    base_url = URLS[mode]
    print(f"--- Starting Agent in [{mode.upper()}] mode ---")
    print(f"LLM URL:    {base_url}")
    print(f"Bridge URL: {BRIDGE_RPC_URL}")
    
    client = OpenAI(base_url=base_url, api_key="sk-placeholder")
    
    history: list[ChatCompletionMessageParam] = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    while True:
        try:
            user_input = input(f"\n{GREEN}User: {RESET}")
            if user_input.lower() in ['exit', 'quit']: 
                break
            
            history.append({"role": "user", "content": user_input})
            
            completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=history,
                temperature=0.1
            )
            
            response_text = completion.choices[0].message.content or ""
            tool_call = extract_json_tool_call(response_text)
            
            if tool_call and "tool" in tool_call:
                tool_name = tool_call["tool"]
                tool_args = tool_call.get("args", {})
                
                tool_result = execute_tool_via_bridge(tool_name, tool_args)
                safe_print(f"{BLUE}[Tool Output] {tool_result[:100]}...{RESET}")
                
                history.append({"role": "assistant", "content": response_text})
                history.append({"role": "user", "content": f"Tool Result: {tool_result}"})
                
                final_completion = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=history,
                    temperature=0.1
                )
                final_text = final_completion.choices[0].message.content
                safe_print(f"{BLUE}Assistant: {RESET}{final_text}")
                history.append({"role": "assistant", "content": final_text})
                
            else:
                safe_print(f"{BLUE}Assistant: {RESET}{response_text}")
                history.append({"role": "assistant", "content": response_text})

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Updated choices to match new naming
    parser.add_argument("--model", choices=["custom", "cloud"], default="custom", help="Choose LLM backend")
    args = parser.parse_args()
    
    run_chat_loop(args.model)