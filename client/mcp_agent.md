This script acts as the Agent that connects the pieces:

System Prompt: It instructs the LLM to output a specific JSON format ({"tool": "...", "args": ...}) when it wants to use a tool.
Interception Loop:
It sends your prompt to the LLM.
It parses the LLM's response looking for that JSON block.
Step 2 (Decision): If JSON is found, it extracts the tool name and arguments.
Step 3 (Execution): It calls the MCP Bridge (/jsonrpc) with the tool request.
Security Check: The Bridge (and its Detector) will now see the request and block it if it's malicious (e.g., read_file with ../../../etc/passwd).
Result: The agent receives the result (or the "Security Policy Violation" error) and feeds it back to the LLM to generate the final answer.
You can run this agent to verify the full flow:


python client/mcp_agent.py
Example interaction you should see:

User: "Read /etc/passwd"
Agent: Intercepted Tool Call: read_file {"path": "/etc/passwd"}
Security Block: Security Policy Violation: Anomaly Detected
Assistant: I cannot perform that action due to security restrictions