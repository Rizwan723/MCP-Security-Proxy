import os
import json
import logging
import aiofiles
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Any

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
class Settings(BaseSettings):
    """
    Configuration for Filesystem Tool.
    All parameters can be overridden via environment variables with FS_ prefix.
    """
    # Set to False to intentionally allow vulnerabilities for testing the Bridge
    safe_mode: bool = False
    root_dir: str = "/data"
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_prefix = "FS_"

settings = Settings()

# Setup Logging
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("Tool_Filesystem")

app = FastAPI(title="Filesystem Tool (MCP)")

# Legacy compatibility
SAFE_MODE = settings.safe_mode
ROOT_DIR = os.path.abspath(settings.root_dir)

# ---------------------------------------------------------
# 1. HELPER FUNCTIONS
# ---------------------------------------------------------
def resolve_path(user_path: str) -> str:
    """
    Resolves the absolute path.
    In SAFE_MODE, it blocks traversal.
    In VULNERABLE mode, it allows access to /etc/thesis_secret.
    """
    # Join root with user input
    target_path = os.path.abspath(os.path.join(ROOT_DIR, user_path.lstrip("/")))
    
    if SAFE_MODE:
        # Security Check: Ensure target is still inside ROOT_DIR
        if not os.path.commonpath([ROOT_DIR, target_path]) == ROOT_DIR:
            raise PermissionError(f"Access Denied: Path {user_path} is outside sandbox.")
            
    return target_path

# ---------------------------------------------------------
# 2. TOOL IMPLEMENTATIONS
# ---------------------------------------------------------
TOOLS_METADATA = [
    {
        "name": "list_directory",
        "description": "List contents of a directory",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to list"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "read_file",
        "description": "Read contents of a file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to read"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "Write content to a file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to write to"},
                "content": {"type": "string", "description": "Content to write"}
            },
            "required": ["path", "content"]
        }
    }
]

async def list_directory(path: str = ".") -> List[str]:
    target = resolve_path(path)
    if not os.path.exists(target):
        raise FileNotFoundError("Directory not found")
    if not os.path.isdir(target):
        raise NotADirectoryError("Path is not a directory")
    
    return os.listdir(target)

async def read_file(path: str) -> str:
    target = resolve_path(path)
    if not os.path.exists(target):
        raise FileNotFoundError("File not found")
    
    async with aiofiles.open(target, mode='r') as f:
        content = await f.read()
    return content

async def write_file(path: str, content: str) -> str:
    target = resolve_path(path)
    # Ensure directory exists
    os.makedirs(os.path.dirname(target), exist_ok=True)
    
    async with aiofiles.open(target, mode='w') as f:
        await f.write(content)
    return f"Successfully wrote {len(content)} bytes to {path}"

# ---------------------------------------------------------
# 3. JSON-RPC HANDLER
# ---------------------------------------------------------
@app.post("/")
async def handle_rpc(request: Request):
    body = None
    try:
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        req_id = body.get("id")
        
        # MCP "tools/call" unpacking
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "result": {
                    "tools": TOOLS_METADATA
                },
                "id": req_id
            }

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            
            result = None
            
            if tool_name == "list_directory":
                result = await list_directory(args.get("path", "."))
            elif tool_name == "read_file":
                result = await read_file(args.get("path"))
            elif tool_name == "write_file":
                result = await write_file(args.get("path"), args.get("content"))
            else:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
                    "id": req_id
                })
                
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result)}],
                    "isError": False
                },
                "id": req_id
            }

        # Handle direct namespace calls (legacy/simple mode)
        # e.g. method="filesystem/read_file"
        elif "/" in method:
            action = method.split("/")[-1]
            args = params
            
            result = None
            if action == "read_file":
                result = await read_file(args.get("path"))
            elif action == "list_directory":
                result = await list_directory(args.get("path", "."))
            # ... add others
            
            return {"jsonrpc": "2.0", "result": result, "id": req_id}

        else:
             return JSONResponse({"error": {"code": -32600, "message": "Invalid Request"}})

    except Exception as e:
        logger.error(f"Error: {e}")
        # Return tool execution error with isError flag per MCP spec
        return JSONResponse({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            },
            "id": body.get("id") if body else None
        })