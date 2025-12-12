import json
import sqlite3
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings
from typing import List, Dict, Any

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
class Settings(BaseSettings):
    """
    Configuration for SQLite Tool.
    All parameters can be overridden via environment variables with SQL_ prefix.
    """
    db_path: str = "thesis.db"
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_prefix = "SQL_"

settings = Settings()

# Setup Logging
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("Official_SQLite_Port")

app = FastAPI(title="Official SQLite MCP Server (HTTP Port)")
DB_PATH = settings.db_path

# ---------------------------------------------------------
# 1. OFFICIAL TOOL IMPLEMENTATIONS
# Reference: https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite
# ---------------------------------------------------------

TOOLS_METADATA = [
    {
        "name": "read_query",
        "description": "Execute a SELECT query on the database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL SELECT query"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "write_query",
        "description": "Execute an INSERT, UPDATE, or DELETE query",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL modification query"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "list_tables",
        "description": "List all tables in the database",
        "inputSchema": {
            "type": "object",
            "properties": {},
        }
    },
    {
        "name": "describe_table",
        "description": "Get schema information for a table",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table_name": {"type": "string", "description": "Name of the table"}
            },
            "required": ["table_name"]
        }
    }
]

def get_db():
    """Helper to get connection. Not async for simplicity in SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # Return dict-like rows
    return conn

def read_query(query: str) -> List[Dict[str, Any]]:
    """Execute a SELECT query (Read-Only)."""
    if not query.strip().upper().startswith("SELECT"):
        raise ValueError("Only SELECT queries are allowed in read_query")
        
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        return [dict(row) for row in cursor.fetchall()]

def write_query(query: str) -> str:
    """Execute INSERT, UPDATE, DELETE queries."""
    if query.strip().upper().startswith("SELECT"):
        raise ValueError("Use read_query for SELECT statements")
        
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        return f"Affected rows: {cursor.rowcount}"

def list_tables() -> List[str]:
    """List all tables in the database."""
    query = "SELECT name FROM sqlite_master WHERE type='table'"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        return [row["name"] for row in cursor.fetchall()]

def describe_table(table_name: str) -> List[Dict[str, Any]]:
    """Get schema information for a specific table."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Secure way to check schema in SQLite
        cursor.execute(f"PRAGMA table_info({table_name})") 
        return [dict(row) for row in cursor.fetchall()]

# ---------------------------------------------------------
# 2. JSON-RPC ROUTER
# ---------------------------------------------------------
@app.post("/")
async def handle_rpc(request: Request):
    try:
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        req_id = body.get("id")

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

            # Route to Official Functions
            try:
                if tool_name == "read_query":
                    data = read_query(args.get("query"))
                    result = json.dumps(data)
                elif tool_name == "write_query":
                    result = write_query(args.get("query"))
                elif tool_name == "list_tables":
                    result = json.dumps(list_tables())
                elif tool_name == "describe_table":
                    result = json.dumps(describe_table(args.get("table_name")))
                else:
                    raise ValueError(f"Tool '{tool_name}' not found")

                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [{"type": "text", "text": result}],
                        "isError": False
                    },
                    "id": req_id
                }
            except Exception as e:
                # Tool Logic Error (e.g., Bad SQL) - return with isError per MCP spec
                logger.error(f"SQL Error: {e}")
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [{"type": "text", "text": f"Database Error: {str(e)}"}],
                        "isError": True
                    },
                    "id": req_id
                }

        else:
             return JSONResponse({"error": {"code": -32600, "message": "Invalid Request"}})

    except Exception as e:
        logger.error(f"System Error: {e}")
        return JSONResponse({"error": {"code": -32000, "message": str(e)}})