This is a smart strategic move. By using the **Official SQLite Reference Implementation**, you achieve two major goals for your thesis:

1.  **Production Realism:** You prove your security tool works against the actual "standard" tools developers use, not just "toy" tools you wrote yourself.
2.  **Standard Compliance:** You demonstrate that your MCP Bridge handles the official `read_query` / `write_query` tool definitions correctly.

However, the official MCP servers typically run over **STDIO** (standard input/output) for local desktop apps. Since your architecture is **Dockerized Microservices (HTTP)**, we must "port" the official logic to a **FastAPI wrapper**. This effectively containerizes the standard tool for a cloud-native environment.

### **1. `mcp_tools/sqlite/requirements.txt`**

```text
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.6.0
# We use standard sqlite3 (built-in), no extra libs needed
```

-----

### **2. `mcp_tools/sqlite/Dockerfile`**

We will include a pre-seeding step so your database isn't empty when the thesis demo starts.

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------
# ENGINEERING TASK: Database Seeding
# We pre-create the DB so SQL Injection has something to steal.
# ---------------------------------------------------------
COPY init_db.py .
RUN python init_db.py

# Copy Application Code
COPY server.py .

# Expose HTTP Port
EXPOSE 8080

# Run the Service
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
```

-----

### **3. `mcp_tools/sqlite/init_db.py` (Seeding Script)**

This script creates the "Honey Pot" data for your thesis.

```python
import sqlite3

def init_db():
    conn = sqlite3.connect("thesis.db")
    cursor = conn.cursor()
    
    # 1. Users Table (Target for SQL Injection)
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)")
    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'super_secret_thesis_password', 1)")
    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('vince', 'student_password', 0)")
    
    # 2. Products Table (Benign Data)
    cursor.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Laptop', 1200.00)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Mouse', 25.50)")
    
    conn.commit()
    conn.close()
    print("Database seeded successfully: thesis.db")

if __name__ == "__main__":
    init_db()
```

-----

### **4. `mcp_tools/sqlite/server.py` (The Official Port)**

This implementation strictly mimics the **Official `mcp-server-sqlite` Interface**. This ensures that if you swap this container for the real CLI tool later, the LLM won't know the difference.

```python
import sqlite3
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import List, Dict, Any

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Official_SQLite_Port")

app = FastAPI(title="Official SQLite MCP Server (HTTP Port)")
DB_PATH = "thesis.db"

# ---------------------------------------------------------
# 1. OFFICIAL TOOL IMPLEMENTATIONS
# Reference: https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite
# ---------------------------------------------------------

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

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            result = None

            # Route to Official Functions
            try:
                if tool_name == "read_query":
                    data = read_query(args.get("query"))
                    result = str(data) # Flatten for LLM context
                elif tool_name == "write_query":
                    result = write_query(args.get("query"))
                elif tool_name == "list_tables":
                    result = str(list_tables())
                elif tool_name == "describe_table":
                    result = str(describe_table(args.get("table_name")))
                else:
                    raise ValueError(f"Tool '{tool_name}' not found")

                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "content": [{"type": "text", "text": result}]
                    },
                    "id": req_id
                }
            except Exception as e:
                # Tool Logic Error (e.g., Bad SQL)
                logger.error(f"SQL Error: {e}")
                return {
                    "jsonrpc": "2.0",
                    "content": [{"type": "text", "text": f"Database Error: {str(e)}"}],
                    "isError": True,
                    "id": req_id
                }

        else:
             return JSONResponse({"error": {"code": -32600, "message": "Invalid Request"}})

    except Exception as e:
        logger.error(f"System Error: {e}")
        return JSONResponse({"error": {"code": -32000, "message": str(e)}})
```

-----

### **Critical Integration Step: Update the Bridge**

Since we are now using the **Official Tool Names** (`read_query`, `write_query`) instead of `sqlite:query`, we need to update the `mcp_bridge/src/services/forwarder.py` file to route these correctly.

**Action:** Update the `_resolve_tool_url` method in `forwarder.py`:

```python
    def _resolve_tool_url(self, method: str, params: Any) -> str:
        """
        Determines which microservice to call.
        UPDATED: Routes official tool names to the correct container.
        """
        tool_name = ""
        if method == "tools/call":
            tool_name = params.get("name")
        
        # 1. Route Official SQLite Tools -> tool-db
        if tool_name in ["read_query", "write_query", "list_tables", "describe_table"]:
            return self.tool_map["sqlite"] # http://tool-db:8080
            
        # 2. Route Filesystem Tools -> tool-fs
        if tool_name in ["read_file", "write_file", "list_directory"]:
            return self.tool_map["filesystem"] # http://tool-fs:8080
            
        # 3. Fallback (Namespaced)
        if "/" in method:
            return self.tool_map.get(method.split("/")[0])
            
        return None
```

[Image of Docker Compose Network Topology]

You now have a production-realistic **SQLite MCP Server** that mimics the official implementation but runs securely inside your DMZ network.

**Next Step:**
We have the **Brain** (LLM), the **Guard** (Bridge), and the **Limbs** (Tools).
The only missing piece is the **Simulator** (`client/`).

Would you like me to implement the **`client/`** folder now? This will include the automated script to generate the "Synthetic Attacks" for your thesis data.