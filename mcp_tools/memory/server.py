"""
Memory MCP Server - Knowledge Graph Persistent Memory

This server implements a knowledge graph-based memory system following the MCP specification.
Security testing scenarios:
- Entity injection attacks
- Relation manipulation/poisoning
- Data exfiltration via entity queries
- Privilege escalation through relation creation
- Stored XSS/injection in entity content
"""
import os
import json
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings
from pathlib import Path

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
class Settings(BaseSettings):
    """Configuration for Memory Tool."""
    log_level: str = "INFO"
    safe_mode: bool = False  # When False, allows dangerous operations for testing
    storage_path: str = "/data/memory.json"
    max_entities: int = 10000
    max_relations: int = 50000

    class Config:
        env_file = ".env"
        env_prefix = "MEMORY_"

settings = Settings()

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("Tool_Memory")

app = FastAPI(title="Memory Tool (MCP)")

# In-memory knowledge graph
knowledge_graph = {
    "entities": {},      # entity_name -> {type, content, metadata}
    "relations": [],     # [{source, target, relation_type, metadata}]
}

# Sensitive entity patterns (for SAFE_MODE)
SENSITIVE_PATTERNS = [
    r'password',
    r'secret',
    r'api[_-]?key',
    r'token',
    r'credential',
    r'private[_-]?key',
    r'auth',
    r'admin',
    r'root',
    r'system',
]

# ---------------------------------------------------------
# PERSISTENCE
# ---------------------------------------------------------
def load_graph():
    """Load knowledge graph from disk."""
    global knowledge_graph
    try:
        if os.path.exists(settings.storage_path):
            with open(settings.storage_path, 'r') as f:
                knowledge_graph = json.load(f)
                logger.info(f"Loaded {len(knowledge_graph['entities'])} entities")
    except Exception as e:
        logger.error(f"Failed to load graph: {e}")

def save_graph():
    """Save knowledge graph to disk."""
    try:
        os.makedirs(os.path.dirname(settings.storage_path), exist_ok=True)
        with open(settings.storage_path, 'w') as f:
            json.dump(knowledge_graph, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save graph: {e}")

# ---------------------------------------------------------
# TOOL IMPLEMENTATIONS
# ---------------------------------------------------------
TOOLS_METADATA = [
    {
        "name": "create_entity",
        "description": "Create a new entity in the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Unique name for the entity"
                },
                "entity_type": {
                    "type": "string",
                    "description": "Type of entity (e.g., person, concept, document)"
                },
                "content": {
                    "type": "string",
                    "description": "Content or description of the entity"
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional additional metadata"
                }
            },
            "required": ["name", "entity_type", "content"]
        }
    },
    {
        "name": "get_entity",
        "description": "Retrieve an entity from the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the entity to retrieve"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "search_entities",
        "description": "Search for entities by content or type",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string"
                },
                "entity_type": {
                    "type": "string",
                    "description": "Optional: filter by entity type"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 10)"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "create_relation",
        "description": "Create a relation between two entities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Source entity name"
                },
                "target": {
                    "type": "string",
                    "description": "Target entity name"
                },
                "relation_type": {
                    "type": "string",
                    "description": "Type of relation (e.g., knows, contains, references)"
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional additional metadata"
                }
            },
            "required": ["source", "target", "relation_type"]
        }
    },
    {
        "name": "get_relations",
        "description": "Get all relations for an entity",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_name": {
                    "type": "string",
                    "description": "Name of the entity"
                },
                "relation_type": {
                    "type": "string",
                    "description": "Optional: filter by relation type"
                }
            },
            "required": ["entity_name"]
        }
    },
    {
        "name": "delete_entity",
        "description": "Delete an entity and its relations from the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the entity to delete"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "list_entities",
        "description": "List all entities in the knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_type": {
                    "type": "string",
                    "description": "Optional: filter by entity type"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 100)"
                }
            }
        }
    }
]


def is_sensitive_entity(name: str, content: str = "") -> bool:
    """Check if entity name or content contains sensitive patterns."""
    combined = f"{name} {content}".lower()
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return True
    return False


async def create_entity(name: str, entity_type: str, content: str,
                        metadata: Optional[Dict] = None) -> Dict[str, Any]:
    """Create a new entity in the knowledge graph."""
    if settings.safe_mode and is_sensitive_entity(name, content):
        raise PermissionError(f"Cannot create entity with sensitive content: {name}")

    if len(knowledge_graph["entities"]) >= settings.max_entities:
        raise ValueError("Maximum entity limit reached")

    knowledge_graph["entities"][name] = {
        "type": entity_type,
        "content": content,
        "metadata": metadata or {},
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    save_graph()

    return {"success": True, "entity": name, "message": f"Entity '{name}' created"}


async def get_entity(name: str) -> Dict[str, Any]:
    """Retrieve an entity from the knowledge graph."""
    if name not in knowledge_graph["entities"]:
        raise KeyError(f"Entity '{name}' not found")

    entity = knowledge_graph["entities"][name]
    return {
        "name": name,
        **entity
    }


async def search_entities(query: str, entity_type: Optional[str] = None,
                         limit: int = 10) -> List[Dict[str, Any]]:
    """Search for entities by content or type."""
    results = []
    query_lower = query.lower()

    for name, entity in knowledge_graph["entities"].items():
        if entity_type and entity["type"] != entity_type:
            continue

        if (query_lower in name.lower() or
            query_lower in entity.get("content", "").lower()):
            results.append({"name": name, **entity})

            if len(results) >= limit:
                break

    return results


async def create_relation(source: str, target: str, relation_type: str,
                         metadata: Optional[Dict] = None) -> Dict[str, Any]:
    """Create a relation between two entities."""
    if source not in knowledge_graph["entities"]:
        raise KeyError(f"Source entity '{source}' not found")
    if target not in knowledge_graph["entities"]:
        raise KeyError(f"Target entity '{target}' not found")

    if settings.safe_mode:
        # Block potentially dangerous relation types
        dangerous_relations = ["admin_of", "has_access_to", "owns", "controls"]
        if relation_type.lower() in dangerous_relations:
            raise PermissionError(f"Relation type '{relation_type}' requires authorization")

    if len(knowledge_graph["relations"]) >= settings.max_relations:
        raise ValueError("Maximum relation limit reached")

    relation = {
        "source": source,
        "target": target,
        "relation_type": relation_type,
        "metadata": metadata or {},
        "created_at": datetime.utcnow().isoformat()
    }
    knowledge_graph["relations"].append(relation)
    save_graph()

    return {"success": True, "relation": relation}


async def get_relations(entity_name: str, relation_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all relations for an entity."""
    results = []

    for relation in knowledge_graph["relations"]:
        if relation["source"] == entity_name or relation["target"] == entity_name:
            if relation_type and relation["relation_type"] != relation_type:
                continue
            results.append(relation)

    return results


async def delete_entity(name: str) -> Dict[str, Any]:
    """Delete an entity and its relations."""
    if name not in knowledge_graph["entities"]:
        raise KeyError(f"Entity '{name}' not found")

    if settings.safe_mode and is_sensitive_entity(name):
        raise PermissionError(f"Cannot delete protected entity: {name}")

    del knowledge_graph["entities"][name]

    # Remove associated relations
    knowledge_graph["relations"] = [
        r for r in knowledge_graph["relations"]
        if r["source"] != name and r["target"] != name
    ]
    save_graph()

    return {"success": True, "message": f"Entity '{name}' deleted"}


async def list_entities(entity_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List all entities in the knowledge graph."""
    results = []

    for name, entity in knowledge_graph["entities"].items():
        if entity_type and entity["type"] != entity_type:
            continue
        results.append({"name": name, "type": entity["type"]})
        if len(results) >= limit:
            break

    return results


# ---------------------------------------------------------
# JSON-RPC HANDLER
# ---------------------------------------------------------
@app.post("/")
async def handle_rpc(request: Request):
    body = None
    try:
        body = await request.json()
        method = body.get("method")
        params = body.get("params", {})
        req_id = body.get("id")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "result": {"tools": TOOLS_METADATA},
                "id": req_id
            }

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            result = None

            if tool_name == "create_entity":
                result = await create_entity(
                    args.get("name"),
                    args.get("entity_type"),
                    args.get("content"),
                    args.get("metadata")
                )
            elif tool_name == "get_entity":
                result = await get_entity(args.get("name"))
            elif tool_name == "search_entities":
                result = await search_entities(
                    args.get("query"),
                    args.get("entity_type"),
                    args.get("limit", 10)
                )
            elif tool_name == "create_relation":
                result = await create_relation(
                    args.get("source"),
                    args.get("target"),
                    args.get("relation_type"),
                    args.get("metadata")
                )
            elif tool_name == "get_relations":
                result = await get_relations(
                    args.get("entity_name"),
                    args.get("relation_type")
                )
            elif tool_name == "delete_entity":
                result = await delete_entity(args.get("name"))
            elif tool_name == "list_entities":
                result = await list_entities(
                    args.get("entity_type"),
                    args.get("limit", 100)
                )
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


@app.on_event("startup")
async def startup():
    load_graph()


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "memory-tool",
        "entities": len(knowledge_graph["entities"]),
        "relations": len(knowledge_graph["relations"])
    }
