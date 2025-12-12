import httpx
import logging
from typing import Dict, Any, Optional, List

from src.config import get_settings
from src.models import JsonRpcRequest, JsonRpcResponse

logger = logging.getLogger(__name__)
settings = get_settings()

class RequestForwarder:
    """
    Manages async HTTP connections to downstream MCP tools.
    Implements connection pooling via a shared httpx.AsyncClient.
    """
    def __init__(self):
        # Connection Pooling: Re-uses TCP connections for lower latency
        self.client = httpx.AsyncClient(timeout=10.0)
        # Dynamic Routing Table: tool_name -> server_url
        self.tool_routing_table: Dict[str, str] = {}
        # Aggregated tools metadata from all upstream servers
        self.tools_metadata: List[Dict[str, Any]] = []

        # Fallback for legacy/hardcoded setups (DEPRECATED - use dynamic discovery)
        self.legacy_tool_map = {
            "filesystem": settings.tool_fs_url,
            "sqlite": settings.tool_sql_url,
            "sandbox": settings.tool_sandbox_url,
            "time": "http://tool-time:8080"
        }

    async def discover_tools(self):
        """
        Dynamic Discovery: Queries all configured MCP servers for their capabilities.
        Populates self.tool_routing_table and self.tools_metadata.
        """
        logger.info(f"Starting tool discovery on {len(settings.mcp_servers)} servers...")

        # Clear existing metadata to rebuild fresh
        new_routing_table: Dict[str, str] = {}
        new_tools_metadata: List[Dict[str, Any]] = []

        for server_url in settings.mcp_servers:
            try:
                # MCP Protocol: tools/list
                payload = {
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "id": "init-discovery"
                }

                response = await self.client.post(server_url, json=payload)
                response.raise_for_status()
                data = response.json()

                if "result" in data and "tools" in data["result"]:
                    tools = data["result"]["tools"]
                    for tool in tools:
                        tool_name = tool["name"]
                        new_routing_table[tool_name] = server_url
                        new_tools_metadata.append(tool)
                        logger.info(f"Registered tool '{tool_name}' -> {server_url}")
                else:
                    logger.warning(f"Server {server_url} returned no tools or invalid format.")

            except Exception as e:
                logger.error(f"Failed to discover tools from {server_url}: {e}")

        # Atomic update of routing table and metadata
        self.tool_routing_table = new_routing_table
        self.tools_metadata = new_tools_metadata
        logger.info(f"Discovery complete: {len(self.tools_metadata)} tools from {len(settings.mcp_servers)} servers")

    def get_aggregated_tools(self) -> List[Dict[str, Any]]:
        """
        Returns aggregated tools metadata from all upstream MCP servers.
        Used for tools/list passthrough.
        """
        return self.tools_metadata

    def _resolve_tool_url(self, method: str, params: Any) -> Optional[str]:
        """
        Determines which microservice to call.
        Uses dynamic routing table first, then falls back to legacy mapping.
        """
        tool_name = ""
        if method == "tools/call":
            tool_name = params.get("name")
            
            # 1. Dynamic Lookup
            if tool_name in self.tool_routing_table:
                return self.tool_routing_table[tool_name]
        
        # 2. Legacy Hardcoded Logic (Fallback)
        # Route Official SQLite Tools -> tool-db
        if tool_name in ["read_query", "write_query", "list_tables", "describe_table"]:
            return self.legacy_tool_map["sqlite"]
            
        # Route Filesystem Tools -> tool-fs
        if tool_name in ["read_file", "write_file", "list_directory"]:
            return self.legacy_tool_map["filesystem"]
            
        # 3. Fallback (Namespaced)
        if "/" in method:
            return self.legacy_tool_map.get(method.split("/")[0])
            
        return None

    async def forward(self, request: JsonRpcRequest) -> Dict[str, Any]:
        """
        Proxies the validated request to the appropriate internal container.
        """
        target_url = self._resolve_tool_url(request.method, request.params)
        
        if not target_url:
            logger.warning(f"Routing failed for method: {request.method}")
            return JsonRpcResponse.error_response(
                request.id, -32601, "Method not found / Tool routing failed"
            ).model_dump(exclude_none=True)

        try:
            # Serialize Pydantic model to dict
            payload = request.model_dump(exclude_none=True)
            
            # Perform the Request
            response = await self.client.post(target_url, json=payload)
            
            # Return raw JSON from tool (Transparent Proxy)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Tool Error {response.status_code}: {response.text}")
                return JsonRpcResponse.error_response(
                    request.id, -32603, "Internal Error from Tool Container"
                ).model_dump(exclude_none=True)

        except httpx.HTTPError as exc:
            logger.error(f"Network Error forwarding to {target_url}: {exc}")
            return JsonRpcResponse.error_response(
                request.id, -32603, "Proxy Network Error"
            ).model_dump(exclude_none=True)

    async def close(self):
        await self.client.aclose()