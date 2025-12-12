import os
import json
import logging
import asyncio
import base64
from typing import Generator, Optional, Dict, Any
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse, Response
from fastapi.concurrency import run_in_threadpool
from contextlib import asynccontextmanager
import httpx

from src.config import get_settings
from src.models import JsonRpcRequest, JsonRpcResponse
from src.core.detector import BinaryMCPDetector
from src.core.utils import log_thesis_data
from src.services.forwarder import RequestForwarder

# Logging Setup
settings = get_settings()
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("MCP_Gateway")


def _validate_training_format(tool_name: str, samples: Any) -> None:
    """Validate training data format for a tool."""
    if not isinstance(samples, dict):
        raise ValueError(
            f"Invalid format for '{tool_name}': expected dict, got {type(samples).__name__}"
        )
    if "benign" not in samples:
        raise ValueError(f"Missing 'benign' key for tool '{tool_name}'")
    if "attack" not in samples:
        raise ValueError(f"Missing 'attack' key for tool '{tool_name}'")

# MCP Protocol Constants
MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "mcp-security-gateway"
SERVER_VERSION = "1.0.0"

# MCP Capabilities - what this bridge supports
MCP_SERVER_CAPABILITIES = {
    "tools": {
        "listChanged": True  # We support notifying when tools change
    },
    # We aggregate resources/prompts from upstream but don't provide our own
    "resources": {},
    "prompts": {},
}

# Global Forwarder Instance
forwarder: Optional[RequestForwarder] = None

async def periodic_discovery(forwarder_instance: RequestForwarder, interval: int = 60):
    """Background task to refresh tool discovery periodically."""
    while True:
        try:
            await asyncio.sleep(interval)
            logger.info("Running periodic tool discovery...")
            await forwarder_instance.discover_tools()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Periodic discovery failed: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifecycle:
    1. Initialize Detector (Load Model & Fit Prototypes)
    2. Initialize Forwarder (Open Connection Pool)
    3. Start Periodic Discovery Task
    """
    global forwarder
    logger.info("--- MCP BRIDGE STARTUP ---")
    
    # A. Setup Forwarder
    forwarder = RequestForwarder()
    # Dynamic Discovery of Tools
    await forwarder.discover_tools()
    
    # Start background discovery task
    discovery_task = asyncio.create_task(periodic_discovery(forwarder))

    # B. Setup Detector (binary classification: benign vs attack)
    detector = BinaryMCPDetector()  # Singleton

    # 1. Try to load pre-trained models
    detector.load_models()

    if not detector.prototypes:
        logger.info("No pre-trained model found. Attempting to fit from training data...")
        training_file = os.path.join(settings.research_data_path, settings.training_data_file)

        if os.path.exists(training_file):
            try:
                with open(training_file, "r", encoding="utf-8") as f:
                    training_data = json.load(f)

                for tool_name, samples in training_data.items():
                    _validate_training_format(tool_name, samples)
                    detector.fit(
                        tool_name,
                        benign_samples=samples.get("benign", []),
                        attack_samples=samples.get("attack", [])
                    )

                detector.save_models()
                logger.info("Detector fitted and saved successfully.")
            except Exception as e:
                logger.error(f"Training failed: {e}")
        else:
            logger.warning("No training data found. Running in ZERO-SHOT mode.")
    
    yield # Server runs here

    # Shutdown
    logger.info("--- MCP BRIDGE SHUTDOWN ---")
    discovery_task.cancel()
    if forwarder:
        await forwarder.close()

app = FastAPI(title=settings.app_name, lifespan=lifespan)


# ---------------------------------------------------------
# MCP PROTOCOL HANDLERS
# ---------------------------------------------------------

def handle_initialize(req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    MCP initialize handler - establishes connection and negotiates capabilities.
    https://spec.modelcontextprotocol.io/specification/basic/lifecycle/
    """
    client_info = params.get("clientInfo", {})
    logger.info(f"MCP Initialize from client: {client_info.get('name', 'unknown')} v{client_info.get('version', '?')}")

    return {
        "jsonrpc": "2.0",
        "result": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
            "capabilities": MCP_SERVER_CAPABILITIES,
        },
        "id": req_id
    }


def handle_ping(req_id: Any) -> Dict[str, Any]:
    """
    MCP ping handler - simple health check.
    https://spec.modelcontextprotocol.io/specification/basic/utilities/
    """
    return {
        "jsonrpc": "2.0",
        "result": {},
        "id": req_id
    }


def handle_tools_list(req_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    MCP tools/list handler - returns aggregated tools from all upstream servers.
    Supports cursor-based pagination per MCP specification.
    https://spec.modelcontextprotocol.io/specification/server/tools/
    """
    tools = forwarder.get_aggregated_tools() if forwarder else []

    # Pagination support: cursor is base64-encoded offset
    cursor = params.get("cursor")
    page_size = 50  # Default page size

    start_index = 0
    if cursor:
        try:
            start_index = int(base64.b64decode(cursor).decode())
        except (ValueError, Exception):
            start_index = 0

    # Slice tools for this page
    end_index = start_index + page_size
    page_tools = tools[start_index:end_index]

    # Build response with optional nextCursor
    result = {"tools": page_tools}

    if end_index < len(tools):
        next_cursor = base64.b64encode(str(end_index).encode()).decode()
        result["nextCursor"] = next_cursor

    return {
        "jsonrpc": "2.0",
        "result": result,
        "id": req_id
    }


def handle_resources_list(req_id: Any) -> Dict[str, Any]:
    """
    MCP resources/list handler - placeholder for resource discovery.
    https://spec.modelcontextprotocol.io/specification/server/resources/
    """
    # Future: aggregate resources from upstream servers
    return {
        "jsonrpc": "2.0",
        "result": {
            "resources": []
        },
        "id": req_id
    }


def handle_prompts_list(req_id: Any) -> Dict[str, Any]:
    """
    MCP prompts/list handler - placeholder for prompt templates.
    https://spec.modelcontextprotocol.io/specification/server/prompts/
    """
    # Future: aggregate prompts from upstream servers
    return {
        "jsonrpc": "2.0",
        "result": {
            "prompts": []
        },
        "id": req_id
    }


def handle_notifications_initialized() -> None:
    """
    MCP notifications/initialized - client confirms initialization complete.
    This is a notification (no response required).
    """
    logger.info("Client confirmed initialization complete")


# ---------------------------------------------------------
# MAIN JSON-RPC ENDPOINT
# ---------------------------------------------------------

@app.post("/jsonrpc")
async def handle_jsonrpc(request: Request, background_tasks: BackgroundTasks):
    # 1. Parse & Validate Schema
    try:
        body = await request.json()
        rpc_req = JsonRpcRequest(**body)  # Pydantic Validation
    except Exception as e:
        logger.warning(f"Malformed Request: {e}")
        return JSONResponse(
            content=JsonRpcResponse.error_response(None, -32700, "Parse Error").model_dump(exclude_none=True)
        )

    # 2. Handle MCP Protocol Methods (no security inspection needed)
    method = rpc_req.method
    # Handle both dict and list params per JSON-RPC 2.0 spec
    if isinstance(rpc_req.params, dict):
        params = rpc_req.params
    elif isinstance(rpc_req.params, list):
        # Convert positional params to indexed dict for compatibility
        params = {str(i): v for i, v in enumerate(rpc_req.params)}
    else:
        params = {}

    # MCP Lifecycle Methods
    if method == "initialize":
        return JSONResponse(content=handle_initialize(rpc_req.id, params))

    if method == "ping":
        return JSONResponse(content=handle_ping(rpc_req.id))

    # MCP Notifications (id is None - no response expected per JSON-RPC 2.0)
    if method == "notifications/initialized":
        handle_notifications_initialized()
        # Notifications don't get responses - return 204 No Content
        return Response(status_code=204)

    # MCP Discovery Methods (passthrough aggregation)
    if method == "tools/list":
        return JSONResponse(content=handle_tools_list(rpc_req.id, params))

    if method == "resources/list":
        return JSONResponse(content=handle_resources_list(rpc_req.id))

    if method == "prompts/list":
        return JSONResponse(content=handle_prompts_list(rpc_req.id))

    # 3. Extract Feature for Detection (only for tools/call and other methods)
    # Logic to flatten params into a string for DistilBERT
    tool_name = "unknown"
    payload_text = ""

    if method == "tools/call" and isinstance(rpc_req.params, dict):
        tool_name = rpc_req.params.get("name", "unknown")
        payload_text = json.dumps(rpc_req.params.get("arguments", {}))
    else:
        # Fallback for direct calls
        if "/" in method:
            tool_name = method.split("/")[0]
        payload_text = json.dumps(rpc_req.params)

    # 3. Security Inspection (binary classification)
    detector = BinaryMCPDetector()
    # Offload CPU-bound inference to threadpool to avoid blocking the event loop
    security_result = await run_in_threadpool(detector.predict, tool_name, payload_text)

    # 4. Thesis Logging (Non-blocking)
    background_tasks.add_task(
        log_thesis_data,
        request_id=str(rpc_req.id),
        tool=tool_name,
        payload=payload_text,
        result=security_result
    )

    # 5. Decision Gate (binary classification)
    if not security_result["allowed"]:
        confidence = security_result.get("confidence", 0.0)

        logger.warning(f"BLOCKED [ATTACK]: {tool_name} | Confidence: {confidence:.2%}")
        logger.debug(f"   Reason: {security_result['reason']}")

        err_response = JsonRpcResponse.error_response(
            rpc_req.id,
            -32000,
            "Security Violation: Attack pattern detected",
            data={
                "class": "attack",
                "confidence": confidence,
                "reason": security_result["reason"],
                "distance": security_result.get("distance")
            }
        )
        return JSONResponse(content=err_response.model_dump(exclude_none=True))

    # 6. Forward to Tool
    if forwarder is None:
        logger.error("Forwarder not initialized")
        err_response = JsonRpcResponse.error_response(
            rpc_req.id, -32603, "Internal Error: Forwarder not initialized"
        )
        return JSONResponse(content=err_response.model_dump(exclude_none=True))
    
    upstream_response = await forwarder.forward(rpc_req)
    return JSONResponse(content=upstream_response)


# Also expose at root "/" for MCP stdio transport compatibility
# Some MCP clients expect the JSON-RPC endpoint at the root path
@app.post("/")
async def handle_jsonrpc_root(request: Request, background_tasks: BackgroundTasks):
    """Alias for /jsonrpc - MCP protocol compatibility."""
    return await handle_jsonrpc(request, background_tasks)


@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    """
    Proxy endpoint for OpenAI-compatible chat completions.
    Forwards requests to the internal LLM Service.
    """
    llm_url = os.getenv("LLM_SERVICE_URL", "http://mcp-llm:8080")
    target_url = f"{llm_url}/v1/chat/completions"
    
    try:
        body = await request.json()
        async with httpx.AsyncClient() as client:
            # Forward the request to the LLM service
            response = await client.post(target_url, json=body, timeout=60.0)
            
            # Return the response from the LLM service
            return JSONResponse(content=response.json(), status_code=response.status_code)
    except httpx.RequestError as exc:
        logger.error(f"An error occurred while requesting {exc.request.url!r}.")
        return JSONResponse(content={"error": "LLM Service Unreachable"}, status_code=503)
    except Exception as e:
        logger.error(f"Proxy Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/health")
async def health_check():
    """
    Health check endpoint with MCP server information.
    """
    tools_count = len(forwarder.get_aggregated_tools()) if forwarder else 0
    return {
        "status": "healthy",
        "server": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocol_version": MCP_PROTOCOL_VERSION,
        },
        "tools_discovered": tools_count,
        "upstream_servers": len(settings.mcp_servers),
    }