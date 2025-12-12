"""
Fetch MCP Server - Web Content Fetching Tool

This server implements web content fetching functionality following the MCP specification.
Security testing scenarios:
- SSRF (Server-Side Request Forgery)
- URL injection and protocol smuggling
- Internal network scanning attempts
- Malicious redirect chains
"""
import os
import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings
import httpx

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
class Settings(BaseSettings):
    """Configuration for Fetch Tool."""
    log_level: str = "INFO"
    safe_mode: bool = False  # When False, allows internal URLs for testing
    timeout: int = 10
    max_content_length: int = 1048576  # 1MB default
    user_agent: str = "MCP-Fetch/1.0"

    class Config:
        env_file = ".env"
        env_prefix = "FETCH_"

settings = Settings()

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("Tool_Fetch")

app = FastAPI(title="Fetch Tool (MCP)")

# Internal/dangerous URL patterns (for SAFE_MODE blocking)
BLOCKED_PATTERNS = [
    r'^https?://localhost',
    r'^https?://127\.',
    r'^https?://10\.',
    r'^https?://172\.(1[6-9]|2[0-9]|3[01])\.',
    r'^https?://192\.168\.',
    r'^https?://169\.254\.',  # Link-local
    r'^https?://\[::1\]',     # IPv6 localhost
    r'^file://',
    r'^gopher://',
    r'^ftp://',
]

# ---------------------------------------------------------
# TOOL IMPLEMENTATIONS
# ---------------------------------------------------------
TOOLS_METADATA = [
    {
        "name": "fetch_url",
        "description": "Fetch content from a URL and return the text content",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch content from"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum content length to return (default: 10000)"
                },
                "headers": {
                    "type": "object",
                    "description": "Optional custom headers to include"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "fetch_html",
        "description": "Fetch HTML from a URL and extract text content",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch HTML from"
                },
                "selector": {
                    "type": "string",
                    "description": "Optional CSS selector to extract specific content"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "check_url",
        "description": "Check if a URL is accessible and return status information",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to check"
                }
            },
            "required": ["url"]
        }
    }
]


def validate_url(url: str) -> bool:
    """Validate URL for safety in SAFE_MODE."""
    if not settings.safe_mode:
        return True  # Allow all URLs in vulnerable mode for testing

    for pattern in BLOCKED_PATTERNS:
        if re.match(pattern, url, re.IGNORECASE):
            return False

    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False

    return True


async def fetch_url(url: str, max_length: int = 10000, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Fetch content from a URL."""
    if not validate_url(url):
        raise PermissionError(f"URL blocked by security policy: {url}")

    request_headers = {"User-Agent": settings.user_agent}
    if headers:
        request_headers.update(headers)

    async with httpx.AsyncClient(timeout=settings.timeout, follow_redirects=True) as client:
        response = await client.get(url, headers=request_headers)
        response.raise_for_status()

        content = response.text[:max_length]

        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", "unknown"),
            "content_length": len(response.text),
            "content": content,
            "truncated": len(response.text) > max_length
        }


async def fetch_html(url: str, selector: Optional[str] = None) -> Dict[str, Any]:
    """Fetch HTML and optionally extract content."""
    if not validate_url(url):
        raise PermissionError(f"URL blocked by security policy: {url}")

    async with httpx.AsyncClient(timeout=settings.timeout, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": settings.user_agent})
        response.raise_for_status()

        html_content = response.text

        # Basic text extraction (remove HTML tags)
        text_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        text_content = re.sub(r'<style[^>]*>.*?</style>', '', text_content, flags=re.DOTALL | re.IGNORECASE)
        text_content = re.sub(r'<[^>]+>', ' ', text_content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()

        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "title": re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE).group(1) if re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE) else None,
            "text_content": text_content[:10000],
            "html_length": len(html_content)
        }


async def check_url(url: str) -> Dict[str, Any]:
    """Check URL accessibility."""
    if not validate_url(url):
        raise PermissionError(f"URL blocked by security policy: {url}")

    async with httpx.AsyncClient(timeout=settings.timeout, follow_redirects=False) as client:
        try:
            response = await client.head(url, headers={"User-Agent": settings.user_agent})
            return {
                "url": url,
                "accessible": True,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "content_length": response.headers.get("content-length"),
                "redirects_to": str(response.headers.get("location")) if response.is_redirect else None
            }
        except httpx.RequestError as e:
            return {
                "url": url,
                "accessible": False,
                "error": str(e)
            }


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

            if tool_name == "fetch_url":
                result = await fetch_url(
                    args.get("url"),
                    args.get("max_length", 10000),
                    args.get("headers")
                )
            elif tool_name == "fetch_html":
                result = await fetch_html(
                    args.get("url"),
                    args.get("selector")
                )
            elif tool_name == "check_url":
                result = await check_url(args.get("url"))
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "fetch-tool"}
