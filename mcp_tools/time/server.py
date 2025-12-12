import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings
try:
    from zoneinfo import ZoneInfo, available_timezones
except ImportError:
    from backports.zoneinfo import ZoneInfo
    try:
        from backports.zoneinfo import available_timezones
    except ImportError:
        available_timezones = set() # Fallback if not available
from tzlocal import get_localzone_name

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
class Settings(BaseSettings):
    """
    Configuration for Time Tool.
    All parameters can be overridden via environment variables with TIME_ prefix.
    """
    log_level: str = "INFO"
    default_timezone: str = "UTC"
    
    class Config:
        env_file = ".env"
        env_prefix = "TIME_"

settings = Settings()

# Setup Logging
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("Tool_Time")

app = FastAPI(title="Time Tool (MCP)")

# ---------------------------------------------------------
# 1. HELPER FUNCTIONS
# ---------------------------------------------------------
def get_local_tz(local_tz_override: str | None = None) -> ZoneInfo:
    if local_tz_override:
        return ZoneInfo(local_tz_override)
    local_tzname = get_localzone_name()
    if local_tzname is not None:
        return ZoneInfo(local_tzname)
    return ZoneInfo("UTC")

def get_zoneinfo(timezone_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(timezone_name)
    except Exception:
        # Try to find a matching timezone by suffix (e.g. "Budapest" -> "Europe/Budapest")
        zones = available_timezones() if callable(available_timezones) else available_timezones
        
        if zones:
            matches = [tz for tz in zones if tz.endswith(f"/{timezone_name}")]
            if matches:
                # Return the first match (e.g., "Europe/Budapest")
                return ZoneInfo(matches[0])
        
        raise ValueError(f"Invalid timezone: '{timezone_name}'")

# ---------------------------------------------------------
# 2. TOOL IMPLEMENTATIONS
# ---------------------------------------------------------
TOOLS_METADATA = [
    {
        "name": "get_current_time",
        "description": "Get current time in a specific timezone",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timezone": {
                    "type": "string",
                    "description": "IANA timezone name (e.g., 'America/New_York', 'Europe/London'). Defaults to UTC."
                }
            },
            "required": ["timezone"]
        }
    },
    {
        "name": "convert_time",
        "description": "Convert time between timezones",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_timezone": {
                    "type": "string",
                    "description": "Source IANA timezone name"
                },
                "time": {
                    "type": "string",
                    "description": "Time to convert in 24-hour format (HH:MM)"
                },
                "target_timezone": {
                    "type": "string",
                    "description": "Target IANA timezone name"
                }
            },
            "required": ["source_timezone", "time", "target_timezone"]
        }
    }
]

async def get_current_time(timezone_name: str) -> Dict[str, Any]:
    timezone = get_zoneinfo(timezone_name)
    current_time = datetime.now(timezone)
    return {
        "timezone": timezone_name,
        "datetime": current_time.isoformat(timespec="seconds"),
        "day_of_week": current_time.strftime("%A"),
        "is_dst": bool(current_time.dst()),
    }

async def convert_time(source_tz: str, time_str: str, target_tz: str) -> Dict[str, Any]:
    source_timezone = get_zoneinfo(source_tz)
    target_timezone = get_zoneinfo(target_tz)

    try:
        parsed_time = datetime.strptime(time_str, "%H:%M").time()
    except ValueError:
        try:
            parsed_time = datetime.strptime(time_str, "%H:%M:%S").time()
        except ValueError:
            raise ValueError("Invalid time format. Expected HH:MM or HH:MM:SS [24-hour format]")

    now = datetime.now(source_timezone)
    source_time = datetime(
        now.year, now.month, now.day,
        parsed_time.hour, parsed_time.minute, parsed_time.second,
        tzinfo=source_timezone,
    )

    target_time = source_time.astimezone(target_timezone)
    source_offset = source_time.utcoffset() or timedelta()
    target_offset = target_time.utcoffset() or timedelta()
    hours_difference = (target_offset - source_offset).total_seconds() / 3600

    if hours_difference.is_integer():
        time_diff_str = f"{hours_difference:+.1f}h"
    else:
        time_diff_str = f"{hours_difference:+.2f}".rstrip("0").rstrip(".") + "h"

    return {
        "source": {
            "timezone": source_tz,
            "datetime": source_time.isoformat(timespec="seconds"),
            "day_of_week": source_time.strftime("%A"),
            "is_dst": bool(source_time.dst()),
        },
        "target": {
            "timezone": target_tz,
            "datetime": target_time.isoformat(timespec="seconds"),
            "day_of_week": target_time.strftime("%A"),
            "is_dst": bool(target_time.dst()),
        },
        "time_difference": time_diff_str,
    }

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
            
            if tool_name == "get_current_time":
                result = await get_current_time(args.get("timezone", "UTC"))
            elif tool_name == "convert_time":
                result = await convert_time(
                    args.get("source_timezone"),
                    args.get("time"),
                    args.get("target_timezone")
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
