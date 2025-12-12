from pydantic import BaseModel, Field, field_validator
from typing import Optional, Union, Any, Dict, List, Literal
from enum import Enum


class SecurityClass(str, Enum):
    """
    Binary security classification system for fast, accurate threat detection.

    BENIGN: Safe request - matches known good patterns, standard arguments,
            aligns with expected tool usage context.
    ATTACK: Malicious request - includes injection attacks, path traversal,
            command execution, anomalous patterns, and policy violations.
    """
    BENIGN = "benign"
    ATTACK = "attack"

    @property
    def is_allowed(self) -> bool:
        """Only BENIGN requests are automatically allowed."""
        return self == SecurityClass.BENIGN

    @property
    def description(self) -> str:
        descriptions = {
            SecurityClass.BENIGN: "Safe request matching known good patterns",
            SecurityClass.ATTACK: "Attack pattern detected"
        }
        return descriptions[self]


class JsonRpcRequest(BaseModel):
    """
    Strict implementation of JSON-RPC 2.0 Request object.
    """
    jsonrpc: Literal["2.0"] = "2.0"
    method: str = Field(..., min_length=1, description=" The name of the method to be invoked.")
    params: Optional[Union[Dict[str, Any], List[Any]]] = None
    id: Optional[Union[str, int, None]] = None


class JsonRpcErrorData(BaseModel):
    """Thesis-specific error data for debugging security blocks."""
    class_: str = Field(alias="class")  # SecurityClass value: benign, attack
    confidence: float  # 0.0 to 1.0
    reason: str
    distance: Optional[float] = None  # Distance to decision boundary

    class Config:
        populate_by_name = True

class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Optional[JsonRpcErrorData] = None

class JsonRpcResponse(BaseModel):
    """
    Standard JSON-RPC 2.0 Response.
    """
    jsonrpc: Literal["2.0"] = "2.0"
    result: Optional[Any] = None
    error: Optional[JsonRpcError] = None
    id: Optional[Union[str, int, None]] = None

    @classmethod
    def error_response(cls, req_id: Any, code: int, message: str, data: Any = None):
        return cls(
            id=req_id,
            error=JsonRpcError(code=code, message=message, data=data)
        )