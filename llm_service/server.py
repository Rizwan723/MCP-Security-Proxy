import os
import logging
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from typing import List, Optional, Dict, Any
from llama_cpp import Llama

# -------------------------------------------------------------------
# 1. CONFIGURATION
# -------------------------------------------------------------------
class Settings(BaseSettings):
    """
    Configuration for Local LLM Service.
    All parameters can be overridden via environment variables.
    """
    # Model path and loading parameters
    model_path: str = "/app/models/llama-2-7b-chat.Q4_K_M.gguf"
    n_ctx: int = 4096  # Context window size
    n_batch: int = 512 # Batch size for GPU utilization
    n_gpu_layers: int = -1  # -1 = all layers to GPU
    flash_attn: bool = False # Enable Flash Attention if supported
    verbose: bool = True
    chat_format: str = "llama-2"  # Chat template format
    
    # Generation defaults
    temperature: float = 0.7
    max_tokens: int = 512
    
    class Config:
        env_file = ".env"
        env_prefix = "LLM_"

settings = Settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LLM_Service")

# -------------------------------------------------------------------
# 2. MODEL LIFECYCLE (Singleton)
# -------------------------------------------------------------------
# We load the model globally on startup to avoid reloading per request
try:
    if not os.path.exists(settings.model_path):
        logger.warning(f"Model not found at {settings.model_path}. Service will fail requests!")
        llm = None
    else:
        logger.info(f"Loading Model from {settings.model_path}...")
        llm = Llama(
            model_path=settings.model_path,
            n_ctx=settings.n_ctx,
            n_batch=settings.n_batch,
            n_gpu_layers=settings.n_gpu_layers,
            flash_attn=settings.flash_attn,
            verbose=settings.verbose,
            chat_format=settings.chat_format
        )
        logger.info("Model Loaded Successfully.")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    llm = None

app = FastAPI(title="Local LLM Service (Thesis)")

# -------------------------------------------------------------------
# 3. DATA MODELS (OpenAI-like)
# -------------------------------------------------------------------
class Message(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    messages: List[Message]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: bool = False
    stop: Optional[List[str]] = None

# -------------------------------------------------------------------
# 4. ENDPOINTS
# -------------------------------------------------------------------
@app.get("/health")
def health():
    if llm is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return {"status": "ok", "model_loaded": True}

@app.post("/v1/chat/completions")
def chat_completion(request: ChatCompletionRequest):
    """
    Standard Chat Completion endpoint.
    Receives conversation history, formats it for Llama-2, and returns response.
    """
    if llm is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        # Llama-cpp-python handles the chat templating (User/Assistant roles)
        output = llm.create_chat_completion(
            messages=[m.model_dump() for m in request.messages],
            temperature=request.temperature or settings.temperature,
            max_tokens=request.max_tokens or settings.max_tokens,
            stream=request.stream,
            stop=request.stop
        )
        return output
    except Exception as e:
        logger.error(f"Generation Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))