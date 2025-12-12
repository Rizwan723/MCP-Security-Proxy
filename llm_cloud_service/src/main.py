import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

import openai
import google.generativeai as genai

from src.config import settings

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Cloud_LLM")

app = FastAPI(title="Cloud LLM Adapter (Thesis)")

# ---------------------------------------------------------
# 1. PROVIDER INITIALIZATION
# ---------------------------------------------------------
if settings.llm_provider == "openai":
    openai.api_key = settings.openai_api_key
    logger.info(f"Initialized OpenAI Provider with model: {settings.model_name}")

elif settings.llm_provider == "gemini":
    genai.configure(api_key=settings.google_api_key)
    # Gemini Setup
    gemini_model = genai.GenerativeModel(settings.model_name)
    logger.info(f"Initialized Google Gemini Provider with model: {settings.model_name}")

# ---------------------------------------------------------
# 2. DATA MODELS (Same as Local Service)
# ---------------------------------------------------------
class Message(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    messages: List[Message]
    temperature: Optional[float] = settings.temperature
    max_tokens: Optional[int] = settings.max_tokens

# ---------------------------------------------------------
# 3. ADAPTER LOGIC
# ---------------------------------------------------------
async def call_openai(request: ChatCompletionRequest):
    """Direct wrapper for OpenAI API"""
    try:
        response = openai.chat.completions.create(
            model=settings.model_name,
            messages=[m.model_dump() for m in request.messages],
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
        # Return standard dictionary format compatible with our Client
        return response.model_dump()
    except Exception as e:
        logger.error(f"OpenAI Error: {e}")
        raise HTTPException(status_code=502, detail=f"OpenAI Provider Error: {str(e)}")

async def call_gemini(request: ChatCompletionRequest):
    """
    Adapter for Gemini: Converts 'messages' list to Gemini's history format.
    """
    try:
        # 1. Convert OpenAl-style history to Gemini ChatHistory
        # Gemini expects roles 'user' and 'model' (not 'assistant')
        gemini_history = []
        last_user_message = ""

        for msg in request.messages[:-1]: # All but the last one are history
            role = "user" if msg.role == "user" else "model"
            gemini_history.append({"role": role, "parts": [msg.content]})
        
        # The last message is the current prompt
        last_user_message = request.messages[-1].content

        # 2. Start Chat Session
        chat = gemini_model.start_chat(history=gemini_history)
        
        # 3. Generate
        response = chat.send_message(
            last_user_message,
            generation_config=genai.types.GenerationConfig(
                temperature=request.temperature,
                max_output_tokens=request.max_tokens
            )
        )
        
        # 4. Format response to look like OpenAI (Crucial for compatibility)
        return {
            "id": "gemini-response",
            "object": "chat.completion",
            "created": 0,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response.text
                },
                "finish_reason": "stop"
            }],
            "usage": {"total_tokens": 0} # Gemini doesn't always return usage in the same way
        }
        
    except Exception as e:
        logger.error(f"Gemini Error: {e}")
        raise HTTPException(status_code=502, detail=f"Google Provider Error: {str(e)}")

# ---------------------------------------------------------
# 4. UNIFIED ENDPOINT
# ---------------------------------------------------------
@app.post("/v1/chat/completions")
async def chat_completion(request: ChatCompletionRequest):
    if settings.llm_provider == "openai":
        return await call_openai(request)
    elif settings.llm_provider == "gemini":
        return await call_gemini(request)
    else:
        raise HTTPException(status_code=500, detail="Invalid Provider Configuration")