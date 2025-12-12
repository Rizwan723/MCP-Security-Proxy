# -------------------------------------------------------------------
# LLM Runtime (Optimized)
# -------------------------------------------------------------------
# BEST PRACTICE 1: Match Base Image to Wheel Version (CUDA 12.2)
# BEST PRACTICE 2: Use 'runtime' instead of 'devel' for prebuilt wheels to save space
# BEST PRACTICE 3: Use Ubuntu 22.04 to avoid PEP 668 pip restrictions
FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04

WORKDIR /app

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Python and minimal runtime dependencies
# We don't need libopenblas-dev (header files) for runtime, just the libs if needed.
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# 1. Install General Dependencies
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir -r requirements.txt

# 2. Install Llama-cpp-python (Prebuilt CUDA Wheel)
# We ensure the wheel matches the container's CUDA version (12.2)
RUN python3 -m pip install llama-cpp-python \
    --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu122

# Copy application code
COPY server.py .

# Expose port
EXPOSE 8080

# Environment variables
# NOTE: Llama-2 is quite old (2023). Ensure your model path matches your actual model.
ENV MODEL_PATH="/app/models/llama-2-7b-chat.gguf"
ENV N_CTX=4096

# Start Server
CMD ["python3", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]