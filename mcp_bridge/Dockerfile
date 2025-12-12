# -------------------------------------------------------------------
# STAGE 1: Builder (Compiling dependencies)
# -------------------------------------------------------------------
# Use a slim python image to reduce attack surface
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system build tools (needed for some python packages)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# ENGINEERING BEST PRACTICE:
# We install the CPU-only version of PyTorch (--extra-index-url).
# Standard 'pip install torch' pulls CUDA libraries (2GB+), which
# bloats the container and slows down your development cycle.
RUN pip install --user --no-cache-dir \
    torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cpu

# Install the rest of the requirements
RUN pip install --user --no-cache-dir -r requirements.txt

# Pre-download the DistilBERT model during build.
# This prevents the container from trying to download 300MB
# from HuggingFace every time it starts (Latency Optimization).
RUN python -c "from transformers import AutoTokenizer, AutoModel; \
    AutoTokenizer.from_pretrained('distilbert-base-uncased'); \
    AutoModel.from_pretrained('distilbert-base-uncased')"

# -------------------------------------------------------------------
# STAGE 2: Runtime (The actual secure container)
# -------------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# SECURITY BEST PRACTICE:
# Create a non-root user. If this container is compromised (Sandbox Escape),
# the attacker won't have root privileges on the host[cite: 208, 209].
RUN useradd -m -r mcpuser && \
    chown mcpuser /app

# Copy installed packages from builder stage
COPY --from=builder --chown=mcpuser:mcpuser /root/.local /home/mcpuser/.local
COPY --from=builder --chown=mcpuser:mcpuser /root/.cache/huggingface /home/mcpuser/.cache/huggingface

# Update PATH to include user-installed binaries
ENV PATH=/home/mcpuser/.local/bin:$PATH
# Tell transformers where to look for the pre-downloaded model
ENV HF_HOME=/home/mcpuser/.cache/huggingface

# Copy the application source code
COPY ./src /app/src

# Switch to non-root user
USER mcpuser

# Expose the port (must match docker compose)
EXPOSE 8000

# Start the Async Server
# host 0.0.0.0 is required for Docker networking
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]