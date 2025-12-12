# Lightweight Python image
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src ./src

# Expose the same port as the local service for easy swapping
EXPOSE 8080

# Run the app
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]