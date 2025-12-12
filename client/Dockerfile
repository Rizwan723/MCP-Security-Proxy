FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the attack scripts
COPY . .

# Keep container alive for manual execution
CMD ["tail", "-f", "/dev/null"]