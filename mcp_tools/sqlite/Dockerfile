FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------
# ENGINEERING TASK: Database Seeding
# We pre-create the DB so SQL Injection has something to steal.
# ---------------------------------------------------------
COPY init_db.py .
RUN python init_db.py

# Copy Application Code
COPY server.py .

# Expose HTTP Port
EXPOSE 8080

# Run the Service
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]