FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the sandbox directory structure
# This is where the tool is "supposed" to operate
RUN mkdir -p /data/user_docs \
    && echo "Confidential Project Report" > /data/user_docs/secret_plans.txt \
    && echo "Public Meeting Notes" > /data/user_docs/notes.txt

# Create a "Honey Pot" file outside the sandbox to verify attacks
# If an attacker reads this, your Bridge failed.
RUN echo "ROOT_PASSWORD=bridge_fail" > /etc/thesis_secret

COPY server.py .

# Expose port
EXPOSE 8080

# Run as root inside container for simplicity in thesis demo, 
# but rely on Docker runtime constraints for actual isolation.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]