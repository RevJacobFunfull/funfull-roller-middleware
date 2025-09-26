# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Ensure output is flushed immediately and no pyc files
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Create app directory
WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py ./

# Default port; Render and other PaaS set $PORT at runtime
ENV PORT=8080

# Start the server; respect $PORT when provided
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
