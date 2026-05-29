# Dockerfile
# Base image — official Python 3.11 slim (smaller than full Python)
FROM python:3.11-slim

# Who built this — goes in your dissertation and GitHub
LABEL maintainer="SecureFlow Project"
LABEL description="AI-powered intrusion detection endpoint"
LABEL version="1.0.0"

# Set working directory inside the container
WORKDIR /secureflow

# Copy requirements first — Docker caches this layer
# If requirements don't change, Docker skips reinstalling on rebuild
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create directory for model persistence
RUN mkdir -p app

# Expose port 8000 to the outside world
EXPOSE 8000

# Health check — Docker monitors this automatically
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# Run the application
CMD ["python", "app/main.py"]