FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install fastapi uvicorn redis[asyncio]

# Copy application code
COPY morpheus/ ./morpheus/
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Run the API server
CMD ["uvicorn", "morpheus.api.rest_api:app", "--host", "0.0.0.0", "--port", "8000"]
