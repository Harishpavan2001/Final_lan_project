# --- Build Stage ---
FROM python:3.11-slim as builder

WORKDIR /install

# Install requirements first to cache dependency layers
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Final Execution Stage ---
FROM python:3.11-slim

WORKDIR /app

# Setup environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app:create_app
ENV FLASK_ENV=production

# Install essential system packages (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies from builder stage
COPY --from=builder /install /usr/local

# Copy application files
COPY . .

# Set execution permissions on scripts
RUN chmod +x docker/entrypoint.sh docker/healthcheck.sh

# Expose internal Flask/Gunicorn port
EXPOSE 5000

# Launch container using entrypoint script
ENTRYPOINT ["docker/entrypoint.sh"]
