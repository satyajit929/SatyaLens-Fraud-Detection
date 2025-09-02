# FRAUD DETECTION SYSTEM - DOCKERFILE
# =============================================================================
# Multi-stage Docker build for production-ready fraud detection system

# Stage 1: Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Add metadata labels
LABEL maintainer="fraud-detection-team@company.com" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="fraud-detection-system" \
      org.label-schema.description="Production-ready fraud detection system" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/your-company/fraud-detection-system" \
      org.label-schema.schema-version="1.0"

# Set environment variables for build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    python3-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create non-root user for security
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -d /app -s /bin/bash appuser && \
    mkdir -p /app && \
    chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=appuser:appgroup ./app /app/app
COPY --chown=appuser:appgroup ./tests /app/tests
COPY --chown=appuser:appgroup ./alembic.ini /app/
COPY --chown=appuser:appgroup ./alembic /app/alembic

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/models /app/data /app/uploads /app/backups && \
    chown -R appuser:appgroup /app/logs /app/models /app/data /app/uploads /app/backups

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Add health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# =============================================================================
# DEVELOPMENT DOCKERFILE (Alternative)
# =============================================================================
# Uncomment below for development version with hot reload

# FROM python:3.11-slim as development
# 
# ENV PYTHONDONTWRITEBYTECODE=1 \
#     PYTHONUNBUFFERED=1 \
#     PYTHONPATH=/app
# 
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     gcc \
#     g++ \
#     libpq-dev \
#     curl \
#     git \
#     && rm -rf /var/lib/apt/lists/*
# 
# WORKDIR /app
# 
# COPY requirements.txt .
# RUN pip install --upgrade pip && \
#     pip install -r requirements.txt
# 
# # Install development dependencies
# RUN pip install watchdog[watchmedo] pytest-watch
# 
# COPY . .
# 
# EXPOSE 8000
# 
# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

