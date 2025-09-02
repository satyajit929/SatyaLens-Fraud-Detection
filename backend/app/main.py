from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import logging
import time
from contextlib import asynccontextmanager

from .config import settings
from .database import create_tables
from .exceptions import EXCEPTION_HANDLERS
from . import APP_INFO

# Import routers
from .auth.routes import router as auth_router
from .apps.routes import router as apps_router
from .monitoring.routes import router as monitoring_router
from .monitoring.websocket import router as websocket_router

# Setup logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting SatyaLens Backend...")
    
    # Create database tables
    try:
        create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise
    
    # Initialize fraud detection engine
    try:
        from .fraud.detector import fraud_detector
        await fraud_detector.initialize()
        logger.info("Fraud detection engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize fraud detection engine: {e}")
    
    # Start background tasks
    try:
        from .fraud.tasks import start_background_scanner
        start_background_scanner()
        logger.info("Background scanner started")
    except Exception as e:
        logger.error(f"Failed to start background scanner: {e}")
    
    logger.info("SatyaLens Backend started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down SatyaLens Backend...")
    
    # Cleanup tasks
    try:
        from .fraud.detector import fraud_detector
        await fraud_detector.cleanup()
        logger.info("Fraud detection engine cleaned up")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    
    logger.info("SatyaLens Backend shutdown complete")

# Create FastAPI application
app = FastAPI(
    title=APP_INFO["title"],
    description=APP_INFO["description"],
    version=APP_INFO["version"],
    contact=APP_INFO["contact"],
    license_info=APP_INFO["license_info"],
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Add exception handlers
for exception_type, handler in EXCEPTION_HANDLERS.items():
    app.add_exception_handler(exception_type, handler)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if not settings.debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*.satyalens.com", "localhost", "127.0.0.1"]
    )

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests"""
    start_time = time.time()
    
    # Log request
    logger.info(f"Request: {request.method} {request.url.path}")
    
    # Process request
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(
        f"Response: {response.status_code} - {process_time:.3f}s"
    )
    
    # Add process time header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    if not settings.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

# Include routers
app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Authentication"]
)

app.include_router(
    apps_router,
    prefix="/api/v1/apps",
    tags=["App Management"]
)

app.include_router(
    monitoring_router,
    prefix="/api/v1/monitoring",
    tags=["Monitoring"]
)

app.include_router(
    websocket_router,
    prefix="/ws",
    tags=["WebSocket"]
)

# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint"""
    return {
        "success": True,
        "message": "SatyaLens API is running",
        "data": {
            "app_name": settings.app_name,
            "version": settings.app_version,
            "status": "healthy"
        }
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        from .database import SessionLocal
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "unhealthy"
    
    try:
        # Check Redis connection
        import redis
        redis_client = redis.from_url(settings.redis_url)
        redis_client.ping()
        redis_status = "healthy"
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        redis_status = "unhealthy"
    
    overall_status = "healthy" if db_status == "healthy" and redis_status == "healthy" else "unhealthy"
    
    return {
        "success": True,
        "message": "Health check completed",
        "data": {
            "status": overall_status,
            "database": db_status,
            "redis": redis_status,
            "timestamp": time.time()
        }
    }

# API info endpoint
@app.get("/api/info", tags=["Info"])
async def api_info():
    """API information endpoint"""
    return {
        "success": True,
        "message": "API information",
        "data": {
            "name": APP_INFO["title"],
            "version": APP_INFO["version"],
            "description": APP_INFO["description"],
            "contact": APP_INFO["contact"],
            "endpoints": {
                "auth": "/api/v1/auth",
                "apps": "/api/v1/apps",
                "monitoring": "/api/v1/monitoring",
                "websocket": "/ws"
            },
            "features": [
                "JWT Authentication",
                "OTP Verification",
                "App Integration",
                "Real-time Monitoring",
                "Fraud Detection",
                "WebSocket Support"
            ]
        }
    }

# Catch-all for undefined routes
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(path: str):
    """Catch-all for undefined routes"""
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "message": f"Endpoint not found: /{path}",
            "data": None,
            "errors": ["The requested endpoint does not exist"]
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info"
    )