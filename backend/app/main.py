from fastapi import FastAPI
from app.api.v1.endpoints.analysis import router as analysis_router
from app.api.v1.endpoints.health import router as health_router
from app.middleware.request_size import LimitPayloadSizeMiddleware

app = FastAPI(
    title="AI-Based Phishing Detection and Awareness System",
    description="Backend API for email phishing risk assessment and explainable security guidance.",
    version="0.1.0",
)

# Register request size protection middleware (250 KB ceiling)
app.add_middleware(LimitPayloadSizeMiddleware)

# Register API v1 routes
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Health check endpoint to verify that the service is running."""
    return {"status": "ok"}