from typing import Any, Dict, Optional
from fastapi import APIRouter
from pydantic import BaseModel

from app.detectors.ml.analyzer import ml_url_analyzer

router = APIRouter(prefix="/health", tags=["Health"])


class MLHealthResponse(BaseModel):
    available: bool
    status: str
    threshold: Optional[float] = None


@router.get("/ml", response_model=MLHealthResponse)
def get_ml_health() -> Dict[str, Any]:
    """Provides operational readiness and status diagnostics for the ML URL model."""
    return {
        "available": ml_url_analyzer.is_available,
        "status": ml_url_analyzer.status_reason,
        "threshold": ml_url_analyzer.threshold if ml_url_analyzer.is_available else None,
    }