from fastapi import APIRouter, status
from app.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.analysis_service import analysis_service

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious email content",
    description="Accepts email headers, content, URLs, and optional authentication signals for phishing evaluation.",
)
def analyze_email(request: AnalysisRequest) -> AnalysisResponse:
    """Delegates request to the analysis service layer."""
    return analysis_service.analyze_email(request)