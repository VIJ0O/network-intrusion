"""
Predictions router — Returns the latest AI threat forecasts and trend analysis.
"""

from fastapi import APIRouter
from models.schemas import PredictionResult
from services.ai_engine import ai_engine

router = APIRouter(prefix="/api/predictions", tags=["Predictions"])


@router.get("", response_model=PredictionResult)
async def ai_predictions():
    """Get active threat probabilities and forecasting intervals computed by PyTorch."""
    return PredictionResult(**ai_engine.latest_result)
