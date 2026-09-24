from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class RunScanRequest(BaseModel):
    moduleId: str
    subtopicId: str
    textInput: Optional[str] = None
    urlInput: Optional[str] = None
    fileId: Optional[str] = None
    extraFieldValues: Optional[Dict[str, str]] = None


class DetectedIndicatorOut(BaseModel):
    id: str
    label: str
    description: str
    severity: str
    weight: float
    triggered: bool


class AnalysisResultOut(BaseModel):
    scanId: str
    moduleId: str
    subtopicId: str
    subtopicTitle: str
    target: str
    targetType: str
    riskScore: int
    classification: str
    confidenceScore: int
    detectionTime: str
    analysisEngine: str
    threatType: str
    severity: str
    indicators: List[DetectedIndicatorOut]
    explanation: str
    recommendations: List[str]
    status: str
