from typing import Optional

from pydantic import BaseModel


class RiskCalculateRequest(BaseModel):

    incident_id: int
    user_id: int

    department: Optional[str] = None

    data_type: Optional[str] = None

    classification: str

    detection_rule: Optional[str] = None

    action: Optional[str] = None

    channel: str

    destination: str

    severity: str = "low"

    previous_violations: int = 0

    number_of_violations: int = 0

    volume: float = 0

    device_trust: str = "UNKNOWN"

    is_managed_device: bool = False

    behaviour_anomaly_score: Optional[float] = None


class RiskCalculateResponse(BaseModel):

    incident_id: int

    risk_score: float

    risk_level: str

    risk_action: str

    factors: dict

    reasons: list[str]


class RiskSummaryResponse(BaseModel):

    total_incidents: int

    active_incidents: int

    average_risk_score: float

    maximum_risk_score: float

    critical: int

    high: int

    medium: int

    low: int

    risk_bands: dict[str, str]

    security_posture: Optional[float] = None

    protected_endpoints: Optional[int] = None

    genai_blocks: Optional[int] = None
