from pydantic import BaseModel
from typing import Optional


class UEBAAnomalyResponse(BaseModel):

    type: str

    score: float

    reason: str

    # Present for correlated detections such as CHANNEL_CHAINING.
    correlation: Optional[dict] = None


class UEBAResponse(BaseModel):

    user_id: int

    event_id: int

    behaviour_score: float

    anomaly_count: int

    anomalies: list[UEBAAnomalyResponse]

    baseline: dict

    reasons: list[str]


class UEBAProfileResponse(BaseModel):

    user_id: int

    average_volume: float

    normal_start_hour: int

    normal_end_hour: int

    average_events_per_day: float

    common_channel: Optional[str] = None

    common_destination: Optional[str] = None

    common_data_classification: Optional[str] = None

    baseline_event_count: int


class UEBASummaryResponse(BaseModel):

    total_anomalies: int
    critical_anomalies: int
    high_anomalies: int
    total_alerts: int
    total_profiles: int
    average_behaviour_score: float
