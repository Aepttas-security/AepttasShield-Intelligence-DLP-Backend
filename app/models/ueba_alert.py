from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
    Text,
)

from app.core.database import Base


class UEBAAlert(Base):

    __tablename__ = "ueba_alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    anomaly_id = Column(
        Integer,
        ForeignKey("behavior_anomalies.id"),
        nullable=True,
        index=True
    )

    alert_type = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        default="MEDIUM"
    )

    risk_score = Column(
        Float,
        default=0
    )

    message = Column(
        Text,
        nullable=True
    )

    status = Column(
        String,
        default="OPEN"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )