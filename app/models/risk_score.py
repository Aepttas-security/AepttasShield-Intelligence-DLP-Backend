from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    Integer,
    String,
    Text,
)

from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    incident_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    department: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    data_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    classification: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    detection_rule: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    action: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    channel: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    destination: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    number_of_violations: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    previous_violations: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    # ==========================================
    # RULEBOOK RISK FACTORS
    # ==========================================

    data_sensitivity_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    destination_trust_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    user_risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    device_trust_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    behaviour_anomaly_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    transfer_volume_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    channel_risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    # Kept for compatibility with your existing dashboard/database
    severity_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    frequency_risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    # ==========================================
    # FINAL SCORE
    # ==========================================

    total_risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
        index=True,
    )

    # MONITOR / WARN / JUSTIFY / BLOCK / CRITICAL
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Recommended action from the rulebook
    risk_action: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    risk_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        index=True,
    )