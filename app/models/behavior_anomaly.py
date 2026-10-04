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


class BehaviorAnomaly(Base):

    __tablename__ = "behavior_anomalies"

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

    event_id = Column(
        Integer,
        ForeignKey("dlp_events.id"),
        nullable=True,
        index=True
    )

    anomaly_type = Column(
        String,
        nullable=False
    )

    anomaly_score = Column(
        Float,
        default=0
    )

    severity = Column(
        String,
        default="LOW"
    )

    reason = Column(
        Text,
        nullable=True
    )

    # ==========================================
    # CHANNEL CHAINING CORRELATION
    # ==========================================

    # Stable identifier shared by every anomaly that belongs to the
    # same correlated transfer chain, so the sequence can be replayed.
    correlation_id = Column(
        String(100),
        nullable=True,
        index=True
    )

    # JSON array of the correlated dlp_events ids, in chronological order.
    related_event_ids = Column(
        Text,
        nullable=True
    )

    # Length of the correlation window that produced the chain.
    correlation_window_minutes = Column(
        Integer,
        nullable=True
    )

    detected_at = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )