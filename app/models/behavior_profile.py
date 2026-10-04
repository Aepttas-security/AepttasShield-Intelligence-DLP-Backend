from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
)

from app.core.database import Base


class BehaviorProfile(Base):

    __tablename__ = "behavior_profiles"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False,
        unique=True,
        index=True
    )

    # Normal activity statistics

    average_volume = Column(
        Float,
        default=0
    )

    normal_start_hour = Column(
        Integer,
        default=9
    )

    normal_end_hour = Column(
        Integer,
        default=18
    )

    average_events_per_day = Column(
        Float,
        default=0
    )

    # Common behaviour

    common_channel = Column(
        String,
        nullable=True
    )

    common_destination = Column(
        String,
        nullable=True
    )

    common_data_classification = Column(
        String,
        nullable=True
    )

    # Number of events used to create baseline

    baseline_event_count = Column(
        Integer,
        default=0
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )