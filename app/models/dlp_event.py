from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
)
from sqlalchemy.sql import func

from app.core.database import Base


class DLPEvent(Base):
    __tablename__ = "dlp_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    device_id = Column(
        Integer,
        ForeignKey("devices.id"),
        nullable=True
    )

    policy_id = Column(
        Integer,
        ForeignKey("policies.id"),
        nullable=True
    )

    event_type = Column(
        String,
        nullable=False
    )

    data_classification = Column(
        String,
        nullable=False
    )

    channel = Column(
        String,
        nullable=False
    )

    destination = Column(
        String,
        nullable=True
    )

    # Amount of data transferred/accessed
    volume = Column(
        Float,
        default=0
    )

    severity = Column(
        String
    )

    action_taken = Column(
        String
    )

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )