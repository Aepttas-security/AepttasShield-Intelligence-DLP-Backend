from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
    Text,
)
from sqlalchemy.sql import func

from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    event_id = Column(
        Integer,
        ForeignKey("dlp_events.id")
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id")
    )

    title = Column(
        String,
        nullable=False
    )

    severity = Column(
        String
    )

    risk_score = Column(
        Float
    )

    description = Column(
        Text
    )

    status = Column(
        String,
        default="OPEN"
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    resolved_at = Column(
        DateTime(timezone=True)
    )