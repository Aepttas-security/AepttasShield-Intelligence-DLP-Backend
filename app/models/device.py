from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
)

from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    device_name = Column(
        String,
        nullable=False
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    device_type = Column(
        String
    )

    # TRUSTED / UNKNOWN / UNTRUSTED
    trust_level = Column(
        String,
        default="UNKNOWN"
    )

    # Corporate-managed device
    is_managed = Column(
        Boolean,
        default=False
    )