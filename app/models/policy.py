from sqlalchemy import Column, Integer, String, Boolean, Float
from app.core.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)

    policy_name = Column(String, nullable=False)

    # Data condition
    data_classification = Column(
        String,
        nullable=False
    )

    # Transfer channel
    channel = Column(
        String,
        nullable=False
    )

    # Destination condition
    destination_type = Column(String)

    # Policy severity
    severity = Column(String)

    # Enforcement action
    action = Column(
        String,
        nullable=False
    )

    # Whether policy is currently enabled
    is_active = Column(
        Boolean,
        default=True
    )

    # Higher priority = evaluated first
    priority = Column(
        Integer,
        default=100,
        nullable=False
    )

    # Optional context conditions
    minimum_risk_score = Column(
        Float,
        default=0
    )

    minimum_volume = Column(
        Float,
        default=0
    )

    required_device_trust = Column(
        String,
        default=None
    )

    # Optional policy description
    description = Column(
        String,
        nullable=True
    )