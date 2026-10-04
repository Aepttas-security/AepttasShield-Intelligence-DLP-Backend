from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)

from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    risk_score_id: Mapped[int] = mapped_column(
        ForeignKey(
            "risk_scores.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True,
    )

    factor_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    factor_value: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    factor_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    # Rulebook supports configurable weights
    weight: Mapped[float] = mapped_column(
        Float,
        default=1,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )