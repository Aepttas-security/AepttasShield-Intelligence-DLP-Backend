import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db

from app.models.user import User
from app.models.dlp_event import DLPEvent
from app.models.device import Device
from app.models.behavior_profile import BehaviorProfile
from app.models.behavior_anomaly import BehaviorAnomaly
from app.models.ueba_alert import UEBAAlert

from app.schemas.ueba import (
    UEBAResponse,
    UEBAProfileResponse,
    UEBASummaryResponse,
)

from app.services.ueba_engine import (
    analyze_user_behavior,
)


router = APIRouter(
    prefix="/ueba",
    tags=["UEBA"]
)


def parse_related_event_ids(raw) -> list[int]:
    """Decode the stored correlation payload into a list of event ids."""
    if not raw:
        return []

    if isinstance(raw, list):
        candidates = raw
    else:
        try:
            candidates = json.loads(raw)
        except (TypeError, ValueError):
            return []

    if not isinstance(candidates, list):
        return []

    ids = []

    for value in candidates:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue

    return ids


# ============================================================
# POST /ueba/analyze/{event_id}
# ============================================================

@router.post(
    "/analyze/{event_id}",
    response_model=UEBAResponse
)
def analyze_event_behavior(
    event_id: int,
    db: Session = Depends(get_db),
):

    # --------------------------------------------------------
    # FIND EVENT
    # --------------------------------------------------------

    event = (
        db.query(DLPEvent)
        .filter(
            DLPEvent.id == event_id
        )
        .first()
    )

    if not event:

        raise HTTPException(
            status_code=404,
            detail="DLP event not found"
        )

    user = db.query(User).filter(User.id == event.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User associated with DLP event not found")

    if event.device_id is not None:
        device = db.query(Device).filter(Device.id == event.device_id).first()
        if not device:
            raise HTTPException(status_code=409, detail="Device associated with DLP event not found")
        if device.user_id != event.user_id:
            raise HTTPException(status_code=422, detail="DLP event device does not belong to its user")

    # --------------------------------------------------------
    # RUN UEBA ENGINE
    # --------------------------------------------------------

    try:

        result = analyze_user_behavior(
            db=db,
            user_id=event.user_id,
            event_id=event.id,
        )

    except ValueError as e:

        raise HTTPException(
            status_code=404,
            detail=str(e)
        )
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="UEBA analysis could not be stored"
        )

    # Ensure newly saved anomaly records are available for alert correlation.
    db.flush()
    primary_anomaly = (
        db.query(BehaviorAnomaly)
        .filter(
            BehaviorAnomaly.user_id == event.user_id,
            BehaviorAnomaly.event_id == event.id,
        )
        .order_by(BehaviorAnomaly.anomaly_score.desc())
        .first()
    )

    # --------------------------------------------------------
    # CREATE UEBA ALERT
    # --------------------------------------------------------

    if result.behaviour_score >= 80:

        existing_alert = (
            db.query(UEBAAlert)
            .filter(
                UEBAAlert.user_id
                == event.user_id,

                UEBAAlert.status
                == "OPEN",

                UEBAAlert.alert_type
                == "CRITICAL_BEHAVIOUR",
            )
            .first()
        )

        if existing_alert:
            if primary_anomaly and existing_alert.anomaly_id is None:
                existing_alert.anomaly_id = primary_anomaly.id
        else:
            alert = UEBAAlert(
                user_id=event.user_id,
                anomaly_id=primary_anomaly.id if primary_anomaly else None,
                alert_type="CRITICAL_BEHAVIOUR",
                severity="CRITICAL",
                risk_score=result.behaviour_score,
                message=(
                    "Critical behavioural anomaly "
                    "detected. Review correlated "
                    "DLP activity."
                ),
                status="OPEN",
            )

            db.add(alert)

    elif result.behaviour_score >= 60:

        existing_alert = (
            db.query(UEBAAlert)
            .filter(
                UEBAAlert.user_id
                == event.user_id,

                UEBAAlert.status
                == "OPEN",

                UEBAAlert.alert_type
                == "HIGH_BEHAVIOUR",
            )
            .first()
        )

        if existing_alert:
            if primary_anomaly and existing_alert.anomaly_id is None:
                existing_alert.anomaly_id = primary_anomaly.id
        else:
            alert = UEBAAlert(
                user_id=event.user_id,
                anomaly_id=primary_anomaly.id if primary_anomaly else None,
                alert_type="HIGH_BEHAVIOUR",
                severity="HIGH",
                risk_score=result.behaviour_score,
                message=(
                    "High behavioural anomaly "
                    "detected. Adaptive review "
                    "may be required."
                ),
                status="OPEN",
            )

            db.add(alert)

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="UEBA results could not be committed"
        )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return UEBAResponse(

        user_id=result.user_id,

        event_id=event.id,

        behaviour_score=result.behaviour_score,

        anomaly_count=result.anomaly_count,

        anomalies=result.anomalies,

        baseline=result.baseline,

        reasons=result.reasons,
    )


# ============================================================
# GET /ueba/profile/{user_id}
# ============================================================

@router.get(
    "/profile/{user_id}",
    response_model=UEBAProfileResponse
)
def get_behavior_profile(
    user_id: int,
    db: Session = Depends(get_db),
):

    profile = (
        db.query(BehaviorProfile)
        .filter(
            BehaviorProfile.user_id
            == user_id
        )
        .first()
    )

    if not profile:

        raise HTTPException(
            status_code=404,
            detail="Behaviour profile not found"
        )

    return UEBAProfileResponse(

        user_id=profile.user_id,

        average_volume=(
            profile.average_volume or 0
        ),

        normal_start_hour=(
            profile.normal_start_hour
        ),

        normal_end_hour=(
            profile.normal_end_hour
        ),

        average_events_per_day=(
            profile.average_events_per_day
            or 0
        ),

        common_channel=(
            profile.common_channel
        ),

        common_destination=(
            profile.common_destination
        ),

        common_data_classification=(
            profile.common_data_classification
        ),

        baseline_event_count=(
            profile.baseline_event_count
            or 0
        ),
    )


# ============================================================
# GET /ueba/anomalies
# ============================================================

@router.get("/anomalies")
def get_ueba_anomalies(
    db: Session = Depends(get_db),
):

    anomalies = (
        db.query(
            BehaviorAnomaly,
            User
        )
        .join(
            User,
            User.id
            == BehaviorAnomaly.user_id
        )
        .order_by(
            BehaviorAnomaly.detected_at.desc()
        )
        .all()
    )

    # Correlated detections reference other dlp_events. Resolve them once so
    # the dashboard can replay the chain instead of showing a bare label.
    related_event_ids = set()

    for anomaly, _ in anomalies:
        for event_id in parse_related_event_ids(
            anomaly.related_event_ids
        ):
            related_event_ids.add(event_id)

    related_events = {}

    if related_event_ids:
        for event in (
            db.query(DLPEvent)
            .filter(DLPEvent.id.in_(related_event_ids))
            .all()
        ):
            related_events[event.id] = {
                "event_id": event.id,
                "event_type": event.event_type,
                "channel": event.channel,
                "destination": event.destination,
                "data_classification": (
                    event.data_classification
                ),
                "volume": event.volume,
                "severity": event.severity,
                "action_taken": event.action_taken,
                "timestamp": event.timestamp,
            }

    result = []

    for anomaly, user in anomalies:

        chain_ids = parse_related_event_ids(
            anomaly.related_event_ids
        )

        timeline = [
            related_events[event_id]
            for event_id in chain_ids
            if event_id in related_events
        ]

        result.append({
            "id": anomaly.id,
            "user_id": anomaly.user_id,
            "username": user.username,
            "department": user.department,
            "event_id": anomaly.event_id,
            "anomaly_type": anomaly.anomaly_type,
            "anomaly_score": anomaly.anomaly_score,
            "severity": anomaly.severity,
            "reason": anomaly.reason,
            "detected_at": anomaly.detected_at,

            # CHANNEL CHAINING correlation
            "correlation_id": anomaly.correlation_id,
            "related_event_ids": chain_ids,
            "correlation_window_minutes": (
                anomaly.correlation_window_minutes
            ),
            "related_events": timeline,
        })

    return result


# ============================================================
# GET /ueba/alerts
# ============================================================

@router.get("/alerts")
def get_ueba_alerts(
    db: Session = Depends(get_db),
):

    alerts = (
        db.query(
            UEBAAlert,
            User
        )
        .join(
            User,
            User.id
            == UEBAAlert.user_id
        )
        .order_by(
            UEBAAlert.created_at.desc()
        )
        .all()
    )

    result = []

    for alert, user in alerts:

        result.append({

            "id": alert.id,

            "user_id": alert.user_id,

            "username": user.username,

            "anomaly_id": alert.anomaly_id,

            "alert_type": alert.alert_type,

            "severity": alert.severity,

            "risk_score": alert.risk_score,

            "message": alert.message,

            "status": alert.status,

            "created_at": alert.created_at,
        })

    return result


# ============================================================
# GET /ueba/summary
# ============================================================

@router.get(
    "/summary",
    response_model=UEBASummaryResponse
)
def get_ueba_summary(
    db: Session = Depends(get_db),
):
    total_anomalies = db.query(func.count(BehaviorAnomaly.id)).scalar() or 0
    critical_anomalies = (
        db.query(func.count(BehaviorAnomaly.id))
        .filter(BehaviorAnomaly.severity == "CRITICAL")
        .scalar()
        or 0
    )
    high_anomalies = (
        db.query(func.count(BehaviorAnomaly.id))
        .filter(BehaviorAnomaly.severity == "HIGH")
        .scalar()
        or 0
    )
    total_alerts = db.query(func.count(UEBAAlert.id)).scalar() or 0
    total_profiles = db.query(func.count(BehaviorProfile.id)).scalar() or 0
    avg_score = (
        db.query(func.avg(BehaviorAnomaly.anomaly_score)).scalar()
        or 0.0
    )

    return UEBASummaryResponse(
        total_anomalies=total_anomalies,
        critical_anomalies=critical_anomalies,
        high_anomalies=high_anomalies,
        total_alerts=total_alerts,
        total_profiles=total_profiles,
        average_behaviour_score=round(float(avg_score), 2),
    )


# ============================================================
# GET /ueba/profiles
# ============================================================

@router.get("/profiles")
def get_all_behavior_profiles(
    db: Session = Depends(get_db),
):
    profiles = (
        db.query(BehaviorProfile, User)
        .join(User, User.id == BehaviorProfile.user_id)
        .order_by(BehaviorProfile.updated_at.desc())
        .all()
    )

    return [
        {
            "id": profile.id,
            "user_id": profile.user_id,
            "username": user.username,
            "department": user.department,
            "average_volume": round(float(profile.average_volume or 0), 2),
            "normal_start_hour": profile.normal_start_hour,
            "normal_end_hour": profile.normal_end_hour,
            "average_events_per_day": round(float(profile.average_events_per_day or 0), 2),
            "common_channel": profile.common_channel,
            "common_destination": profile.common_destination,
            "common_data_classification": profile.common_data_classification,
            "baseline_event_count": profile.baseline_event_count or 0,
            "updated_at": profile.updated_at,
        }
        for profile, user in profiles
    ]


# ============================================================
# POST /ueba/process-all
# ============================================================

@router.post("/process-all")
def process_all_ueba(
    db: Session = Depends(get_db),
):
    events = (
        db.query(DLPEvent)
        .order_by(DLPEvent.timestamp.asc(), DLPEvent.id.asc())
        .all()
    )

    results = []
    for event in events:
        try:
            res = analyze_event_behavior(
                event_id=event.id,
                db=db,
            )
            results.append({
                "event_id": event.id,
                "behaviour_score": res.behaviour_score,
                "anomaly_count": res.anomaly_count,
            })
        except Exception as e:
            results.append({
                "event_id": event.id,
                "error": str(e),
            })

    return {
        "status": "success",
        "total_events": len(events),
        "analyzed_count": len([r for r in results if "error" not in r]),
        "results": results,
    }
