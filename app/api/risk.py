import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.core.database import get_db

from app.models.dlp_event import DLPEvent
from app.models.user import User
from app.models.device import Device
from app.models.policy import Policy
from app.models.incident import Incident
from app.models.risk_score import RiskScore
from app.models.risk_factor import RiskFactor
from app.models.risk_alert import RiskAlert
from app.services.risk_engine import (
    RISK_BANDS,
    ENFORCEMENT_LEVELS,
    calculate_risk,
    classify_risk,
    classify_risk_level,
    factor_definitions,
    action_bands,
    enforcement_level,
)
from app.services.policy_engine import evaluate_policy
from app.services.ueba_engine import analyze_user_behavior
from app.schemas.risk import (
    RiskCalculateRequest,
    RiskCalculateResponse,
    RiskSummaryResponse,
)



router = APIRouter(
    prefix="/risk",
    tags=["Risk Analytics"]
)

ACTIVE_INCIDENT_STATUSES = (
    "OPEN",
    "ACTIVE",
    "OPENED",
    "IN_PROGRESS",
    "PENDING",
)


def normalized_risk(score) -> tuple[str, str]:
    numeric_score = float(score or 0)
    return classify_risk_level(numeric_score), classify_risk(numeric_score)[1]


def effective_risk_level(score: RiskScore) -> str:
    """Stored risk_level, falling back to the band when it was never stored."""
    return score.risk_level or classify_risk_level(
        float(score.total_risk_score or 0)
    )


def effective_risk_action(score: RiskScore) -> str:
    """The action that was actually stored at enforcement time.

    risk_action may come from the matched policy rather than the score band
    (see /risk/calculate-from-event), so it must be read back from the record
    instead of being recomputed from the score.
    """
    return score.risk_action or classify_risk(
        float(score.total_risk_score or 0)
    )[1]



# HELPER: CREATE RISK FACTORS


def create_risk_factors(
    db: Session,
    risk_score_id: int,
    result,
    classification: str,
    destination: str,
    device_trust: str,
    volume: float,
    channel: str,
):
    factors = [

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="data_sensitivity",
            factor_value=classification,
            factor_score=result.data_sensitivity_score,
            weight=0.20,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="destination_trust",
            factor_value=destination,
            factor_score=result.destination_trust_score,
            weight=0.15,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="user_risk",
            factor_value="previous violations",
            factor_score=result.user_risk_score,
            weight=0.15,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="device_trust",
            factor_value=device_trust,
            factor_score=result.device_trust_score,
            weight=0.10,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="behaviour_anomaly",
            factor_value="behaviour deviation",
            factor_score=result.behaviour_anomaly_score,
            weight=0.15,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="transfer_volume",
            factor_value=str(volume),
            factor_score=result.transfer_volume_score,
            weight=0.15,
        ),

        RiskFactor(
            risk_score_id=risk_score_id,
            factor_name="channel_risk",
            factor_value=channel,
            factor_score=result.channel_risk_score,
            weight=0.10,
        ),
    ]

    db.add_all(factors)



# HELPER: CREATE ALERT


def create_alert_if_required(
    db: Session,
    risk_score: RiskScore,
    user_id: int,
):

    if risk_score.total_risk_score < 60:
        return

    if risk_score.total_risk_score >= 80:

        alert_type = "CRITICAL_RISK"

        severity = "CRITICAL"

        message = (
            f"Critical risk detected for user {user_id}. "
            f"Risk score: {risk_score.total_risk_score}. "
            f"Action: BLOCK + INCIDENT + AUTOMATED RESPONSE."
        )

    else:

        alert_type = "HIGH_RISK"

        severity = "HIGH"

        message = (
            f"High risk detected for user {user_id}. "
            f"Risk score: {risk_score.total_risk_score}. "
            f"Action: BLOCK / ADAPTIVE CHALLENGE."
        )

    existing_alert = (
        db.query(RiskAlert)
        .filter(
            RiskAlert.user_id == user_id,
            RiskAlert.alert_type == alert_type,
            RiskAlert.status == "OPEN",
        )
        .first()
    )

    if existing_alert:
        return

    alert = RiskAlert(
        risk_score_id=risk_score.id,
        user_id=user_id,
        alert_type=alert_type,
        message=message,
        severity=severity,
        status="OPEN",
    )

    db.add(alert)



# POST /risk/calculate


@router.post(
    "/calculate",
    response_model=RiskCalculateResponse
)
def calculate_manual_risk(
    request: RiskCalculateRequest,
    db: Session = Depends(get_db),
):

    result = calculate_risk(
        classification=request.classification,
        severity=request.severity,
        previous_violations=request.previous_violations,
        channel=request.channel,
        destination=request.destination,
        number_of_violations=request.number_of_violations,
        volume=request.volume,
        device_trust=request.device_trust,
        is_managed_device=request.is_managed_device,
    )

    risk_score = RiskScore(
        incident_id=request.incident_id,
        user_id=request.user_id,
        department=(
            db.query(User.department)
            .filter(User.id == request.user_id)
            .scalar()
        ),
        data_type=request.data_type,
        classification=request.classification,
        detection_rule=request.detection_rule,
        action=request.action,
        channel=request.channel,
        destination=request.destination,
        severity=request.severity,

        number_of_violations=request.number_of_violations,
        previous_violations=request.previous_violations,

        data_sensitivity_score=result.data_sensitivity_score,
        destination_trust_score=result.destination_trust_score,
        user_risk_score=result.user_risk_score,
        device_trust_score=result.device_trust_score,
        behaviour_anomaly_score=result.behaviour_anomaly_score,
        transfer_volume_score=result.transfer_volume_score,
        channel_risk_score=result.channel_risk_score,

        severity_score=result.severity_score,
        frequency_risk_score=result.frequency_risk_score,

        total_risk_score=result.total_risk_score,
        risk_level=result.risk_level,
        risk_action=result.risk_action,
        risk_reason=json.dumps(result.reasons),
    )

    db.add(risk_score)

    db.flush()

    create_risk_factors(
        db=db,
        risk_score_id=risk_score.id,
        result=result,
        classification=request.classification,
        destination=request.destination,
        device_trust=request.device_trust,
        volume=request.volume,
        channel=request.channel,
    )

    create_alert_if_required(
        db=db,
        risk_score=risk_score,
        user_id=request.user_id,
    )

    db.commit()

    return RiskCalculateResponse(
        incident_id=request.incident_id,
        risk_score=result.total_risk_score,
        risk_level=result.risk_level,
        risk_action=result.risk_action,
        factors={
            "data_sensitivity": result.data_sensitivity_score,
            "destination_trust": result.destination_trust_score,
            "user_risk": result.user_risk_score,
            "device_trust": result.device_trust_score,
            "behaviour_anomaly": result.behaviour_anomaly_score,
            "transfer_volume": result.transfer_volume_score,
            "channel_risk": result.channel_risk_score,
        },
        reasons=result.reasons,
    )



# POST /risk/calculate-from-event/{event_id}


@router.post(
    "/calculate-from-event/{event_id}"
)
def calculate_risk_from_event(
    event_id: int,
    db: Session = Depends(get_db),
):

    event = (
        db.query(DLPEvent)
        .filter(DLPEvent.id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="DLP event not found"
        )

    user = (
        db.query(User)
        .filter(User.id == event.user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    
    # UEBA ANALYSIS
   

    ueba_result = analyze_user_behavior(
        db= db,
        user_id= event.user_id,
        event_id= event.id,
    )

    behaviour_anomaly_score = (
        ueba_result.behaviour_score
    )

    
    # DEVICE
    

    device = None

    if event.device_id:

        device = (
            db.query(Device)
            .filter(Device.id == event.device_id)
            .first()
        )
        if not device:
            raise HTTPException(
                status_code=409,
                detail="Device associated with DLP event not found",
            )
        if device.user_id != event.user_id:
            raise HTTPException(
                status_code=422,
                detail="DLP event device does not belong to its user",
            )

    device_trust = (
        device.trust_level
        if device
        else "UNKNOWN"
    )

    is_managed_device = (
        device.is_managed
        if device
        else False
    )

    
    # INCIDENT
    

    incident = (
        db.query(Incident)
        .filter(
            Incident.event_id == event.id
        )
        .first()
    )

    if not incident:

        incident = Incident(
            event_id=event.id,
            user_id=event.user_id,
            title=(
                f"DLP incident: "
                f"{event.event_type}"
            ),
            severity=event.severity or "LOW",
            description=(
                f"DLP event detected through "
                f"{event.channel}."
            ),
            status="OPEN",
        )

        db.add(incident)

        db.flush()

    
    # PREVIOUS USER VIOLATIONS
    

    previous_violations = (
        db.query(func.count(Incident.id))
        .filter(
            Incident.user_id == event.user_id,
            Incident.id != incident.id,
        )
        .scalar()
        or 0
    )

    
    # USER EVENT FREQUENCY
    

    number_of_violations = (
        db.query(func.count(DLPEvent.id))
        .filter(
            DLPEvent.user_id == event.user_id
        )
        .scalar()
        or 0
    )

    
    # POLICY EVALUATION
    

    policies = (
        db.query(Policy)
        .filter(
            Policy.is_active == True
        )
        .order_by(
            Policy.priority.asc()
        )
        .all()
    )

    policy_decision = evaluate_policy(
        event,
        policies
    )

    
    # USE POLICY WHEN AVAILABLE
    

    detection_rule = (
        policy_decision.policy_name
        if policy_decision.matched
        else "NO_MATCHING_POLICY"
    )

    policy_action = policy_decision.action

    
    # RISK CALCULATION
    

    result = calculate_risk(
    classification=event.data_classification,
    severity=event.severity or "low",
    previous_violations=previous_violations,
    channel=event.channel,
    destination=event.destination or "unknown",
    number_of_violations=number_of_violations,
    volume=event.volume or 0,
    device_trust=device_trust,
    is_managed_device=is_managed_device,
    behaviour_anomaly_score=behaviour_anomaly_score,
    )

    
    # POLICY ACTION HAS PRIORITY
    

    final_action = policy_action

    if not policy_decision.matched:

        final_action = result.risk_action

    elif result.total_risk_score >= 80:

        final_action = (
            "BLOCK + INCIDENT + AUTOMATED RESPONSE"
        )

    elif result.total_risk_score >= 60:

        final_action = (
            "BLOCK / ADAPTIVE CHALLENGE"
        )

    
    # CREATE RISK SCORE
   
    risk_score = RiskScore(
        incident_id=incident.id,
        user_id=event.user_id,
        department=user.department,

        data_type=event.event_type,

        classification=event.data_classification,

        detection_rule=detection_rule,

        action=final_action,

        channel=event.channel,

        destination=event.destination,

        severity=event.severity,

        number_of_violations=number_of_violations,

        previous_violations=previous_violations,

        data_sensitivity_score=result.data_sensitivity_score,

        destination_trust_score=result.destination_trust_score,

        user_risk_score=result.user_risk_score,

        device_trust_score=result.device_trust_score,

        behaviour_anomaly_score=result.behaviour_anomaly_score,

        transfer_volume_score=result.transfer_volume_score,

        channel_risk_score=result.channel_risk_score,

        severity_score=result.severity_score,

        frequency_risk_score=result.frequency_risk_score,

        total_risk_score=result.total_risk_score,

        risk_level=result.risk_level,

        risk_action=final_action,

        risk_reason=json.dumps(
            result.reasons
        ),
    )

    db.add(risk_score)

    db.flush()

    
    # RISK FACTORS
    

    create_risk_factors(
        db=db,
        risk_score_id=risk_score.id,
        result=result,
        classification=event.data_classification,
        destination=event.destination or "unknown",
        device_trust=device_trust,
        volume=event.volume or 0,
        channel=event.channel,
    )

    
    # UPDATE INCIDENT
    

    incident.risk_score = (
        result.total_risk_score
    )

    # Critical risk automatically escalates incident
    if result.total_risk_score >= 80:

        incident.severity = "CRITICAL"

    elif result.total_risk_score >= 60:

        incident.severity = "HIGH"

    
    # UPDATE USER RISK
    

    user.current_risk_score = (
        result.total_risk_score
    )

    
    # ALERT
    

    create_alert_if_required(
        db=db,
        risk_score=risk_score,
        user_id=event.user_id,
    )

    db.commit()

    return {
        "event_id": event.id,
        "incident_id": incident.id,
        "policy_id": policy_decision.policy_id,
        "policy": policy_decision.policy_name,
        "policy_matched": policy_decision.matched,
        "policy_reason": policy_decision.reason,
        "risk_score": result.total_risk_score,
        "risk_level": result.risk_level,
        "risk_action": final_action,
    
    # UEBA RESULTS
    
    "ueba": {
        "behaviour_score": ueba_result.behaviour_score,
        "anomaly_count": ueba_result.anomaly_count,
        "anomalies": ueba_result.anomalies,
        "reasons": ueba_result.reasons,
    },

    
    # RISK FACTORS
    
    "factors": {
        "data_sensitivity": result.data_sensitivity_score,
        "destination_trust": result.destination_trust_score,
        "user_risk": result.user_risk_score,
        "device_trust": result.device_trust_score,
        "behaviour_anomaly": result.behaviour_anomaly_score,
        "transfer_volume": result.transfer_volume_score,
        "channel_risk": result.channel_risk_score,
    },

    "reasons": result.reasons,
}



# GET /risk/summary


@router.get(
    "/summary",
    response_model=RiskSummaryResponse
)
def risk_summary(
    db: Session = Depends(get_db)
):

    total = (
        db.query(func.count(func.distinct(RiskScore.incident_id)))
        .join(User, User.id == RiskScore.user_id)
        .scalar()
        or 0
    )

    active_incidents = (
        db.query(func.count(Incident.id))
        .join(User, User.id == Incident.user_id)
        .filter(
            func.upper(func.coalesce(Incident.status, "OPEN")).in_(
                ["OPEN", "ACTIVE", "OPENED", "IN_PROGRESS", "PENDING"]
            )
        )
        .scalar()
        or 0
    )

    average = (
        db.query(
            func.avg(
                RiskScore.total_risk_score
            )
        )
        .join(User, User.id == RiskScore.user_id)
        .scalar()
        or 0
    )

    maximum = (
        db.query(func.max(RiskScore.total_risk_score))
        .join(User, User.id == RiskScore.user_id)
        .scalar()
        or 0
    )

    critical = (
        db.query(func.count(RiskScore.id))
        .join(User, User.id == RiskScore.user_id)
        .filter(
            RiskScore.risk_level == "CRITICAL"
        )
        .scalar()
        or 0
    )

    high = (
        db.query(func.count(RiskScore.id))
        .join(User, User.id == RiskScore.user_id)
        .filter(
            RiskScore.total_risk_score.between(60, 79.999999)
        )
        .scalar()
        or 0
    )

    medium = (
        db.query(func.count(RiskScore.id))
        .join(User, User.id == RiskScore.user_id)
        .filter(
            RiskScore.total_risk_score.between(30, 59.999999)
        )
        .scalar()
        or 0
    )

    low = (
        db.query(func.count(RiskScore.id))
        .join(User, User.id == RiskScore.user_id)
        .filter(
            RiskScore.total_risk_score < 30
        )
        .scalar()
        or 0
    )

    return RiskSummaryResponse(
        total_incidents=total,
        active_incidents=active_incidents,
        average_risk_score=round(
            float(average),
            2
        ),
        maximum_risk_score=round(float(maximum), 2),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        risk_bands=RISK_BANDS,
    )



# GET /risk/incidents


@router.get("/incidents")
def risk_incidents(
    db: Session = Depends(get_db)
):

    scores = (
        db.query(RiskScore, Incident, User)
        .join(Incident, Incident.id == RiskScore.incident_id)
        .join(User, User.id == RiskScore.user_id)
        .order_by(
            RiskScore.created_at.desc()
        )
        .all()
    )

    result = []
    seen_incidents = set()

    for score, incident, user in scores:
        if incident.id in seen_incidents:
            continue
        seen_incidents.add(incident.id)
        result.append(
            {
                "incident_id": score.incident_id,
                "user_id": score.user_id,
                "username": user.username,
                "department": user.department,
                "title": incident.title,
                "status": incident.status or "OPEN",
                "created_at": incident.created_at,
                "risk_score": score.total_risk_score,
                "risk_level": effective_risk_level(score),
                "risk_action": effective_risk_action(score),
                "enforcement_level": enforcement_level(
                    effective_risk_action(score)
                ),
                "severity": incident.severity or score.severity,
                "channel": score.channel,
                "destination": score.destination,
            }
        )

    return result



# GET /risk/users


@router.get("/users")
def risk_users(
    db: Session = Depends(get_db)
):

    rows = (
        db.query(
            RiskScore.user_id,
            User.username,
            User.department,
            func.count(RiskScore.id).label(
                "incident_count"
            ),
            func.sum(
                RiskScore.number_of_violations
            ).label(
                "total_violations"
            ),
            func.avg(
                RiskScore.total_risk_score
            ).label(
                "average_risk"
            ),
            func.max(
                RiskScore.total_risk_score
            ).label(
                "max_risk"
            ),
        )
        .join(User, User.id == RiskScore.user_id)
        .group_by(RiskScore.user_id, User.username, User.department)
        .all()
    )

    result = []

    for row in rows:

        average = float(
            row.average_risk or 0
        )

        level = normalized_risk(average)[0]
        action = normalized_risk(average)[1]

        result.append(
            {
                "user_id": row.user_id,
                "username": row.username,
                "department": row.department,
                "incident_count": row.incident_count,
                "total_violations": row.total_violations or 0,
                "average_risk": round(
                    average,
                    2
                ),
                "max_risk": round(
                    float(row.max_risk or 0),
                    2
                ),
                "risk_level": level,
                "risk_action": action,
            }
        )

    return result



# GET /risk/departments


@router.get("/departments")
def risk_departments(
    db: Session = Depends(get_db)
):

    rows = (
        db.query(
            User.department,
            func.count(RiskScore.id).label(
                "score_count"
            ),
            func.count(
                func.distinct(
                    RiskScore.incident_id
                )
            ).label(
                "incident_count"
            ),
            func.avg(
                RiskScore.total_risk_score
            ).label(
                "average_risk"
            ),
            func.max(
                RiskScore.total_risk_score
            ).label (
                "max_risk"
            ),
        )
        .join(User, User.id == RiskScore.user_id)
        .filter(
            User.department.isnot(None),
            func.lower(User.department) != "string",
        )
        .group_by(User.department)
        .all()
    )

    result = []

    for row in rows:

        average = float(
            row.average_risk or 0
        )

        level = normalized_risk(average)[0]
        action = normalized_risk(average)[1]

        result.append(
            {
                "department": row.department,
                "incident_count": row.incident_count,
                "risk_score_evaluations": row.score_count,
                "average_risk": round(
                    average,
                    2
                ),
                "max_risk": round(
                    float(row.max_risk or 0),
                    2
                ),
                "risk_level": level,
                "risk_action": action,
            }
        )

    return result



# GET /risk/high-risk-users


@router.get("/high-risk-users")
def high_risk_users(
    db: Session = Depends(get_db)
):

    rows = (
        db.query(
            RiskScore.user_id,
            User.username,
            User.department,
            func.avg(
                RiskScore.total_risk_score
            ).label("average_risk"),
            func.max(
                RiskScore.total_risk_score
            ).label("max_risk"),
            func.count(RiskScore.id).label("score_count"),
            func.count(
                func.distinct(
                    RiskScore.incident_id
                )
            ).label("incident_count"),
        )
        .join(User, User.id == RiskScore.user_id)
        .group_by(RiskScore.user_id, User.username, User.department)
        .having(
            func.avg(
                RiskScore.total_risk_score
            ) >= 60
        )
        .all()
    )

    return [
        {
            "user_id": row.user_id,
            "username": row.username,
            "department": row.department,
            "average_risk": round(
                float(row.average_risk or 0),
                2
            ),
            "max_risk": round(
                float(row.max_risk or 0),
                2
            ),
            "incident_count": row.incident_count,
            "risk_score_evaluations": row.score_count,
            "risk_level": normalized_risk(row.average_risk)[0],
            "risk_action": normalized_risk(row.average_risk)[1],
        }
        for row in rows
    ]



# GET /risk/alerts


@router.get("/alerts")
def risk_alerts(
    db: Session = Depends(get_db)
):

    alerts = (
        db.query(RiskAlert, RiskScore)
        .join(RiskScore, RiskScore.id == RiskAlert.risk_score_id)
        .order_by(
            RiskAlert.created_at.desc()
        )
        .all()
    )

    result = []
    seen_active = set()

    for alert, score in alerts:
        dedupe_key = (alert.user_id, alert.alert_type, alert.status)
        if alert.status == "OPEN" and dedupe_key in seen_active:
            continue
        if alert.status == "OPEN":
            seen_active.add(dedupe_key)

        result.append(
            {
                "id": alert.id,
                "risk_score_id": alert.risk_score_id,
                "user_id": alert.user_id,
                "alert_type": alert.alert_type,
                "risk_level": effective_risk_level(score),
                "risk_action": effective_risk_action(score),
                "enforcement_level": enforcement_level(
                    effective_risk_action(score)
                ),
                "total_risk_score": score.total_risk_score,
                "message": alert.message,
                "severity": alert.severity,
                "status": alert.status,
                "created_at": alert.created_at,
            }
        )

    return result



# GET /risk/scores


@router.get("/scores")
def risk_scores(
    db: Session = Depends(get_db)
):

    scores = (
        db.query(
            RiskScore,
            User,
            Incident,
            DLPEvent,
            Device,
        )
        .join(User, User.id == RiskScore.user_id)
        .outerjoin(
            Incident,
            Incident.id == RiskScore.incident_id
        )
        .outerjoin(
            DLPEvent,
            DLPEvent.id == Incident.event_id
        )
        .outerjoin(
            Device,
            Device.id == DLPEvent.device_id
        )
        .order_by(
            RiskScore.created_at.desc()
        )
        .all()
    )

    return [
        {
            "id": score.id,
            "incident_id": score.incident_id,
            "user_id": score.user_id,
            "username": user.username if user else None,
            "department": (
                user.department if user else score.department
            ),
            "data_type": score.data_type,
            "classification": score.classification,
            "detection_rule": score.detection_rule,
            "action": score.action,
            "risk_action": effective_risk_action(score),
            "channel": score.channel,
            "destination": score.destination,
            "severity": score.severity,

            "number_of_violations":
                score.number_of_violations,

            "previous_violations":
                score.previous_violations,

            "data_sensitivity_score":
                score.data_sensitivity_score,

            "destination_trust_score":
                score.destination_trust_score,

            "user_risk_score":
                score.user_risk_score,

            "device_trust_score":
                score.device_trust_score,

            "behaviour_anomaly_score":
                score.behaviour_anomaly_score,

            "transfer_volume_score":
                score.transfer_volume_score,

            "channel_risk_score":
                score.channel_risk_score,

            "severity_score":
                score.severity_score,

            "frequency_risk_score":
                score.frequency_risk_score,

            "total_risk_score":
                score.total_risk_score,

            "risk_level":
                effective_risk_level(score),

            "enforcement_level": enforcement_level(
                effective_risk_action(score)
            ),

            # Every calculated factor, including the supporting
            # severity and frequency scores.
            "factors": {
                "data_sensitivity": score.data_sensitivity_score,
                "destination_trust": score.destination_trust_score,
                "user_risk": score.user_risk_score,
                "device_trust": score.device_trust_score,
                "behaviour_anomaly": score.behaviour_anomaly_score,
                "transfer_volume": score.transfer_volume_score,
                "channel_risk": score.channel_risk_score,
                "severity": score.severity_score,
                "frequency": score.frequency_risk_score,
            },

            "risk_reason":
                score.risk_reason,

            "created_at":
                score.created_at,

            #
            # AUDIT / EVIDENCE CONTEXT
            
            # Traceability only: metadata and detector results, never the
            # inspected payload itself.
            "event_id": (
                event.id if event else None
            ),
            "event_type": (
                event.event_type if event else None
            ),
            "volume": (
                event.volume if event else None
            ),
            "event_action": (
                event.action_taken if event else None
            ),
            "event_timestamp": (
                event.timestamp if event else None
            ),
            "device_id": (
                device.id if device else None
            ),
            "device_name": (
                device.device_name if device else None
            ),
            "device_trust": (
                device.trust_level if device else None
            ),
            "device_managed": (
                device.is_managed if device else None
            ),
            "incident_status": (
                incident.status if incident else None
            ),
            "incident_severity": (
                incident.severity if incident else None
            ),
            "incident_created_at": (
                incident.created_at if incident else None
            ),
        }
        for score, user, incident, event, device in scores
    ]



# GET /risk/factors


@router.get("/factors")
def risk_factor_definitions():
    """Rulebook metadata for the dashboard.

    Factor labels, weights, enforcement action bands and the L0-L5 mapping
    are served from the engine so the frontend stays a presentation layer
    and never has to restate scoring policy.
    """
    return {
        "factors": factor_definitions(),
        "action_bands": action_bands(),
        "risk_level_bands": RISK_BANDS,
        "enforcement_levels": ENFORCEMENT_LEVELS,
    }



# GET /risk/debug


@router.get("/debug")
def risk_debug(
    db: Session = Depends(get_db)
):

    database = db.execute(
        text("SELECT current_database()")
    ).scalar()

    count = db.execute(
        text(
            "SELECT COUNT(*) FROM risk_scores"
        )
    ).scalar()

    return {
        "database": database,
        "risk_score_count": count,
    }



# GET /risk/test-loaded


@router.get("/test-loaded")
def test_loaded():

    return {
        "status": "Risk Analytics loaded",
        "rulebook_model": "Adaptive Risk v1",
        "factors": [
            "data_sensitivity",
            "destination_trust",
            "user_risk",
            "device_trust",
            "behaviour_anomaly",
            "transfer_volume",
            "channel_risk",
        ],
        "risk_bands": {
            "0-29": "LOW",
            "30-59": "MEDIUM",
            "60-79": "HIGH",
            "80-100": "CRITICAL",
        },
    }
