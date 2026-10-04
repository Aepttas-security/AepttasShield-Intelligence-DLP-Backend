from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json

from sqlalchemy.orm import Session

from app.models.dlp_event import DLPEvent
from app.models.user import User
from app.models.behavior_profile import BehaviorProfile
from app.models.behavior_anomaly import BehaviorAnomaly
from app.models.ueba_alert import UEBAAlert


def _to_naive_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt



# ============================================================
# UEBA CONFIGURATION
# ============================================================

AFTER_HOURS_START = 0
AFTER_HOURS_END = 8

NORMAL_WORK_START = 9
NORMAL_WORK_END = 18

BULK_VOLUME_MB = 500

REPEATED_ATTEMPT_WINDOW_MINUTES = 30
REPEATED_ATTEMPT_COUNT = 3

CHANNEL_CHAIN_WINDOW_MINUTES = 30


# ============================================================
# RESULT
# ============================================================

@dataclass
class UEBAResult:

    user_id: int

    behaviour_score: float

    anomaly_count: int

    anomalies: list[dict]

    baseline: dict

    reasons: list[str]


# ============================================================
# NORMALIZE
# ============================================================

def normalize(value: str | None) -> str:

    if value is None:
        return ""

    return (
        value
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )
def event_precedes(
    event: DLPEvent,
    current_event: DLPEvent,
) -> bool:
    """Return whether an event belongs to the current event's history."""
    if event.id == current_event.id:
        return False

    event_time = _to_naive_utc(event.timestamp)
    current_time = _to_naive_utc(current_event.timestamp)
    if event_time is not None and current_time is not None:
        return (event_time, event.id or 0) < (current_time, current_event.id or 0)

    return (event.id or 0) < (current_event.id or 0)


# ============================================================
# GET USER EVENTS
# ============================================================

def get_user_events(
    db: Session,
    user_id: int,
) -> list[DLPEvent]:

    return (
        db.query(DLPEvent)
        .filter(
            DLPEvent.user_id == user_id
        )
        .order_by(
            DLPEvent.timestamp.asc(),
            DLPEvent.id.asc(),
        )
        .all()
    )


# ============================================================
# BUILD BEHAVIOURAL BASELINE
# ============================================================

def build_baseline(
    events: list[DLPEvent],
) -> dict:

    if not events:

        return {
            "average_volume": 0,
            "normal_start_hour": NORMAL_WORK_START,
            "normal_end_hour": NORMAL_WORK_END,
            "average_events_per_day": 0,
            "common_channel": None,
            "common_destination": None,
            "common_data_classification": None,
            "baseline_event_count": 0,
        }

    # --------------------------------------------------------
    # Average volume
    # --------------------------------------------------------

    volumes = [
        float(event.volume or 0)
        for event in events
    ]

    average_volume = (
        sum(volumes) / len(volumes)
        if volumes
        else 0
    )

    # --------------------------------------------------------
    # Common channel
    # --------------------------------------------------------

    channels = [
        normalize(event.channel)
        for event in events
        if event.channel
    ]

    common_channel = (
        max(set(channels), key=channels.count)
        if channels
        else None
    )

    # --------------------------------------------------------
    # Common destination
    # --------------------------------------------------------

    destinations = [
        normalize(event.destination)
        for event in events
        if event.destination
    ]

    common_destination = (
        max(set(destinations), key=destinations.count)
        if destinations
        else None
    )

    # --------------------------------------------------------
    # Common data classification
    # --------------------------------------------------------

    classifications = [
        normalize(event.data_classification)
        for event in events
        if event.data_classification
    ]

    common_classification = (
        max(
            set(classifications),
            key=classifications.count
        )
        if classifications
        else None
    )

    # --------------------------------------------------------
    # Activity hours
    # --------------------------------------------------------

    hours = [
        event.timestamp.hour
        for event in events
        if event.timestamp
    ]

    if hours:

        normal_start_hour = min(hours)
        normal_end_hour = max(hours)

    else:

        normal_start_hour = NORMAL_WORK_START
        normal_end_hour = NORMAL_WORK_END

    # --------------------------------------------------------
    # Events per day
    # --------------------------------------------------------

    if events and events[0].timestamp:

        first_day = events[0].timestamp.date()
        last_day = events[-1].timestamp.date()

        number_of_days = (
            last_day - first_day
        ).days + 1

        number_of_days = max(
            number_of_days,
            1
        )

        average_events_per_day = (
            len(events) / number_of_days
        )

    else:

        average_events_per_day = 0

    return {
        "average_volume": round(
            average_volume,
            2
        ),

        "normal_start_hour": normal_start_hour,

        "normal_end_hour": normal_end_hour,

        "average_events_per_day": round(
            average_events_per_day,
            2
        ),

        "common_channel": common_channel,

        "common_destination": common_destination,

        "common_data_classification":
            common_classification,

        "baseline_event_count": len(events),
    }


# ============================================================
# SAVE / UPDATE BEHAVIOUR PROFILE
# ============================================================

def save_behavior_profile(
    db: Session,
    user_id: int,
    baseline: dict,
):

    profile = (
        db.query(BehaviorProfile)
        .filter(
            BehaviorProfile.user_id == user_id
        )
        .first()
    )

    if not profile:

        profile = BehaviorProfile(
            user_id=user_id
        )

        db.add(profile)

    profile.average_volume = (
        baseline["average_volume"]
    )

    profile.normal_start_hour = (
        baseline["normal_start_hour"]
    )

    profile.normal_end_hour = (
        baseline["normal_end_hour"]
    )

    profile.average_events_per_day = (
        baseline["average_events_per_day"]
    )

    profile.common_channel = (
        baseline["common_channel"]
    )

    profile.common_destination = (
        baseline["common_destination"]
    )

    profile.common_data_classification = (
        baseline[
            "common_data_classification"
        ]
    )

    profile.baseline_event_count = (
        baseline["baseline_event_count"]
    )

    return profile


# ============================================================
# 1. BULK EXPORT / VOLUME ANOMALY
# ============================================================

def detect_bulk_export(
    event: DLPEvent,
    baseline: dict,
) -> tuple[float, str | None]:

    volume = float(event.volume or 0)

    classification = normalize(
        event.data_classification
    )

    destination = normalize(
        event.destination
    )

    # Rulebook scenario:
    # volume anomaly + sensitive dataset
    # + external destination

    sensitive = classification in (
        "confidential",
        "restricted",
        "critical",
    )

    external = destination in (
        "external",
        "unknown",
        "untrusted",
        "personal_email",
        "personal_cloud",
        "public",
    )

    volume_anomaly = (
        volume >= BULK_VOLUME_MB
        or (
            baseline["average_volume"] > 0
            and volume
            >= baseline["average_volume"] * 5
        )
    )

    if (
        volume_anomaly
        and sensitive
        and external
    ):

        return (
            100,
            "Bulk export: unusually large "
            "sensitive-data transfer to an "
            "external destination."
        )

    if volume_anomaly:

        return (
            70,
            "Unusual transfer volume detected."
        )

    return 0, None


# ============================================================
# 2. AFTER-HOURS ACTIVITY
# ============================================================

def detect_after_hours(
    event: DLPEvent,
    baseline: dict,
) -> tuple[float, str | None]:

    if not event.timestamp:

        return 0, None

    hour = event.timestamp.hour

    classification = normalize(
        event.data_classification
    )

    sensitive = classification in (
        "confidential",
        "restricted",
        "critical",
    )

    outside_baseline = (
        hour < baseline["normal_start_hour"]
        or hour > baseline["normal_end_hour"]
    )

    if outside_baseline and sensitive:

        return (
            75,
            "Sensitive transfer occurred "
            "outside the user's normal "
            "activity hours."
        )

    if (
        hour < AFTER_HOURS_END
        or hour >= 22
    ):

        return (
            50,
            "Activity occurred during "
            "after-hours."
        )

    return 0, None


# ============================================================
# 3. ROLE / BEHAVIOURAL PATTERN MISMATCH
# ============================================================

def detect_role_mismatch(
    event: DLPEvent,
    baseline: dict,
) -> tuple[float, str | None]:

    if baseline["baseline_event_count"] < 3:

        return 0, None

    classification = normalize(
        event.data_classification
    )

    channel = normalize(
        event.channel
    )

    unusual_classification = (
        baseline["common_data_classification"]
        and classification
        != baseline["common_data_classification"]
    )

    unusual_channel = (
        baseline["common_channel"]
        and channel
        != baseline["common_channel"]
    )

    # We use the user's learned historical
    # behaviour as the role pattern.
    # The Rulebook requires role mismatch,
    # but does not prescribe a fixed
    # department-to-data mapping.

    if (
        unusual_classification
        and unusual_channel
    ):

        return (
            65,
            "Activity differs from the user's "
            "normal role behaviour pattern."
        )

    if unusual_classification:

        return (
            45,
            "Data classification differs from "
            "the user's normal behaviour pattern."
        )

    return 0, None


# ============================================================
# 4. CHANNEL / DESTINATION DEVIATION
# ============================================================

def detect_channel_deviation(
    event: DLPEvent,
    baseline: dict,
) -> tuple[float, str | None]:
    if baseline["baseline_event_count"] < 3:
        return 0, None

    channel = normalize(event.channel)
    common_channel = baseline["common_channel"]
    if common_channel and channel and channel != common_channel:
        return 50, "Transfer channel differs from the user's normal behaviour pattern."

    return 0, None


def detect_destination_deviation(
    event: DLPEvent,
    baseline: dict,
) -> tuple[float, str | None]:
    if baseline["baseline_event_count"] < 3:
        return 0, None

    destination = normalize(event.destination)
    common_destination = baseline["common_destination"]
    if common_destination and destination and destination != common_destination:
        return 55, "Transfer destination differs from the user's normal behaviour pattern."

    return 0, None


# ============================================================
# 5. REPEATED ATTEMPTS
# ============================================================
def detect_repeated_attempts(
    events: list[DLPEvent],
    current_event: DLPEvent,
) -> tuple[float, str | None]:

    cur_dt = _to_naive_utc(current_event.timestamp)
    if not cur_dt:
        return 0, None

    start_time = cur_dt - timedelta(
        minutes=REPEATED_ATTEMPT_WINDOW_MINUTES
    )

    recent_events = [
        event
        for event in events
        if (
            event.timestamp
            and start_time
            <= _to_naive_utc(event.timestamp)
            <= cur_dt
        )
    ]

    blocked_events = [
        event
        for event in recent_events
        if normalize(event.action_taken)
        in (
            "block",
            "blocked",
            "deny",
            "denied",
        )
    ]

    if len(blocked_events) >= REPEATED_ATTEMPT_COUNT:
        return (
            85,
            f"Repeated blocked transfer "
            f"attempts detected: "
            f"{len(blocked_events)} attempts "
            f"within {REPEATED_ATTEMPT_WINDOW_MINUTES} "
            f"minutes."
        )

    return 0, None


def _chain_stage(event: DLPEvent) -> str:
    """Label a correlated event with its transfer stage for the timeline."""
    event_type = normalize(event.event_type)
    channel = normalize(event.channel)

    if "copy" in event_type:
        return "COPY"

    if "archive" in event_type or "compress" in event_type:
        return "ARCHIVE"

    if channel in ("usb", "removable_media"):
        return "USB"

    if channel in ("cloud_upload", "cloud"):
        return "CLOUD"

    return (channel or event_type or "TRANSFER").upper()


def build_channel_chaining_correlation(
    recent_events: list[DLPEvent],
) -> dict:
    """Build the correlated transfer chain for a channel-chaining detection.

    The identifier is derived from the participating event ids so that
    re-analysing the same window produces the same correlation id instead of
    a new one, which keeps the anomaly record idempotent.
    """
    ordered = sorted(
        recent_events,
        key=lambda event: (
            _to_naive_utc(event.timestamp) or datetime.min,
            event.id or 0,
        )
    )

    event_ids = [event.id for event in ordered if event.id is not None]

    # Derived from the exact participating event set, so re-analysing the same
    # window reuses the same id while two different chains never collide.
    digest = hashlib.sha1(
        ",".join(str(event_id) for event_id in event_ids).encode(
            "utf-8"
        )
    ).hexdigest()[:10]

    correlation_id = (
        f"CHAIN-{ordered[0].user_id}-{digest}"
        if event_ids and ordered[0].user_id
        else None
    )

    return {
        "correlation_id": correlation_id,
        "related_event_ids": event_ids,
        "window_minutes": CHANNEL_CHAIN_WINDOW_MINUTES,
        "stages": [
            {
                "event_id": event.id,
                "stage": _chain_stage(event),
                "event_type": event.event_type,
                "channel": event.channel,
            }
            for event in ordered
        ],
    }


# ============================================================
# 6. CHANNEL CHAINING
# ============================================================

def detect_channel_chaining(
    events: list[DLPEvent],
    current_event: DLPEvent,
) -> tuple[float, str | None, dict | None]:

    cur_dt = _to_naive_utc(current_event.timestamp)
    if not cur_dt:
        return 0, None

    start_time = cur_dt - timedelta(
        minutes=CHANNEL_CHAIN_WINDOW_MINUTES
    )

    recent_events = [
        event
        for event in events
        if (
            event.timestamp
            and start_time
            <= _to_naive_utc(event.timestamp)
            <= cur_dt
        )
    ]

    channels = {

        normalize(event.channel)

        for event in recent_events

        if event.channel
    }

    # Rulebook example:
    # copy + archive + USB + cloud

    has_copy = any(
        "copy" in normalize(event.event_type)
        for event in recent_events
    )

    has_archive = any(
        "archive" in normalize(event.event_type)
        or "compress" in normalize(event.event_type)
        for event in recent_events
    )

    has_usb = any(
        normalize(event.channel)
        in (
            "usb",
            "removable_media",
        )
        for event in recent_events
    )

    has_cloud = any(
        normalize(event.channel)
        in (
            "cloud_upload",
            "cloud",
        )
        for event in recent_events
    )

    chain_count = sum([
        has_copy,
        has_archive,
        has_usb,
        has_cloud,
    ])

    if chain_count >= 3:

        return (
            90,
            "Channel chaining detected across "
            "multiple data-transfer stages.",
            build_channel_chaining_correlation(
                recent_events
            ),
        )

    # Also detect a simpler multi-channel
    # sequence.

    if len(channels) >= 3:

        return (
            70,
            "Multiple transfer channels used "
            "within a short time window.",
            build_channel_chaining_correlation(
                recent_events
            ),
        )

    return 0, None, None


# ============================================================
# CREATE ANOMALY RECORD
# ============================================================

def save_anomaly(
    db: Session,
    user_id: int,
    event_id: int,
    anomaly_type: str,
    score: float,
    reason: str,
    correlation: dict | None = None,
):

    if score <= 0:
        return None

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    correlation_id = (
        correlation.get("correlation_id")
        if correlation
        else None
    )

    related_event_ids = (
        json.dumps(correlation["related_event_ids"])
        if correlation and correlation.get("related_event_ids")
        else None
    )

    correlation_window = (
        correlation.get("window_minutes")
        if correlation
        else None
    )

    matches = (
        db.query(BehaviorAnomaly)
        .filter(
            BehaviorAnomaly.user_id == user_id,
            BehaviorAnomaly.event_id == event_id,
            BehaviorAnomaly.anomaly_type == anomaly_type,
        )
        .order_by(BehaviorAnomaly.id.asc())
        .all()
    )

    if matches:
        anomaly = matches[0]

        # Older processing runs may have created duplicate records before this
        # logical key was consistently enforced. Preserve the canonical record
        # and keep any alert relationship valid while removing only duplicates.
        for duplicate in matches[1:]:
            db.query(UEBAAlert).filter(
                UEBAAlert.anomaly_id == duplicate.id
            ).update(
                {UEBAAlert.anomaly_id: anomaly.id},
                synchronize_session=False,
            )
            db.delete(duplicate)

        anomaly.anomaly_score = score
        anomaly.severity = severity
        anomaly.reason = reason
        anomaly.detected_at = datetime.utcnow()

        if correlation_id:
            anomaly.correlation_id = correlation_id
        if related_event_ids:
            anomaly.related_event_ids = related_event_ids
        if correlation_window is not None:
            anomaly.correlation_window_minutes = (
                correlation_window
            )

        return anomaly

    anomaly = BehaviorAnomaly(
        user_id=user_id,
        event_id=event_id,
        anomaly_type=anomaly_type,
        anomaly_score=score,
        severity=severity,
        reason=reason,
        correlation_id=correlation_id,
        related_event_ids=related_event_ids,
        correlation_window_minutes=correlation_window,
    )

    db.add(anomaly)
    return anomaly


# ============================================================
# MAIN UEBA ANALYSIS
# ============================================================

def analyze_user_behavior(
    db: Session,
    user_id: int,
    event_id: int | None = None,
) -> UEBAResult:

    # --------------------------------------------------------
    # USER
    # --------------------------------------------------------

    user = (
        db.query(User)
        .filter(
            User.id == user_id
        )
        .first()
    )

    if not user:

        raise ValueError(
            "User not found"
        )

    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    events = get_user_events(
        db,
        user_id
    )

    if not events:

        return UEBAResult(
            user_id=user_id,
            behaviour_score=0,
            anomaly_count=0,
            anomalies=[],
            baseline={},
            reasons=[
                "No behavioural data available."
            ],
        )

    # --------------------------------------------------------
    # CURRENT EVENT
    # --------------------------------------------------------

    current_event = None

    if event_id:

        current_event = next(
            (
                event
                for event in events
                if event.id == event_id
            ),
            None,
        )

    if not current_event:

        current_event = events[-1]

    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    historical_events = [
        event
        for event in events
        if event_precedes(event, current_event)
    ]

    # Detection windows must not use events that occur after the event being
    # evaluated; that would leak future activity into the result.
    events_through_current = historical_events + [current_event]

    baseline = build_baseline(
        historical_events
    )

    # --------------------------------------------------------
    # SAVE PROFILE
    # --------------------------------------------------------

    # A profile represents the user's latest known baseline. Analysing an
    # older event must not replace it with an outdated point-in-time baseline.
    if current_event.id == events[-1].id:
        save_behavior_profile(
            db=db,
            user_id=user_id,
            baseline=baseline,
        )

    # --------------------------------------------------------
    # DETECT ANOMALIES
    # --------------------------------------------------------

    anomaly_results = []

    reasons = []

    # 1. Bulk export

    score, reason = detect_bulk_export(
        current_event,
        baseline,
    )

    if score > 0:

        anomaly_results.append({
            "type": "BULK_EXPORT",
            "score": score,
            "reason": reason,
        })

        reasons.append(reason)

        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="BULK_EXPORT",
            score=score,
            reason=reason,
        )

    # 2. After hours

    score, reason = detect_after_hours(
        current_event,
        baseline,
    )

    if score > 0:

        anomaly_results.append({
            "type": "AFTER_HOURS",
            "score": score,
            "reason": reason,
        })

        reasons.append(reason)

        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="AFTER_HOURS",
            score=score,
            reason=reason,
        )

    # 3. Role mismatch

    score, reason = detect_role_mismatch(
        current_event,
        baseline,
    )

    if score > 0:

        anomaly_results.append({
            "type": "ROLE_MISMATCH",
            "score": score,
            "reason": reason,
        })

        reasons.append(reason)

        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="ROLE_MISMATCH",
            score=score,
            reason=reason,
        )

    # 4. Channel deviation

    score, reason = detect_channel_deviation(
        current_event,
        baseline,
    )

    if score > 0:
        anomaly_results.append({
            "type": "UNUSUAL_CHANNEL",
            "score": score,
            "reason": reason,
        })
        reasons.append(reason)
        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="UNUSUAL_CHANNEL",
            score=score,
            reason=reason,
        )

    # 5. Destination deviation

    score, reason = detect_destination_deviation(
        current_event,
        baseline,
    )

    if score > 0:
        anomaly_results.append({
            "type": "UNUSUAL_DESTINATION",
            "score": score,
            "reason": reason,
        })
        reasons.append(reason)
        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="UNUSUAL_DESTINATION",
            score=score,
            reason=reason,
        )

    # 6. Repeated attempts

    score, reason = detect_repeated_attempts(
        events_through_current,
        current_event,
    )

    if score > 0:

        anomaly_results.append({
            "type": "REPEATED_ATTEMPTS",
            "score": score,
            "reason": reason,
        })

        reasons.append(reason)

        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="REPEATED_ATTEMPTS",
            score=score,
            reason=reason,
        )

    # 7. Channel chaining

    score, reason, correlation = detect_channel_chaining(
        events_through_current,
        current_event,
    )

    if score > 0:

        anomaly_results.append({
            "type": "CHANNEL_CHAINING",
            "score": score,
            "reason": reason,
            "correlation": correlation,
        })

        reasons.append(reason)

        save_anomaly(
            db=db,
            user_id=user_id,
            event_id=current_event.id,
            anomaly_type="CHANNEL_CHAINING",
            score=score,
            reason=reason,
            correlation=correlation,
        )

    # --------------------------------------------------------
    # FINAL BEHAVIOUR SCORE
    # --------------------------------------------------------

    if anomaly_results:

        behaviour_score = max(
            item["score"]
            for item in anomaly_results
        )

    else:

        behaviour_score = 0

    behaviour_score = round(
        min(
            max(
                behaviour_score,
                0
            ),
            100
        ),
        2
    )

    # --------------------------------------------------------
    # DEFAULT REASON
    # -------------------------------------------------------
    if not reasons:

        reasons.append(
            "No significant behavioural "
            "anomaly detected."
        )

    return UEBAResult(

        user_id=user_id,

        behaviour_score=behaviour_score,

        anomaly_count=len(
            anomaly_results
        ),

        anomalies=anomaly_results,

        baseline=baseline,

        reasons=reasons,
    )