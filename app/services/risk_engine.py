from dataclasses import dataclass


# ============================================================
# RULEBOOK RISK WEIGHTS
# ============================================================

WEIGHTS = {
    "data_sensitivity": 0.20,
    "destination_trust": 0.15,
    "user_risk": 0.15,
    "device_trust": 0.10,
    "behaviour_anomaly": 0.15,
    "transfer_volume": 0.15,
    "channel_risk": 0.10,
}

RISK_BANDS = {
    "0-29": "LOW",
    "30-59": "MEDIUM",
    "60-79": "HIGH",
    "80-100": "CRITICAL",
}


# ============================================================
# DATA SENSITIVITY
# ============================================================

DATA_SENSITIVITY = {
    "public": 0,
    "internal": 25,
    "confidential": 70,
    "restricted": 100,
    "critical": 100,
}


# ============================================================
# DESTINATION TRUST
# Higher score = more risky
# ============================================================

DESTINATION_RISK = {
    "internal": 0,
    "approved_partner": 20,
    "trusted": 20,
    "external": 70,
    "unknown": 90,
    "untrusted": 100,
    "personal_email": 100,
    "personal_cloud": 100,
    "public": 100,
}


# ============================================================
# CHANNEL RISK
# ============================================================

CHANNEL_RISK = {
    "internal_application": 0,
    "internal": 0,
    "corporate_email": 20,
    "cloud_upload": 70,
    "external_email": 80,
    "personal_email": 100,
    "usb": 90,
    "removable_media": 90,
    "public_sharing": 100,
    "messaging": 90,
    "personal_messaging": 100,
    "clipboard": 60,
    "screenshot": 70,
}


# ============================================================
# SEVERITY
# Used as supporting context, not a primary adaptive factor
# ============================================================

SEVERITY = {
    "low": 20,
    "medium": 50,
    "high": 80,
    "critical": 100,
}


# ============================================================
# RESULT
# ============================================================

@dataclass
class RiskResult:

    data_sensitivity_score: float

    destination_trust_score: float

    user_risk_score: float

    device_trust_score: float

    behaviour_anomaly_score: float

    transfer_volume_score: float

    channel_risk_score: float

    # Compatibility fields
    severity_score: float
    frequency_risk_score: float

    total_risk_score: float

    risk_level: str

    risk_action: str

    reasons: list[str]


# ============================================================
# USER RISK
# ============================================================

def calculate_user_risk(
    previous_violations: int
) -> float:

    if previous_violations <= 0:
        return 0

    if previous_violations <= 2:
        return 30

    if previous_violations <= 5:
        return 60

    if previous_violations <= 10:
        return 80

    return 100


# ============================================================
# DEVICE TRUST
# ============================================================

def calculate_device_trust(
    trust_level: str | None,
    is_managed: bool = False,
) -> float:

    trust = (trust_level or "UNKNOWN").lower()

    if is_managed:
        return 0

    if trust in ("trusted", "high"):
        return 10

    if trust in ("medium", "known"):
        return 40

    if trust in ("unknown",):
        return 70

    if trust in ("untrusted", "low"):
        return 100

    return 70


# ============================================================
# BEHAVIOUR ANOMALY
# ============================================================

def calculate_behaviour_anomaly(
    previous_violations: int,
    number_of_violations: int,
) -> float:

    # Repeated activity is treated as behavioural deviation.
    if number_of_violations <= 1 and previous_violations == 0:
        return 0

    if number_of_violations <= 2:
        return 30

    if number_of_violations <= 5:
        return 60

    if number_of_violations <= 10:
        return 80

    return 100


# ============================================================
# TRANSFER VOLUME
# Volume is assumed to be in MB.
# ============================================================

def calculate_transfer_volume(
    volume: float
) -> float:

    if volume <= 0:
        return 0

    if volume < 10:
        return 20

    if volume < 100:
        return 50

    if volume < 500:
        return 75

    if volume < 1000:
        return 90

    return 100


# ============================================================
# FREQUENCY COMPATIBILITY FACTOR
# ============================================================

def calculate_frequency_risk(
    number_of_violations: int
) -> float:

    if number_of_violations <= 1:
        return 0

    if number_of_violations <= 3:
        return 30

    if number_of_violations <= 5:
        return 60

    if number_of_violations <= 10:
        return 80

    return 100


# ============================================================
# NORMALIZE LOOKUPS
# ============================================================

def normalize(value: str | None) -> str:

    if value is None:
        return ""

    return value.strip().lower().replace("-", "_").replace(" ", "_")


# ============================================================
# RISK BAND
# ============================================================

def classify_risk(
    score: float
) -> tuple[str, str]:

    if score < 20:
        return "MONITOR", "ALLOW / MONITOR"

    if score < 40:
        return "WARN", "WARN"

    if score < 60:
        return "JUSTIFY", "REQUIRE JUSTIFICATION"

    if score < 80:
        return "BLOCK", "BLOCK / ADAPTIVE CHALLENGE"

    return "CRITICAL", "BLOCK + INCIDENT + AUTOMATED RESPONSE"


def classify_risk_level(score: float) -> str:
    if score < 30:
        return "LOW"

    if score < 60:
        return "MEDIUM"

    if score < 80:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# RULEBOOK METADATA (single source of truth for the API layer)
# ============================================================

# The seven weighted factors sum to 1.0. Severity and frequency are
# calculated and stored as supporting context only, so they are exposed
# for visibility without being given a weight.
SUPPORTING_FACTORS = {
    "severity": "Severity Score",
    "frequency": "Frequency Risk",
}

FACTOR_LABELS = {
    "data_sensitivity": "Data Sensitivity",
    "destination_trust": "Destination Trust",
    "user_risk": "User Risk",
    "device_trust": "Device Trust",
    "behaviour_anomaly": "Behaviour Anomaly",
    "transfer_volume": "Transfer Volume",
    "channel_risk": "Channel Risk",
}


def factor_definitions() -> dict:
    definitions = {}

    for name, weight in WEIGHTS.items():
        definitions[name] = {
            "label": FACTOR_LABELS[name],
            "weight": weight,
            "weighted": True,
        }

    for name, label in SUPPORTING_FACTORS.items():
        definitions[name] = {
            "label": label,
            "weight": 0.0,
            "weighted": False,
        }

    return definitions


def action_bands() -> list[dict]:
    """Enforcement action bands, derived from classify_risk itself."""
    edges = [(0, 20), (20, 40), (40, 60), (60, 80), (80, 101)]

    bands = []

    for index, (low, high) in enumerate(edges):
        level, action = classify_risk(low)
        label = (
            f"{low}-{high - 1}" if high <= 100 else "80-100"
        )
        bands.append({
            "range": label,
            "min": low,
            "level": level,
            "action": action,
            "enforcement_level": enforcement_level(action),
        })

    return bands


# ============================================================
# L0-L5 ENFORCEMENT MAPPING
# ============================================================

ENFORCEMENT_LEVELS = {
    "L0": "Monitor",
    "L1": "Warn",
    "L2": "Justify",
    "L3": "Block",
    "L4": "Adaptive Block",
    "L5": "Automated Response",
}


def enforcement_level(action: str | None) -> str:
    """Map an enforcement action onto the L0-L5 rulebook scale.

    Ordered from most to least escalated because several actions combine
    stages, for example "BLOCK + INCIDENT + AUTOMATED RESPONSE".
    """
    text = normalize(action)

    if not text:
        return "L0"

    if "automated response" in text or "incident" in text:
        return "L5"

    if "adaptive" in text or "challenge" in text:
        return "L4"

    if "block" in text or "deny" in text:
        return "L3"

    if "justif" in text:
        return "L2"

    if "warn" in text:
        return "L1"

    return "L0"


# ============================================================
# MAIN RISK CALCULATION
# ============================================================

def calculate_risk(
    classification: str,
    severity: str,
    previous_violations: int,
    channel: str,
    destination: str,
    number_of_violations: int,
    volume: float = 0,
    device_trust: str = "UNKNOWN",
    is_managed_device: bool = False,
    behaviour_anomaly_score: float | None = None,
)-> RiskResult:

    classification = normalize(classification)
    severity = normalize(severity)
    channel = normalize(channel)
    destination = normalize(destination)

    # --------------------------------------------------------
    # FACTOR 1: DATA SENSITIVITY
    # --------------------------------------------------------

    data_score = DATA_SENSITIVITY.get(
        classification,
        DATA_SENSITIVITY["internal"]
    )

    # --------------------------------------------------------
    # FACTOR 2: DESTINATION TRUST
    # --------------------------------------------------------

    destination_score = DESTINATION_RISK.get(
        destination,
        DESTINATION_RISK["unknown"]
    )

    # --------------------------------------------------------
    # FACTOR 3: USER RISK
    # --------------------------------------------------------

    user_score = calculate_user_risk(
        previous_violations
    )

    # --------------------------------------------------------
    # FACTOR 4: DEVICE TRUST
    # --------------------------------------------------------

    device_score = calculate_device_trust(
        device_trust,
        is_managed_device
    )

    # --------------------------------------------------------
    # FACTOR 5: BEHAVIOUR ANOMALY
    # --------------------------------------------------------

    if behaviour_anomaly_score is not None:
        behaviour_score = min(
            max(float(behaviour_anomaly_score), 0),100
        )
    else:
        behaviour_score = calculate_behaviour_anomaly(
            previous_violations,
            number_of_violations
        )

    # --------------------------------------------------------
    # FACTOR 6: TRANSFER VOLUME
    # --------------------------------------------------------

    volume_score = calculate_transfer_volume(
        volume
    )

    # --------------------------------------------------------
    # FACTOR 7: CHANNEL RISK
    # --------------------------------------------------------

    channel_score = CHANNEL_RISK.get(
        channel,
        CHANNEL_RISK["internal_application"]
    )

    # --------------------------------------------------------
    # COMPATIBILITY FACTORS
    # --------------------------------------------------------

    severity_score = SEVERITY.get(
        severity,
        SEVERITY["low"]
    )

    frequency_score = calculate_frequency_risk(
        number_of_violations
    )

    # --------------------------------------------------------
    # WEIGHTED RISK SCORE
    # --------------------------------------------------------

    weighted_score = (
        data_score * WEIGHTS["data_sensitivity"]
        + destination_score * WEIGHTS["destination_trust"]
        + user_score * WEIGHTS["user_risk"]
        + device_score * WEIGHTS["device_trust"]
        + behaviour_score * WEIGHTS["behaviour_anomaly"]
        + volume_score * WEIGHTS["transfer_volume"]
        + channel_score * WEIGHTS["channel_risk"]
    )

    total_score = round(
        min(max(weighted_score, 0), 100),
        2
    )

    # --------------------------------------------------------
    # RISK BAND & RISK ACTION
    # --------------------------------------------------------

    risk_level = classify_risk_level(total_score)
    _, risk_action = classify_risk(total_score)

    # --------------------------------------------------------
    # REASONS
    # --------------------------------------------------------

    reasons = []

    if data_score >= 70:
        reasons.append(
            f"Sensitive data classification: {classification}"
        )

    if destination_score >= 70:
        reasons.append(
            f"Untrusted/high-risk destination: {destination}"
        )

    if user_score >= 60:
        reasons.append(
            f"High user risk due to previous violations: "
            f"{previous_violations}"
        )

    if device_score >= 70:
        reasons.append(
            f"Low device trust: {device_trust}"
        )

    if behaviour_score >= 60:
        reasons.append(
            f"High behavioural anomaly detected: score {behaviour_score}"
        )

    if volume_score >= 75:
        reasons.append(
            f"High transfer volume: {volume}"
        )

    if channel_score >= 70:
        reasons.append(
            f"High-risk transfer channel: {channel}"
        )

    if severity_score >= 80:
        reasons.append(
            f"High event severity: {severity}"
        )

    if not reasons:
        reasons.append(
            "No major risk factors detected"
        )

    return RiskResult(
        data_sensitivity_score=data_score,
        destination_trust_score=destination_score,
        user_risk_score=user_score,
        device_trust_score=device_score,
        behaviour_anomaly_score=behaviour_score,
        transfer_volume_score=volume_score,
        channel_risk_score=channel_score,
        severity_score=severity_score,
        frequency_risk_score=frequency_score,
        total_risk_score=total_score,
        risk_level=risk_level,
        risk_action=risk_action,
        reasons=reasons,
    )