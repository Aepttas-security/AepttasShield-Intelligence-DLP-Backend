from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from app.core.database import Base, engine, SessionLocal
from app.api.risk import router as risk_router
from app.api.ueba import router as ueba_router
from app import models
from app.models.policy import Policy
from app.models.device import Device
from app.models.user import User


# Create database tables
Base.metadata.create_all(bind=engine)


# Additive, idempotent column migrations.
# create_all() only creates missing tables, so columns added to an existing
# model later still need to be applied to a live database.
ADDITIVE_MIGRATIONS = (
    (
        "behavior_anomalies",
        "correlation_id",
        "ALTER TABLE behavior_anomalies ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(100)",
    ),
    (
        "behavior_anomalies",
        "correlation_id_index",
        "CREATE INDEX IF NOT EXISTS ix_behavior_anomalies_correlation_id ON behavior_anomalies (correlation_id)",
    ),
    (
        "behavior_anomalies",
        "related_event_ids",
        "ALTER TABLE behavior_anomalies ADD COLUMN IF NOT EXISTS related_event_ids TEXT",
    ),
    (
        "behavior_anomalies",
        "correlation_window_minutes",
        "ALTER TABLE behavior_anomalies ADD COLUMN IF NOT EXISTS correlation_window_minutes INTEGER",
    ),
)


def run_additive_migrations():
    statements = [statement for _, _, statement in ADDITIVE_MIGRATIONS]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


try:
    run_additive_migrations()
except Exception as e:
    print("Additive migration exception:", e)


app = FastAPI(
    title="AepttasShield Enterprise DLP - Risk Analytics & UEBA",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    db = SessionLocal()
    try:
        if db.query(Policy).count() == 0:
            default_policies = [
                Policy(
                    policy_name="Critical Data Exfiltration Prevention",
                    data_classification="CRITICAL",
                    channel="*",
                    destination_type="*",
                    severity="CRITICAL",
                    action="BLOCK",
                    priority=1,
                    is_active=True,
                    description="Block any unauthorized transfer of critical classified data.",
                ),
                Policy(
                    policy_name="Removable Media Restricted Data Block",
                    data_classification="RESTRICTED",
                    channel="usb",
                    destination_type="external",
                    severity="HIGH",
                    action="BLOCK",
                    priority=5,
                    is_active=True,
                    description="Block transfer of restricted datasets to USB/removable media.",
                ),
                Policy(
                    policy_name="External Cloud Upload Restriction",
                    data_classification="RESTRICTED",
                    channel="cloud_upload",
                    destination_type="external",
                    severity="HIGH",
                    action="BLOCK",
                    priority=10,
                    is_active=True,
                    description="Block restricted data upload to external cloud destinations.",
                ),
                Policy(
                    policy_name="Confidential Data External Email Warning",
                    data_classification="CONFIDENTIAL",
                    channel="corporate_email",
                    destination_type="external",
                    severity="MEDIUM",
                    action="WARN",
                    priority=20,
                    is_active=True,
                    description="Warn when confidential information is sent to external email addresses.",
                ),
                Policy(
                    policy_name="High Volume Data Transfer Policy",
                    data_classification="*",
                    channel="*",
                    destination_type="*",
                    minimum_volume=500.0,
                    severity="HIGH",
                    action="JUSTIFY",
                    priority=30,
                    is_active=True,
                    description="Require employee justification for high volume data transfers (>500MB).",
                ),
                Policy(
                    policy_name="Internal Operational Flow Monitoring",
                    data_classification="INTERNAL",
                    channel="internal_application",
                    destination_type="internal",
                    severity="LOW",
                    action="MONITOR",
                    priority=100,
                    is_active=True,
                    description="Monitor normal internal application data movements.",
                ),
            ]
            db.add_all(default_policies)

        if db.query(Device).count() == 0:
            first_user = db.query(User).first()
            uid = first_user.id if first_user else 1
            default_devices = [
                Device(
                    device_name="CORP-LT-10492",
                    user_id=uid,
                    device_type="LAPTOP",
                    trust_level="TRUSTED",
                    is_managed=True,
                ),
                Device(
                    device_name="ENG-WS-0042",
                    user_id=uid,
                    device_type="DESKTOP",
                    trust_level="TRUSTED",
                    is_managed=True,
                ),
                Device(
                    device_name="BYOD-IPHONE-09",
                    user_id=uid,
                    device_type="MOBILE",
                    trust_level="UNTRUSTED",
                    is_managed=False,
                ),
            ]
            db.add_all(default_devices)

        db.commit()
    except Exception as e:
        db.rollback()
        print("Startup init exception:", e)
    finally:
        db.close()


@app.get("/")
def home():
    return {
        "message": "AepttasShield Enterprise DLP - Risk Analytics & UEBA API is running",
        "docs_url": "/docs",
        "dashboard_url": "/dashboard",
    }


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    dashboard_path = Path(__file__).resolve().parent.parent / "dlp_dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard file not found</h1>", status_code=404)


@app.get("/test-db")
def test_db():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "Database connected successfully"}
    except Exception as e:
        return {"status": "Database connection failed", "error": str(e)}


# Include Risk Analytics & UEBA routes
app.include_router(risk_router)
app.include_router(ueba_router)