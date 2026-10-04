# 🛡️ AepttasShield Enterprise DLP

Enterprise-grade Data Loss Prevention (DLP) backend with Risk Analytics and User and Entity Behavior Analytics (UEBA) for detecting, analyzing, and responding to potential data security risks.

---

## 📌 Overview

AepttasShield Enterprise DLP is an enterprise security solution designed to monitor, analyze, and manage potential data loss activities.

The system processes DLP events and evaluates them using Risk Analytics and UEBA. Risk Analytics calculates risk based on multiple security factors, while UEBA establishes user behaviour baselines and detects abnormal activities.

The backend provides REST APIs for risk calculation, behaviour analysis, alerts, incidents, user risk analysis, and dashboard integration.

---

## 🚀 Features

### Risk Analytics

- Multi-factor enterprise risk scoring
- Data sensitivity analysis
- Destination trust analysis
- User risk analysis
- Device trust analysis
- Behaviour anomaly analysis
- Transfer volume analysis
- Channel risk analysis
- Severity analysis
- Frequency analysis
- Risk level classification
- Risk-based enforcement actions
- High-risk user identification
- Risk alerts
- Incident generation
- User-level risk analysis
- Department-level risk analysis
- Explainable risk information
- DLP event-based risk calculation

### UEBA

- User behaviour profiling
- Behaviour baseline generation
- Average transfer volume tracking
- Average events-per-day tracking
- Normal working-hour detection
- Common channel identification
- Common destination identification
- Common data classification identification
- After-hours activity detection
- Bulk transfer detection
- Role mismatch detection
- Repeated activity detection
- Channel chaining detection
- Unusual channel detection
- Unusual destination detection
- Behaviour anomaly scoring
- UEBA alerts
- UEBA incident correlation

### Dashboard

The Enterprise DLP dashboard provides visibility into:

- Security posture
- Risk distribution
- Risk scores
- Risk levels
- Risk actions
- Active incidents
- Risk alerts
- High-risk users
- Department risk
- Risk factors
- Behaviour profiles
- Behaviour anomalies
- UEBA activity
- DLP event information

---

## 🏗️ Architecture


                         ┌─────────────────────────┐
                         │     DLP Dashboard       │
                         │                         │
                         │ HTML / CSS / JavaScript │
                         │ Chart.js / Lucide       │
                         └────────────┬────────────┘
                                      │
                                      │ REST API
                                      ▼
                         ┌─────────────────────────┐
                         │       FastAPI           │
                         │        Backend          │
                         └────────────┬────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
                 ▼                                         ▼
       ┌─────────────────────┐                  ┌─────────────────────┐
       │   Risk Analytics    │                  │        UEBA         │
       │                     │                  │                     │
       │ Risk Calculation    │                  │ Behaviour Profiles  │
       │ Risk Factors        │                  │ Baselines           │
       │ Risk Levels         │                  │ Anomalies           │
       │ Risk Actions        │                  │ After-hours         │
       │ Alerts              │                  │ Bulk Activity       │
       │ Incidents           │                  │ Role Mismatch       │
       │ High-risk Users     │                  │ Repeated Attempts   │
       └──────────┬──────────┘                  │ Channel Chaining    │
                  │                             └──────────┬──────────┘
                  │                                        │
                  └────────────────┬───────────────────────┘
                                   │
                                   ▼
                         ┌─────────────────────────┐
                         │       PostgreSQL        │
                         │        Database         │
                         │                         │
                         │ Users                   │
                         │ Devices                 │
                         │ Policies                │
                         │ DLP Events              │
                         │ Risk Scores             │
                         │ Risk Factors            │
                         │ Risk Alerts             │
                         │ Incidents               │
                         │ Behaviour Profiles      │
                         │ Behaviour Anomalies     │
                         └─────────────────────────┘


🛠️ Technology Stack

| Component               | Technology            |
| ----------------------- | --------------------- |
| Programming Language    | Python                |
| Backend Framework       | FastAPI               |
| ORM                     | SQLAlchemy            |
| Database                | PostgreSQL            |
| Database Management     | pgAdmin / Supabase    |
| API Documentation       | Swagger / OpenAPI     |
| Frontend                | HTML, CSS, JavaScript |
| Charts                  | Chart.js              |
| Icons                   | Lucide                |
| API Server              | Uvicorn               |
| Development Environment | Visual Studio Code    |


📂 Project Structure

dlpriskanalytics/
│
├── app/
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── main.py
│   └── __init__.py
│
├── .env
├── .gitignore
├── README.md
└── requirements.txt

The exact files inside each module may vary depending on the current implementation.

⚙️ Installation

1. Clone the Repository

git clone <repository-url>

Navigate into the project:

cd dlpriskanalytics

2. Create a Virtual Environment

Windows:

python -m venv venv

Activate it:

venv\Scripts\activate

Linux/macOS:

python3 -m venv venv
source venv/bin/activate

3. Install Dependencies

pip install -r requirements.txt

🔐 Environment Variables

Create a .env file in the project root.

Example:

DATABASE_URL=your_postgresql_connection_string

For Supabase PostgreSQL, use the PostgreSQL connection string provided by the Supabase project.

Security

Do not commit .env to GitHub.

Never expose:

Database passwords
API keys
Secret keys
Authentication credentials
Production connection strings

A .env.example file can be used instead:

DATABASE_URL= your_postgresql_connection_string

▶️ Running the Server

Activate the virtual environment:

venv\Scripts\activate

Start the FastAPI server:

uvicorn app.main:app --reload

If main.py is being run from the current application directory, use:

uvicorn main:app --reload

The API will normally be available at:

http://127.0.0.1:8000

📖 API Documentation

FastAPI automatically provides interactive API documentation.

Swagger UI

http://127.0.0.1:8000/docs
ReDoc
http://127.0.0.1:8000/redoc

Swagger UI can be used to test the backend APIs and inspect request and response schemas.

🔌 REST APIs

Risk Analytics APIs

| Method | Endpoint                                | Description                                |
| ------ | --------------------------------------- | ------------------------------------------ |
| POST   | `/risk/calculate`                       | Calculate risk for a DLP activity          |
| POST   | `/risk/calculate-from-event/{event_id}` | Calculate risk from an existing DLP event  |
| GET    | `/risk/summary`                         | Retrieve overall risk summary              |
| GET    | `/risk/incidents`                       | Retrieve risk incidents                    |
| GET    | `/risk/users`                           | Retrieve user-level risk information       |
| GET    | `/risk/departments`                     | Retrieve department-level risk information |
| GET    | `/risk/high-risk-users`                 | Retrieve high-risk users                   |
| GET    | `/risk/alerts`                          | Retrieve risk alerts                       |
| GET    | `/risk/scores`                          | Retrieve risk score records                |
| GET    | `/risk/debug`                           | Retrieve risk/debug information            |
| GET    | `/risk/test-loaded`                     | Verify backend/model loading               |


Additional APIs may be available depending on the current implementation.

📊 Risk Analytics

Risk Analytics evaluates DLP activities using multiple risk dimensions.

Risk Factors

The risk model considers factors including:

Data Sensitivity
Destination Trust
User Risk
Device Trust
Behaviour Anomaly
Transfer Volume
Channel Risk
Severity
Frequency

Each factor contributes to the overall risk evaluation.

🎯 Adaptive Risk Model

The configured adaptive risk model uses the following ranges:

| Risk Score | Risk Handling                         |
| ---------: | ------------------------------------- |
|       0–19 | Allow / Monitor                       |
|      20–39 | Warn                                  |
|      40–59 | Justify                               |
|      60–79 | Block / Adaptive Challenge            |
|     80–100 | Block + Incident + Automated Response |


The final enforcement action is determined by the backend risk evaluation and configured DLP rules.

🧠 User and Entity Behavior Analytics

UEBA analyzes user activities against established behavioural baselines.

The purpose of UEBA is to identify activities that deviate from normal user behaviour and increase the associated risk when suspicious behaviour is detected.

👤 Behaviour Profiles

Behaviour profiles can contain:

User
Department
Average transfer volume
Average events per day
Normal start hour
Normal end hour
Common channel
Common destination
Common data classification
Baseline event count
Last profile update

These values are used to establish a behavioural baseline for anomaly detection.

🚨 UEBA Detection Scenarios

Bulk Export

Detects unusually large data transfers, especially when combined with sensitive data and an external destination.

The configured response can include:

Critical Risk
Block
Incident Generation
After-Hours Activity

Detects sensitive data activity outside the user's established normal working hours.

The configured response can include:

Adaptive Challenge
or
Block
Role Mismatch

Detects activity that is inconsistent with the user's normal role or behaviour pattern.

Such activity can increase the user's risk and may require justification.

Repeated Attempts

Detects repeated transfer attempts, particularly when previous attempts were blocked.

The system can escalate the associated severity and correlate repeated activities.

Channel Chaining

Detects suspicious sequences involving multiple channels.

Example:

Copy
  ↓
Archive
  ↓
USB
  ↓
Cloud Upload

Related activities can be correlated into a single security incident.

🔎 Behaviour Anomaly Severity

UEBA anomaly scores are evaluated using configured thresholds.

Supported anomaly severity levels include:

LOW
MEDIUM
HIGH
CRITICAL

The final severity is determined by the configured anomaly scoring logic.

🚨 Risk Alerts

Risk alerts are generated when configured risk thresholds are reached.

Alert information can include:

User
Risk score
Risk level
Alert type
Risk reason
Timestamp
Related event
Related incident

🛡️ Incident Management

Security incidents can be generated when activity meets configured risk or UEBA conditions.

Incident information can include:

Incident ID
User
Device
Event
Risk score
Risk level
Detection reason
Incident status
Timestamp
Related alerts

This allows suspicious activities to be investigated and correlated.

🗄️ Database Schema

PostgreSQL is used for persistent storage.

Major entities include:

Users

Stores user identity and organizational information.

Devices

Stores device information associated with users.

Policies

Stores DLP policy information.

DLP Events

Stores monitored data transfer activities.

DLP event information can include:

User
Device
Policy
Event type
Data classification
Channel
Destination
Volume
Severity
Action
Timestamp
Risk Scores

Stores calculated risk information including:

User
Department
Data type
Classification
Detection rule
Action
Channel
Destination
Severity
Data sensitivity score
Destination trust score
User risk score
Device trust score
Behaviour anomaly score
Transfer volume score
Channel risk score
Severity score
Frequency risk score
Total risk score
Risk level
Risk reason
Timestamp
Risk Factors

Stores individual risk factor information used during risk analysis.

Risk Alerts

Stores generated risk alerts.

Incidents

Stores security incidents associated with DLP activities.

Behaviour Profiles

Stores normal behavioural baselines for users.

Behaviour Anomalies

Stores detected deviations from normal user behaviour.

🔗 Database Relationships

User
 │
 ├── Devices
 │
 ├── DLP Events
 │       │
 │       ├── Policy
 │       ├── Device
 │       └── Risk Score
 │
 ├── Risk Scores
 │
 ├── Risk Alerts
 │
 └── Behaviour Profile
          │
          └── Behaviour Anomalies

DLP Events
     │
     └── Incidents

The relationships are implemented using SQLAlchemy models and PostgreSQL foreign keys.

🤖 ML / AI Components

The current Risk Analytics and UEBA implementation primarily uses rule-based and statistical behaviour analysis.

UEBA uses behavioural baselines and configured detection logic to identify anomalous activities.

The current implementation does not require a separately trained machine-learning model for the core Risk Analytics and UEBA functionality.

Future versions may incorporate machine-learning techniques for:

Advanced anomaly detection
Adaptive behavioural modelling
User risk prediction
Dynamic baseline generation
Context-aware risk scoring

🖥️ Dashboard Integration

The dashboard acts as the presentation layer for the backend.

Dashboard
    │
    │ REST API
    ▼
FastAPI Backend
    │
    ├── Risk Analytics
    ├── UEBA
    ├── Alerts
    ├── Incidents
    └── PostgreSQL

The dashboard consumes information from backend APIs.

Dashboard components can display:

Security posture
Risk distribution
Risk scores
Risk levels
Risk actions
Risk factors
High-risk users
Department risk
Risk alerts
Incidents
Behaviour profiles
Behaviour anomalies
UEBA activity

🔍 Explainable Risk

Risk decisions are designed to be understandable and traceable.

Risk information can include:

Risk score
Risk level
Enforcement action
User
Device
Data classification
Channel
Destination
Severity
Detection rule
Individual risk factors
Risk reason
Timestamp
Related event
Related incident

This provides security teams with context for understanding a risk decision.

📝 Audit and Traceability

Risk and enforcement decisions can be traced to the underlying DLP activity.

Relevant evidence can include:

Event ID
User
Device
Timestamp
Data classification
Channel
Destination
Detection rule
Risk score
Risk factors
Action
Alert
Incident

This supports security investigation and audit requirements.

🔒 Security Considerations

The following practices should be followed:

Never commit .env files.
Never expose database credentials.
Never hard-code production passwords.
Use secure database connections where required.
Restrict database credentials according to the deployment environment.
Validate API inputs.
Apply authentication and authorization in production.
Use HTTPS/TLS in production.
Keep secrets outside source control.
Avoid exposing sensitive information in logs.

🧪 Testing

The backend can be tested using:

Swagger
http://127.0.0.1:8000/docs
Database Testing

Validate:

Database connectivity
Table creation
DLP events
Risk scores
Risk factors
Alerts
Incidents
Behaviour profiles
Behaviour anomalies
Risk Analytics Testing

Validate:

Risk calculation
Risk factor values
Risk classification
Enforcement action
Alert generation
Incident generation
High-risk user detection
UEBA Testing

Validate:

Behaviour profile generation
Baseline values
After-hours detection
Bulk activity detection
Role mismatch detection
Repeated activity detection
Channel chaining
Behaviour anomaly severity
UEBA alerts
Dashboard Testing

Validate:

Dashboard data loading
API responses
Risk values against backend values
UEBA values against backend values
Chart rendering
Alert display
Incident display
No sensitive credentials exposed

🔄 Project Workflow

DLP Activity
     │
     ▼
DLP Event
     │
     ├───────────────────┐
     ▼                   ▼
Risk Analytics          UEBA
     │                   │
     ▼                   ▼
Risk Factors        Behaviour Baseline
     │                   │
     ▼                   ▼
Risk Score          Anomaly Detection
     │                   │
     └─────────┬─────────┘
               ▼
        Risk Evaluation
               │
               ▼
       Enforcement Action
               │
         ┌─────┴─────┐
         │           │
         ▼           ▼
       Alert       Incident
         │           │
         └─────┬─────┘
               ▼
        DLP Dashboard

📈 Risk Evaluation Workflow

DLP Event
    ↓
Identify User and Device
    ↓
Identify Data Classification
    ↓
Evaluate Destination
    ↓
Evaluate Channel
    ↓
Evaluate Transfer Volume
    ↓
Evaluate User Behaviour
    ↓
Calculate Risk Factors
    ↓
Calculate Total Risk Score
    ↓
Classify Risk Level
    ↓
Determine Enforcement Action
    ↓
Generate Alert / Incident when required
    ↓
Display Results in Dashboard

👤 UEBA Workflow

User Activity
      ↓
Collect DLP Events
      ↓
Build Behaviour Profile
      ↓
Establish Baseline
      ↓
Compare New Activity
      ↓
Detect Behaviour Deviation
      ↓
Calculate Anomaly Score
      ↓
Determine Anomaly Severity
      ↓
Update Risk Evaluation
      ↓
Generate UEBA Alert / Incident
      ↓
Display Results in Dashboard

📋 Rulebook Alignment

The current Risk Analytics and UEBA implementation is aligned with the configured AepttasShield Enterprise DLP rulebook for:

Adaptive risk scoring
Risk-based enforcement
Risk factor evaluation
UEBA detection scenarios
Behaviour anomaly detection
Risk alerts
Incident handling
Explainable risk information
Audit traceability

Configured adaptive risk handling:

0–19    → Allow / Monitor
20–39   → Warn
40–59   → Justify
60–79   → Block / Adaptive Challenge
80–100  → Block + Incident + Automated Response

📊 Project Status

The current implementation includes:

Risk Analytics backend
Risk scoring
Risk factor analysis
Risk alerts
Incident handling
High-risk user analysis
User behaviour profiling
UEBA anomaly detection
UEBA API integration
PostgreSQL integration
Dashboard integration
Swagger/OpenAPI documentation

Risk Analytics and UEBA have been reviewed against the configured AepttasShield Enterprise DLP rulebook.

🔮 Future Enhancements

Potential future enhancements include:

Advanced machine-learning based anomaly detection
Adaptive user risk modelling
Automated response orchestration
Real-time event streaming
Advanced cross-channel correlation
Extended audit reporting
Role-based access control
Authentication and authorization
Threat intelligence integration
Automated compliance reporting
Production monitoring and observability

📦 Development

AepttasShield Enterprise DLP is developed as part of the AepttasShield Enterprise Security Platform.

The backend follows a modular architecture that separates:

API layer
Database models
Schemas
Core configuration
Business services
Risk Analytics
UEBA
Dashboard integration

This allows individual modules to be developed, tested, and maintained independently.


📞 Quick Start

# Create virtual environment
python -m venv venv

# Activate environment - Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI
uvicorn app.main:app --reload

Then open:

Application:
http://127.0.0.1:8000

Swagger:
http://127.0.0.1:8000/docs

ReDoc:
http://127.0.0.1:8000/redoc

📄 License

This project is intended for internal development and authorized use within the AepttasShield Enterprise Security Platform.

Unauthorized distribution, modification, or deployment should follow applicable organizational policies and access controls.