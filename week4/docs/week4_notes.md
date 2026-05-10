# Week 4 — Dashboard, Alerting & Final Testing

## What this week adds
- SOC Web Dashboard (dark cyber theme)
- FastAPI REST backend
- Email alerting for critical threats
- Rollback button for SOC analysts
- Full test suite

## How to run

### Start MongoDB first
sudo systemctl start mongod

### Start the dashboard
cd week4
source ../week1/venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000 --reload

### Open in browser
http://localhost:8000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/stats | Dashboard stats |
| GET | /api/indicators | List indicators |
| GET | /api/top-threats | Top 10 threats |
| GET | /api/audit | Audit log |
| GET | /api/blocked | Blocked IPs |
| POST | /api/rollback/{ip} | Rollback block |
| GET | /api/health | Health check |

## Email Alerting
Add these to .env file:
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
ALERT_EMAIL=soc_team@company.com

## Run tests
pytest tests/ -v

## Run alerting check
python alerting.py
