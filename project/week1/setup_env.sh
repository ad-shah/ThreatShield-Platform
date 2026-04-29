#!/usr/bin/env bash
set -e

info()  { echo -e "\033[0;32m[INFO]\033[0m  $1"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $1"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; exit 1; }

info "Checking Python version..."
python3 --version || error "Python 3 not found"

info "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q

info "Installing Python packages..."
pip install -q \
    requests==2.31.0 \
    beautifulsoup4==4.12.3 \
    pymongo==4.7.2 \
    python-dotenv==1.0.1 \
    validators==0.28.1 \
    schedule==1.2.1 \
    pytest==8.2.0 \
    pytest-mock==3.14.0

info "Checking MongoDB..."
if command -v mongod &> /dev/null; then
    info "MongoDB found"
    sudo systemctl start mongod 2>/dev/null || true
else
    warn "MongoDB not found — starting via Docker..."
    docker run -d --name tip_mongo \
        -p 27017:27017 \
        mongo:7.0 2>/dev/null || true
fi

if [ ! -f .env ]; then
    cat > .env << 'EOF'
MONGO_URI=mongodb://localhost:27017/threat_intel
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
POLL_INTERVAL_MINUTES=30
LOG_LEVEL=INFO
EOF
    info ".env created"
fi

mkdir -p logs
info "Logs directory ready"

echo ""
echo "========================================"
echo "  Setup complete! Next steps:"
echo "========================================"
echo "  1. source venv/bin/activate"
echo "  2. nano .env  (add your API keys)"
echo "  3. python ingest.py --dry-run"
echo "  4. python ingest.py"
echo ""
