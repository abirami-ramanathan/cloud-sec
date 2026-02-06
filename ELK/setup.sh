#!/bin/bash

# ELK Stack Setup Script
# This script initializes the ELK Stack and configures log collection

set -e

echo "========================================================================"
echo "ELK STACK SETUP - Cloud Security SIEM"
echo "========================================================================"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
echo "Project Root: $PROJECT_ROOT"
echo "ELK Directory: $SCRIPT_DIR"

# Create log directory structure
echo ""
echo "[1] Creating log directories..."
mkdir -p "$SCRIPT_DIR"/logs/{honeypot,malware-analysis,network-traffic,web-ids,processed}
echo "    ✓ Log directories created"

# Create symlinks to source log files
echo ""
echo "[2] Setting up log symlinks..."

# Honeypot logs
if [ -f "$PROJECT_ROOT/Honeypot/honeypot.log" ]; then
    ln -sf "$PROJECT_ROOT/Honeypot/honeypot.log" "$SCRIPT_DIR/logs/honeypot/" 2>/dev/null || true
    echo "    ✓ Honeypot logs linked"
else
    echo "    ⚠ Honeypot logs not found (start honeypot first)"
fi

# Network Traffic Classifier logs
if [ -d "$PROJECT_ROOT/Network-Traffic-Classifier" ]; then
    find "$PROJECT_ROOT/Network-Traffic-Classifier" -name "*.log" -o -name "*.csv" | while read file; do
        ln -sf "$file" "$SCRIPT_DIR/logs/network-traffic/" 2>/dev/null || true
    done
    echo "    ✓ Network traffic logs linked"
fi

# Web IDS logs
if [ -d "$PROJECT_ROOT/Web-Intrusion-Detection" ]; then
    find "$PROJECT_ROOT/Web-Intrusion-Detection" -name "*.log" -o -name "*.csv" | while read file; do
        ln -sf "$file" "$SCRIPT_DIR/logs/web-ids/" 2>/dev/null || true
    done
    echo "    ✓ Web IDS logs linked"
fi

# Create Kibana dashboards template
echo ""
echo "[3] Creating dashboard templates..."
cat > "$SCRIPT_DIR/kibana-dashboards.json" << 'EOF'
{
  "version": "8.11.0",
  "dashboards": [
    {
      "id": "security-overview",
      "title": "Security Overview",
      "description": "Real-time security posture and threat metrics",
      "panels": [
        {
          "type": "metric",
          "title": "Critical Alerts (24h)",
          "query": "threat_level:critical AND @timestamp:[now-24h TO now]"
        },
        {
          "type": "metric",
          "title": "Total Attacks",
          "query": "log_source:honeypot OR log_source:web-ids"
        },
        {
          "type": "time_histogram",
          "title": "Attacks Over Time",
          "query": "_all"
        },
        {
          "type": "bar_chart",
          "title": "Top Threat Types",
          "aggregation": "attack_type"
        },
        {
          "type": "map",
          "title": "Attacker Locations",
          "field": "attacker_ip"
        }
      ]
    },
    {
      "id": "threat-detection",
      "title": "Threat Detection",
      "description": "Detailed threat analysis and detection metrics",
      "panels": [
        {
          "type": "table",
          "title": "Critical Threats",
          "query": "threat_level:critical",
          "fields": ["@timestamp", "attack_type", "attacker_ip", "threat_score"]
        },
        {
          "type": "bar_chart",
          "title": "Detection Accuracy",
          "aggregation": "verdict",
          "query": "log_source:malware-analysis"
        }
      ]
    },
    {
      "id": "honeypot-activity",
      "title": "Honeypot Activity",
      "description": "SSH, FTP, HTTP attack patterns",
      "panels": [
        {
          "type": "pie_chart",
          "title": "Attack Types",
          "aggregation": "attack_type"
        },
        {
          "type": "table",
          "title": "Captured Credentials",
          "query": "log_source:honeypot AND username:*"
        },
        {
          "type": "bar_chart",
          "title": "Top Attackers",
          "aggregation": "attacker_ip",
          "size": 10
        }
      ]
    },
    {
      "id": "malware-analysis",
      "title": "Malware Analysis",
      "description": "File analysis and detection results",
      "panels": [
        {
          "type": "metric",
          "title": "Total Files Analyzed",
          "query": "log_source:malware-analysis"
        },
        {
          "type": "pie_chart",
          "title": "Malware vs Benign",
          "aggregation": "verdict"
        },
        {
          "type": "bar_chart",
          "title": "Top Malware Families",
          "aggregation": "malware_family"
        }
      ]
    },
    {
      "id": "network-analysis",
      "title": "Network Traffic Analysis",
      "description": "Network flow and anomaly detection",
      "panels": [
        {
          "type": "time_histogram",
          "title": "Traffic Volume",
          "query": "log_source:network-traffic"
        },
        {
          "type": "bar_chart",
          "title": "Top Protocols",
          "aggregation": "protocol"
        },
        {
          "type": "table",
          "title": "Anomalous Flows",
          "query": "threat_level:high OR threat_level:critical"
        }
      ]
    }
  ]
}
EOF
echo "    ✓ Dashboard templates created"

# Check Docker & Docker Compose
echo ""
echo "[4] Checking Docker installation..."
if command -v docker &> /dev/null; then
    echo "    ✓ Docker found: $(docker --version)"
else
    echo "    ✗ Docker not found. Please install Docker first."
    exit 1
fi

if command -v docker-compose &> /dev/null; then
    echo "    ✓ Docker Compose found: $(docker-compose --version)"
elif docker compose version &> /dev/null; then
    echo "    ✓ Docker Compose (integrated) found"
else
    echo "    ✗ Docker Compose not found."
    exit 1
fi

# Display next steps
echo ""
echo "========================================================================"
echo "SETUP COMPLETE!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Ensure all modules are running and generating logs:"
echo "   - Honeypot (Honeypot/)"
echo "   - Malware-Analysis (Malware-Analysis/MA/)"
echo "   - Network-Traffic-Classifier (Network-Traffic-Classifier/)"
echo "   - Web-Intrusion-Detection (Web-Intrusion-Detection/)"
echo ""
echo "2. Start the ELK Stack:"
echo "   cd $SCRIPT_DIR"
echo "   docker compose up -d"
echo ""
echo "3. Wait for services to start (3-5 minutes):"
echo "   docker compose logs -f"
echo ""
echo "4. Access Kibana:"
echo "   http://localhost:5601"
echo ""
echo "5. Configure Kibana:"
echo "   - Go to Stack Management > Index Patterns"
echo "   - Create index pattern: security-logs-*"
echo "   - Set @timestamp as time field"
echo ""
echo "6. Import dashboards:"
echo "   - Stack Management > Saved Objects > Import"
echo "   - Select kibana-dashboards.json"
echo ""
echo "========================================================================"
echo ""
echo "Configuration files:"
echo "  - docker-compose.yml  : ELK services definition"
echo "  - logstash.conf       : Log processing pipeline"
echo "  - filebeat.yml        : Log collection configuration"
echo "  - README.md           : Complete documentation"
echo ""
echo "Log directories:"
echo "  - logs/honeypot/      : Honeypot logs"
echo "  - logs/malware-analysis/ : Malware analysis logs"
echo "  - logs/network-traffic/ : Network traffic logs"
echo "  - logs/web-ids/       : Web IDS logs"
echo "  - logs/processed/     : Processed output logs"
echo ""
