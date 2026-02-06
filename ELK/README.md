# ELK Stack SIEM - Cloud Security

## Overview

This ELK (Elasticsearch, Logstash, Kibana) Stack implements a comprehensive **Security Information and Event Management (SIEM)** system that aggregates, analyzes, and visualizes security data from all modules:

- **Honeypot** - SSH, FTP, HTTP attack detection
- **Malware Analysis** - File analysis and detection
- **Network Traffic Classifier** - Traffic pattern analysis
- **Web Intrusion Detection System (WIDS)** - HTTP attack detection

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LOG SOURCES                              │
├─────────────────────────────────────────────────────────────┤
│ Honeypot │ Malware Analysis │ WIDS │ Network Traffic       │
└──────────┬──────────┬────────┬──────┬──────────────────────┘
           │          │        │      │
           └──────────┴────────┴──────┘
                      │
            ┌─────────▼──────────┐
            │   Filebeat/        │
            │   Logstash         │
            │   (Log Collector)  │
            └─────────┬──────────┘
                      │
         ┌────────────▼───────────────┐
         │   Elasticsearch            │
         │   (Full-Text Search Index) │
         └────────────┬───────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
   ┌────▼────┐  ┌────▼────┐  ┌────▼─────┐
   │ Kibana  │  │ API     │  │ Alerts   │
   │Dashboard│  │Queries  │  │& Reports │
   └─────────┘  └─────────┘  └──────────┘
```

## Components

### 1. **Elasticsearch** (Port 9200)
- Full-text search and analytics engine
- Stores all security events with indexing
- Enables fast querying and aggregation
- Real-time analysis

### 2. **Kibana** (Port 5601)
- Web UI for visualization and exploration
- Creates dashboards from security data
- Real-time monitoring and alerting
- Threat detection and analysis

### 3. **Logstash** (Port 5000)
- Data processing pipeline
- Parses and enriches log data
- Filters for threat detection
- Threat scoring and classification

### 4. **Filebeat**
- Lightweight log shipper
- Collects logs from all modules
- Forwards to Elasticsearch/Logstash
- Minimal resource usage

## Quick Start

### Prerequisites
- Docker & Docker Compose installed
- All modules (Honeypot, Malware-Analysis, WIDS, Network-Traffic-Classifier) running
- Logs being generated in respective folders

### 1. Start the ELK Stack

```bash
cd ELK
docker compose up -d
```

### 2. Wait for Services to Initialize

```bash
# Check status
docker compose ps

# View logs
docker compose logs -f
```

Services typically start in this order:
1. Elasticsearch (takes ~30-60 seconds)
2. Logstash (depends on Elasticsearch)
3. Kibana (depends on Elasticsearch)
4. Filebeat (depends on Elasticsearch)

### 3. Access Kibana Dashboard

```
http://localhost:5601
```

### 4. Configure Log Sources

Create a `logs` directory structure:

```
ELK/
├── logs/
│   ├── honeypot/
│   │   └── honeypot.log
│   ├── malware-analysis/
│   │   └── *.log
│   ├── network-traffic/
│   │   └── *.log
│   ├── web-ids/
│   │   └── *.log
│   └── processed/
│       └── (Logstash output)
```

Symlink or copy logs from modules:

```bash
# Create log directories
mkdir -p logs/{honeypot,malware-analysis,network-traffic,web-ids,processed}

# Symlink from Honeypot
ln -s ../Honeypot/honeypot.log logs/honeypot/

# Symlink from other modules
ln -s ../Malware-Analysis/MA/logs/* logs/malware-analysis/
ln -s ../Network-Traffic-Classifier/*.log logs/network-traffic/
ln -s ../Web-Intrusion-Detection/*.log logs/web-ids/
```

## Log Processing Pipeline

### Honeypot Logs
**Pattern**: `[SSH] 192.168.1.100 (8 attempts)...`

Parsed fields:
- `attack_type`: SSH, FTP, HTTP
- `attacker_ip`: Source IP
- `log_source`: honeypot
- `threat_level`: medium
- `threat_score`: 50

### Malware Analysis Logs
**Pattern**: `Decision Tree - abc123hash - MALWARE - 95%`

Parsed fields:
- `analysis_type`: Decision Tree, Deep Learning
- `file_hash`: SHA256/MD5
- `verdict`: MALWARE, BENIGN
- `confidence`: Detection confidence %
- `threat_level`: critical/low
- `threat_score`: 100 or 25

### Network Traffic Logs
**Pattern**: `192.168.1.1 -> 10.0.0.1:443 TCP NORMAL`

Parsed fields:
- `src_ip`: Source IP
- `dst_ip`: Destination IP
- `dst_port`: Destination port
- `protocol`: TCP, UDP, ICMP
- `traffic_class`: Classification
- `threat_level`: high/low

### Web IDS Logs
**Pattern**: `01/Feb/2026:10:30:01 192.168.1.5 GET /admin XSS`

Parsed fields:
- `timestamp`: Event time
- `client_ip`: Attacker IP
- `method`: HTTP method
- `endpoint`: URL path
- `attack_type`: XSS, SQL, CSRF, RFI, LFI, Command Injection
- `threat_level`: critical/medium

## Threat Scoring System

| Threat Level | Score | Examples |
|--------------|-------|----------|
| **Critical** | 100   | Malware detected, XSS attack, SQL injection |
| **High**     | 75    | Suspicious network behavior, multiple failed logins |
| **Medium**   | 50    | Honeypot triggers, anomalies |
| **Low**      | 25    | Normal traffic, benign files |

## Kibana Dashboards

### 1. **Security Overview** Dashboard
- Real-time threat count by severity
- Attack timeline (last 24 hours)
- Top attackers (by IP)
- Top attack types
- Threat score distribution

### 2. **Threat Detection** Dashboard
- Critical alerts list
- Attack patterns and trends
- False positive tracking
- Detection accuracy metrics

### 3. **Network Traffic Analysis** Dashboard
- Traffic volume by protocol
- Source/destination IPs
- Port activity heatmap
- Bandwidth anomalies

### 4. **Malware Analysis** Dashboard
- Detection rate by model
- File reputation scores
- Detected malware families
- Confidence levels

### 5. **Honeypot Activity** Dashboard
- Attack attempts by type (SSH, FTP, HTTP)
- Captured credentials
- Attacker IP geolocation
- Attack payload analysis

## Advanced Queries

### Find Critical Threats
```json
GET security-logs-*/_search
{
  "query": {
    "match": {
      "threat_level": "critical"
    }
  },
  "aggs": {
    "top_threats": {
      "terms": {
        "field": "attack_type",
        "size": 10
      }
    }
  }
}
```

### Correlate Honeypot & Malware Analysis
```json
GET security-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "attacker_ip": "192.168.1.100" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}
```

### High-Risk Traffic Patterns
```json
GET security-logs-network-traffic-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "threat_level": "high" } },
        { "match": { "dst_port": [22, 445, 3389, 8080] } }
      ]
    }
  }
}
```

## Key Features

### 1. **Real-Time Analysis**
- Events indexed within seconds
- Instant threat detection
- Up-to-the-minute dashboard updates

### 2. **Comprehensive Data Correlation**
- Cross-module attack tracking
- Attacker behavioral analysis
- Multi-stage attack detection

### 3. **Threat Scoring & Prioritization**
- Automatic severity assessment
- Contextual threat scoring
- False positive reduction

### 4. **Scalable Architecture**
- Handles thousands of events/second
- Index lifecycle management (ILM)
- Automatic index rotation

### 5. **Data Retention**
- Configurable retention policies
- Automated archiving
- Compliance-ready logging

## Monitoring & Maintenance

### Check Service Health
```bash
# Container status
docker compose ps

# View logs
docker compose logs elasticsearch
docker compose logs kibana
docker compose logs logstash
docker compose logs filebeat

# Health checks
curl http://localhost:9200/_cluster/health
curl http://localhost:5601/api/status
```

### View Indices
```bash
# List all indices
curl http://localhost:9200/_cat/indices

# View index statistics
curl http://localhost:9200/security-logs-*/_stats
```

### Monitor Disk Usage
```bash
# Check storage
curl http://localhost:9200/_cat/nodes?v
```

## Troubleshooting

### Logstash Not Processing Logs
```bash
# Check Logstash logs
docker compose logs logstash

# Verify Elasticsearch connection
curl http://localhost:9200/_cluster/health
```

### Kibana Visualizations Empty
1. Ensure logs are being collected (check `logs/` folder)
2. Verify Logstash is running: `docker compose logs logstash`
3. Check index existence: `curl http://localhost:9200/_cat/indices`
4. Force refresh in Kibana: Stack Management > Index Patterns > Refresh

### Low Disk Space
```bash
# Delete old indices (older than 30 days)
curl -X DELETE http://localhost:9200/security-logs-*
```

## Security Best Practices

1. **Enable Authentication** (Production)
   - Set `xpack.security.enabled=true` in Elasticsearch
   - Configure user credentials

2. **Network Isolation**
   - Use firewall rules to restrict access
   - Only expose Kibana on internal network

3. **Data Encryption**
   - Enable TLS for Elasticsearch
   - Encrypt data at rest

4. **Access Control**
   - Implement role-based access (RBAC)
   - Regular audit logs

5. **Backup Strategy**
   - Daily snapshot backups
   - Verify restore procedures

## Performance Tuning

### Elasticsearch Heap Size
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
```

### Logstash Batch Processing
```conf
output {
  elasticsearch {
    bulk_max_size => 5000
    worker => 8
    compression_level => 9
  }
}
```

### Index Refresh Interval
```bash
curl -X PUT "localhost:9200/security-logs-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "refresh_interval": "30s"
  }
}
'
```

## Proactive Threat Detection

### 1. **Alerting**
Set up Kibana alerts for:
- Multiple failed login attempts (Honeypot)
- Critical malware detection
- Suspicious network traffic patterns
- Web application attacks

### 2. **Anomaly Detection**
- Machine learning for baseline establishment
- Deviation from normal patterns
- Automated incident escalation

### 3. **Threat Intelligence**
- IP reputation scoring
- Known malware signatures
- Attack pattern correlation

### 4. **Compliance & Reporting**
- Automated compliance reports
- Audit trail maintenance
- Incident timeline reconstruction

## Integration with Other Tools

The ELK Stack can integrate with:
- **SOAR Platforms** (Orchestration)
- **Ticketing Systems** (Incident Management)
- **Notification Services** (Slack, PagerDuty)
- **Threat Intelligence Feeds** (Enrichment)

---

**Status**: Ready for production-grade log aggregation and security analysis
**Version**: 1.0
**Last Updated**: 2026-02-06
