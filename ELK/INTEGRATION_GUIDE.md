# Integration Guide - ELK Stack with Cloud Security Modules

## Overview

This guide explains how to configure log collection from all cloud security modules and integrate them with the ELK Stack SIEM for comprehensive threat detection and analysis.

## Module Integration

### 1. Honeypot Integration

**Log Location**: `../Honeypot/honeypot.log`

**Log Format**:
```
[SSH] 192.168.1.100 (8 attempts)...
[FTP] 10.0.0.50 (5 attempts)...
[HTTP] Attack payload sent: admin
```

**Configuration**:
- Volume mount in docker-compose.yml: `../Honeypot:/honeypot:ro`
- Logstash filter tags: `honeypot`
- Threat scoring: MEDIUM (50 points)

**Key Fields to Extract**:
- `attack_type`: SSH, FTP, HTTP
- `attacker_ip`: Source IP address
- `username`: Captured login attempts
- `password`: Captured credentials

---

### 2. Malware Analysis Integration

**Log Location**: `../Malware-Analysis/MA/logs/`

**Log Format**:
```
Decision Tree - abc123hash456 - MALWARE - 95.4%
Deep Learning - def789hash000 - BENIGN - 87.2%
```

**Configuration**:
- Logstash filter tags: `malware-analysis`
- Threat scoring: CRITICAL (100 points for malware)
- Index pattern: `security-logs-malware-analysis-*`

**Key Fields to Extract**:
- `analysis_type`: Decision Tree, Deep Learning, Two-Stage
- `file_hash`: SHA256 or MD5
- `verdict`: MALWARE, BENIGN, SUSPICIOUS
- `confidence`: Detection confidence percentage
- `model_accuracy`: Model performance metrics

---

### 3. Network Traffic Classifier Integration

**Log Location**: `../Network-Traffic-Classifier/results/`

**Log Format**:
```
2026-02-06 10:30:01 | 192.168.1.1 -> 10.0.0.1:443 | TCP | NORMAL | 2048 bytes
2026-02-06 10:30:02 | 192.168.1.5 -> 8.8.8.8:53 | UDP | ANOMALY | 512 bytes
```

**Configuration**:
- Logstash filter tags: `network-traffic`
- Threat scoring: HIGH (75 points for anomalies)
- Index pattern: `security-logs-network-traffic-*`

**Key Fields to Extract**:
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `dst_port`: Destination port
- `protocol`: TCP, UDP, ICMP, etc.
- `traffic_class`: NORMAL, ANOMALY, SUSPICIOUS
- `bytes_transferred`: Data volume

---

### 4. Web Intrusion Detection System Integration

**Log Location**: `../Web-Intrusion-Detection/data2/`

**Log Format**:
```
[2026-02-06 10:30:01] 192.168.1.5 - POST /api/login - XSS detected
[2026-02-06 10:30:02] 192.168.1.7 - GET /admin?id=1' OR '1'='1 - SQL Injection
```

**Configuration**:
- Logstash filter tags: `web-ids`
- Threat scoring: CRITICAL (100 points for web attacks)
- Index pattern: `security-logs-web-ids-*`

**Key Fields to Extract**:
- `timestamp`: Event time
- `client_ip`: Attacking client IP
- `method`: HTTP method (GET, POST, PUT, DELETE)
- `endpoint`: URL path
- `attack_type`: XSS, SQL Injection, CSRF, RFI, LFI, Command Injection
- `payload`: Attack payload (sanitized)

---

## Setup Instructions

### Step 1: Create Log Directories

```powershell
mkdir logs\{honeypot,malware-analysis,network-traffic,web-ids,processed}
```

### Step 2: Configure Log Sources

Update the Logstash configuration to include all module logs:

```conf
input {
  file {
    path => "/logs/honeypot/*.log"
    tags => ["honeypot"]
  }
  file {
    path => "/logs/malware-analysis/*.log"
    tags => ["malware-analysis"]
  }
  file {
    path => "/logs/network-traffic/*.log"
    tags => ["network-traffic"]
  }
  file {
    path => "/logs/web-ids/*.log"
    tags => ["web-ids"]
  }
}
```

### Step 3: Start ELK Stack

```powershell
cd ELK
.\setup.ps1 -Action setup
.\setup.ps1 -Action start
```

### Step 4: Verify Integration

```powershell
# Check Elasticsearch has indices
curl http://localhost:9200/_cat/indices

# Check Kibana is running
curl http://localhost:5601/api/status

# View Logstash logs
docker compose logs logstash -f
```

### Step 5: Configure Kibana

1. **Create Index Pattern**:
   - Go to: http://localhost:5601
   - Stack Management → Index Patterns
   - New index pattern: `security-logs-*`
   - Time field: `@timestamp`

2. **Create Visualizations**:
   - See examples in `kibana-export.json`

3. **Build Dashboards**:
   - Combine visualizations for each module
   - Set appropriate time ranges
   - Configure auto-refresh intervals

---

## Correlation Rules & Threat Detection

### Rule 1: Multi-Module Attack Correlation
```json
{
  "name": "Coordinated Attack Detection",
  "query": {
    "bool": {
      "must": [
        { "terms": { "tags": ["honeypot", "web-ids"] } },
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "match": { "threat_level": ["high", "critical"] } }
      ]
    }
  },
  "alert": "Possible coordinated attack from multiple vectors"
}
```

### Rule 2: Attacker Profile Tracking
```json
{
  "name": "Attacker IP Tracking",
  "query": {
    "bool": {
      "should": [
        { "match": { "attacker_ip": "192.168.1.100" } },
        { "match": { "src_ip": "192.168.1.100" } }
      ]
    }
  },
  "alert": "Known attacker IP detected across multiple modules"
}
```

### Rule 3: Malware Distribution Attack
```json
{
  "name": "Malware & Network Anomaly Correlation",
  "query": {
    "bool": {
      "must": [
        { "match": { "verdict": "MALWARE" } },
        { "match": { "traffic_class": "ANOMALY" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "alert": "Malware detected with suspicious network activity"
}
```

---

## Threat Score Calculation

Total Threat Score = Σ (Module Score × Weight) / Total Weight

| Module | Base Score | Weight | Description |
|--------|-----------|--------|-------------|
| Honeypot (Critical) | 100 | 1.0 | SSH/FTP bruteforce, Multiple attempts |
| Honeypot (Medium) | 50 | 0.7 | Single failed attempt |
| Malware (Critical) | 100 | 1.5 | High-confidence malware detection |
| Malware (Medium) | 50 | 1.0 | Suspicious file (low confidence) |
| Network (High) | 75 | 0.8 | Traffic anomalies, suspicious ports |
| Network (Low) | 25 | 0.5 | Minor deviations from normal |
| Web IDS (Critical) | 100 | 1.2 | Successful exploit attempts |
| Web IDS (Medium) | 50 | 0.9 | Blocked malicious requests |

**Example**:
```
Threat Score = (100×1.0 + 75×0.8 + 100×1.5) / (1.0 + 0.8 + 1.5)
             = (100 + 60 + 150) / 3.3
             = 310 / 3.3
             = 93.9 / 100 (CRITICAL ALERT)
```

---

## Dashboard Recommendations

### Real-Time Monitoring Dashboard
- Update interval: 10 seconds
- Time range: Last 24 hours
- Key metrics:
  - Critical alerts count
  - Recent attacks timeline
  - Top attackers
  - Threat score trend

### Incident Investigation Dashboard
- Update interval: Manual (1 hour)
- Time range: Last 7 days
- Features:
  - Event correlation view
  - Attack chain visualization
  - MITRE ATT&CK mapping
  - Evidence collection timeline

### Compliance & Reporting Dashboard
- Update interval: Daily
- Time range: Last 30/90 days
- Metrics:
  - Detection rate by module
  - Response time metrics
  - Incident resolution rate
  - False positive tracking

---

## Performance Optimization

### Elasticsearch Tuning
```yaml
elasticsearch:
  environment:
    - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    - "indices.memory.index_buffer_size=40%"
```

### Logstash Optimization
```conf
filter {
  # Batch processing
  mutate {
    id => "optimize-batch"
  }
}

output {
  elasticsearch {
    bulk_max_size => 5000
    worker => 8
  }
}
```

### Index Optimization
```bash
# Set refresh interval for bulk ingestion
curl -X PUT "localhost:9200/security-logs-*/_settings" -H 'Content-Type: application/json' -d'{
  "index": {
    "refresh_interval": "30s",
    "max_result_window": 50000
  }
}'
```

---

## Troubleshooting

### Issue: Logs Not Appearing in Kibana

1. **Check log file paths**:
   ```bash
   ls -la logs/{honeypot,malware-analysis,network-traffic,web-ids}/
   ```

2. **Verify Logstash is processing**:
   ```bash
   docker compose logs logstash | grep -i "error\|processing"
   ```

3. **Check Elasticsearch indices**:
   ```bash
   curl http://localhost:9200/_cat/indices?v
   ```

### Issue: High CPU/Memory Usage

1. **Reduce batch size** in Logstash
2. **Increase JVM heap** for Elasticsearch
3. **Enable index compression**:
   ```bash
   curl -X PUT "localhost:9200/security-logs-*/_settings" -d'{"index":{"codec":"best_compression"}}'
   ```

### Issue: Slow Dashboard Queries

1. **Use appropriate time ranges**
2. **Add field filters** instead of wildcard searches
3. **Create specific index patterns** per module
4. **Enable query caching**

---

## Next Steps

1. **Configure Alerting** - Set up critical threshold alerts
2. **Implement SOAR Integration** - Automated response workflows
3. **Add Threat Intelligence** - IP reputation and malware feeds
4. **Enable Machine Learning** - Anomaly detection automation
5. **Compliance Reporting** - Automated compliance exports

---

**Status**: Ready for comprehensive security monitoring
**Version**: 1.0
**Last Updated**: 2026-02-06
