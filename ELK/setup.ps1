param(
    [Parameter(Mandatory=$false)]
    [string]$Action = "setup"
)

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "ELK STACK SETUP - Cloud Security SIEM" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host ""
Write-Host "Project Root: $ProjectRoot"
Write-Host "ELK Directory: $ScriptDir"

# Function to create directories
function Setup-Directories {
    Write-Host ""
    Write-Host "[1] Creating log directories..." -ForegroundColor Cyan
    
    @(
        "$ScriptDir\logs\honeypot",
        "$ScriptDir\logs\malware-analysis",
        "$ScriptDir\logs\network-traffic",
        "$ScriptDir\logs\web-ids",
        "$ScriptDir\logs\processed"
    ) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "    Created: $_" -ForegroundColor Green
        }
    }
    Write-Host "    ✓ Log directories created" -ForegroundColor Green
}

# Function to setup log collection
function Setup-LogCollection {
    Write-Host ""
    Write-Host "[2] Checking log sources..." -ForegroundColor Cyan
    
    # Honeypot logs
    if (Test-Path "$ProjectRoot\Honeypot\honeypot.log") {
        Copy-Item "$ProjectRoot\Honeypot\honeypot.log" "$ScriptDir\logs\honeypot\" -Force
        Write-Host "    ✓ Honeypot logs configured" -ForegroundColor Green
    } else {
        Write-Host "    ⚠ Honeypot logs not found (start honeypot first)" -ForegroundColor Yellow
    }
    
    # Network Traffic Classifier
    if (Test-Path "$ProjectRoot\Network-Traffic-Classifier") {
        Get-ChildItem "$ProjectRoot\Network-Traffic-Classifier" -Filter "*.log" -o "*.csv" -Recurse | 
        Copy-Item -Destination "$ScriptDir\logs\network-traffic\" -Force
        Write-Host "    ✓ Network traffic logs configured" -ForegroundColor Green
    }
    
    # Web IDS
    if (Test-Path "$ProjectRoot\Web-Intrusion-Detection") {
        Get-ChildItem "$ProjectRoot\Web-Intrusion-Detection" -Filter "*.log" -o "*.csv" -Recurse |
        Copy-Item -Destination "$ScriptDir\logs\web-ids\" -Force
        Write-Host "    ✓ Web IDS logs configured" -ForegroundColor Green
    }
}

# Function to check Docker installation
function Check-Docker {
    Write-Host ""
    Write-Host "[3] Checking Docker installation..." -ForegroundColor Cyan
    
    try {
        $DockerVersion = docker --version
        Write-Host "    ✓ Docker found: $DockerVersion" -ForegroundColor Green
    } catch {
        Write-Host "    ✗ Docker not found. Please install Docker first." -ForegroundColor Red
        exit 1
    }
    
    try {
        $ComposeVersion = docker compose version
        Write-Host "    ✓ Docker Compose found" -ForegroundColor Green
    } catch {
        Write-Host "    ✗ Docker Compose not found." -ForegroundColor Red
        exit 1
    }
}

# Function to start ELK Stack
function Start-ELKStack {
    Write-Host ""
    Write-Host "[4] Starting ELK Stack..." -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    
    try {
        docker compose up -d
        Write-Host "    ✓ ELK Stack started" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "Waiting for services to initialize..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        docker compose ps
    } finally {
        Pop-Location
    }
}

# Function to stop ELK Stack
function Stop-ELKStack {
    Write-Host ""
    Write-Host "Stopping ELK Stack..." -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    
    try {
        docker compose down
        Write-Host "    ✓ ELK Stack stopped" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# Function to view logs
function View-Logs {
    param([string]$Service = "all")
    
    Push-Location $ScriptDir
    
    try {
        if ($Service -eq "all") {
            docker compose logs -f
        } else {
            docker compose logs -f $Service
        }
    } finally {
        Pop-Location
    }
}

# Function to check status
function Check-Status {
    Write-Host ""
    Write-Host "ELK Stack Status:" -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    
    try {
        docker compose ps
        
        Write-Host ""
        Write-Host "Service Information:" -ForegroundColor Yellow
        Write-Host "  Elasticsearch: http://localhost:9200"
        Write-Host "  Kibana:        http://localhost:5601"
        Write-Host "  Logstash:      http://localhost:5000 (TCP input)"
        
        # Check Elasticsearch health
        try {
            $Health = curl -s http://localhost:9200/_cluster/health | ConvertFrom-Json
            Write-Host ""
            Write-Host "Elasticsearch Health:" -ForegroundColor Green
            Write-Host "  Status: $($Health.status)"
            Write-Host "  Active Shards: $($Health.active_shards)"
        } catch {
            Write-Host "Elasticsearch not responding (starting up...)" -ForegroundColor Yellow
        }
    } finally {
        Pop-Location
    }
}

# Main execution
Write-Host ""

if ($Action -eq "setup") {
    Setup-Directories
    Setup-LogCollection
    Check-Docker
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "SETUP COMPLETE!" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Start the ELK Stack:"
    Write-Host "   .\setup.ps1 -Action start"
    Write-Host ""
    Write-Host "2. Check status:"
    Write-Host "   .\setup.ps1 -Action status"
    Write-Host ""
    Write-Host "3. View logs:"
    Write-Host "   .\setup.ps1 -Action logs"
    Write-Host ""
    Write-Host "4. Access Kibana:"
    Write-Host "   http://localhost:5601"
    Write-Host ""
    
} elseif ($Action -eq "start") {
    Check-Docker
    Start-ELKStack
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "ELK STACK STARTED!" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Kibana is available at: http://localhost:5601" -ForegroundColor Green
    Write-Host ""
    
} elseif ($Action -eq "stop") {
    Stop-ELKStack
    
} elseif ($Action -eq "status") {
    Check-Status
    
} elseif ($Action -eq "logs") {
    View-Logs
    
} elseif ($Action -eq "logs-elasticsearch") {
    View-Logs "elasticsearch"
    
} elseif ($Action -eq "logs-kibana") {
    View-Logs "kibana"
    
} elseif ($Action -eq "logs-logstash") {
    View-Logs "logstash"
    
} elseif ($Action -eq "logs-filebeat") {
    View-Logs "filebeat"
    
} else {
    Write-Host "Usage: .\setup.ps1 [-Action <action>]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Yellow
    Write-Host "  setup                  - Run initial setup (default)"
    Write-Host "  start                  - Start ELK Stack containers"
    Write-Host "  stop                   - Stop ELK Stack containers"
    Write-Host "  status                 - Check service status"
    Write-Host "  logs                   - View all logs (press Ctrl+C to exit)"
    Write-Host "  logs-elasticsearch     - View Elasticsearch logs"
    Write-Host "  logs-kibana            - View Kibana logs"
    Write-Host "  logs-logstash          - View Logstash logs"
    Write-Host "  logs-filebeat          - View Filebeat logs"
    Write-Host ""
}
