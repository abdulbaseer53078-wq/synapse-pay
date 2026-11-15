#Requires -Version 7.0
<#
.SYNOPSIS
    One-click dev environment for Synapse Pay on Windows.
.DESCRIPTION
    Runs all 7 steps: generate dev keys, start Postgres, apply migrations,
    start the mock ISO 8583 host, build and start the Rust card-service,
    start the FastAPI backend, and serve the frontend.

    Run from the repo root or any directory (paths are resolved from $PSScriptRoot).
    Press Ctrl+C to stop all spawned processes cleanly.

    Prerequisites: Docker Desktop, Python 3.12+, Rust/cargo
#>

$ErrorActionPreference = "Stop"

$Root    = $PSScriptRoot
$Sandbox = "$Root\.sandbox"
$Dialect = "$Root\iso8583\dialects\synthetic-host.json"

Write-Host ""
Write-Host "==> Synapse Pay dev environment" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Generate dev keys
# ---------------------------------------------------------------------------
Write-Host "[1/7] Generating dev keys..." -ForegroundColor Cyan
python "$Root\backend\scripts\generate_dev_keys.py"

# ---------------------------------------------------------------------------
# 2. Start Postgres
# ---------------------------------------------------------------------------
Write-Host "[2/7] Starting Postgres..." -ForegroundColor Cyan
docker compose -f "$Root\docker-compose.yml" up -d db

# ---------------------------------------------------------------------------
# 3. Apply migrations via Docker (not the host psql)
# ---------------------------------------------------------------------------
Write-Host "[3/7] Applying database migrations..." -ForegroundColor Cyan

# Wait up to 30 s for Postgres to accept connections
$ready = $false
for ($i = 0; $i -lt 30 -and -not $ready; $i++) {
    docker exec synapse-pay-db-1 psql -U postgres -c "SELECT 1" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $ready = $true } else { Start-Sleep -Seconds 1 }
}
if (-not $ready) { throw "Postgres did not become ready within 30 s" }

# Create the database (idempotent — ignore the error if it already exists)
docker exec synapse-pay-db-1 psql -U postgres `
    -c "SELECT 1 FROM pg_database WHERE datname = 'synapse_dev'" | Select-String "1 row" | Out-Null
if ($LASTEXITCODE -ne 0 -or $null -eq (
    docker exec synapse-pay-db-1 psql -U postgres -tAq -c "SELECT 1 FROM pg_database WHERE datname='synapse_dev'")) {
    docker exec synapse-pay-db-1 psql -U postgres -c "CREATE DATABASE synapse_dev" 2>$null
}

# Apply each migration in sorted order
Get-ChildItem "$Root\db\migrations\*.sql" | Sort-Object Name | ForEach-Object {
    Write-Host "    $($_.Name)"
    Get-Content -Raw $_.FullName |
        docker exec -i synapse-pay-db-1 psql -U postgres -d synapse_dev | Out-Null
}

# ---------------------------------------------------------------------------
# 4. Start mock ISO 8583 host (port 9090)
# ---------------------------------------------------------------------------
Write-Host "[4/7] Starting mock ISO 8583 host on :9090..." -ForegroundColor Cyan
$MockHostProc = Start-Process python `
    -ArgumentList @(
        "$Root\host-connector\mock_host\mock_host.py",
        "--dialect",   $Dialect,
        "--cert",      "$Sandbox\host.pem",
        "--key",       "$Sandbox\host-key.pem",
        "--client-ca", "$Sandbox\ca.pem",
        "--port",      "9090"
    ) `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2  # let the socket open before card-service tries to connect

# ---------------------------------------------------------------------------
# 5. Start card-service (cargo run builds on first run)
# ---------------------------------------------------------------------------
Write-Host "[5/7] Starting card-service (first build takes a few minutes)..." -ForegroundColor Cyan
$env:SIM_HSM_BDK_HEX     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
$env:SIM_HSM_CHECKOUT_KEY = "$Sandbox\checkout-key.pem"
$env:HOST_ADDR            = "127.0.0.1:9090"
$env:HOST_SERVER_NAME     = "localhost"
$env:HOST_CA              = "$Sandbox\ca.pem"
$env:HOST_CLIENT_CERT     = "$Sandbox\client.pem"
$env:HOST_CLIENT_KEY      = "$Sandbox\client-key.pem"
$env:HOST_DIALECT         = $Dialect
$env:AUDIT_LOG_PATH       = "$Sandbox\iso-audit.jsonl"
$env:CARD_SERVICE_ADDR    = "127.0.0.1:7070"
$env:CARD_DATA_STORAGE    = "sandbox"
$CardProc = Start-Process cargo `
    -ArgumentList "run" `
    -WorkingDirectory "$Root\card-service" `
    -PassThru -WindowStyle Hidden

# ---------------------------------------------------------------------------
# 6. Start FastAPI backend
# ---------------------------------------------------------------------------
Write-Host "[6/7] Starting FastAPI backend on :8000..." -ForegroundColor Cyan
$env:DATABASE_URL           = "postgresql://postgres:postgres@localhost:5432/synapse_dev"
$env:CHECKOUT_BASE_URL      = "http://localhost:8000"
$env:CA_CERT_PATH           = "$Sandbox\platform-ca.pem"
$env:CA_KEY_PATH            = "$Sandbox\platform-ca-key.pem"
$env:CA_CRL_PATH            = "$Sandbox\platform-crl.pem"
$env:JWT_PUBLIC_KEY_PATH    = "$Sandbox\jwt-public.pem"
$env:CARD_SERVICE_URL       = "http://127.0.0.1:7070"
$env:ALLOW_INSECURE_WEBHOOKS = "1"
$BackendProc = Start-Process python `
    -ArgumentList @("-m", "uvicorn", "app.main:app",
                    "--host", "127.0.0.1", "--port", "8000", "--reload") `
    -WorkingDirectory "$Root\backend" `
    -PassThru -WindowStyle Hidden

# ---------------------------------------------------------------------------
# 7. Start frontend
# ---------------------------------------------------------------------------
Write-Host "[7/7] Starting frontend on :3000..." -ForegroundColor Cyan
$FrontendProc = Start-Process python `
    -ArgumentList @("-m", "http.server", "3000", "--directory", "frontend") `
    -WorkingDirectory $Root `
    -PassThru -WindowStyle Hidden

# ---------------------------------------------------------------------------
# Ready
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "All services started:" -ForegroundColor Green
Write-Host "  API       http://localhost:8000"
Write-Host "  API docs  http://localhost:8000/docs"
Write-Host "  Frontend  http://localhost:3000"
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor Yellow
Write-Host ""

try {
    while ($true) { Start-Sleep -Seconds 60 }
} finally {
    Write-Host "Stopping services..." -ForegroundColor Yellow
    @($BackendProc, $FrontendProc, $CardProc, $MockHostProc) |
        Where-Object { $_ -ne $null -and -not $_.HasExited } |
        ForEach-Object { $_.Kill() }
    docker compose -f "$Root\docker-compose.yml" stop db
    Write-Host "Done." -ForegroundColor Green
}
