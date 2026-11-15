# One-click dev server for Synapse Pay (Windows / PowerShell 7+)
# Usage: .\run_dev.ps1
# Requires: Docker Desktop, Python 3.11+, Rust/cargo (https://rustup.rs)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ROOT    = $PSScriptRoot
$BACKEND = Join-Path $ROOT "backend"
$DB_NAME = "synapse_dev"
$DB_URL  = "postgresql://postgres:postgres@localhost:5432/$DB_NAME"
$DB_CONTAINER = "synapse-pay-db-1"

# ── 1. Generate dev keys if missing ──────────────────────────────────────────
if (-not (Test-Path "$BACKEND\dev_ca.crt")) {
    Write-Host "`n[1/7] Generating dev keys …" -ForegroundColor Cyan
    & python "$BACKEND\scripts\generate_dev_keys.py"
    if ($LASTEXITCODE -ne 0) { Write-Error "Key generation failed."; exit 1 }
} else {
    Write-Host "[1/7] Dev keys already exist — skipping generation." -ForegroundColor Green
}

# ── 2. Start Postgres ─────────────────────────────────────────────────────────
Write-Host "`n[2/7] Starting Postgres …" -ForegroundColor Cyan
docker compose up -d db
if ($LASTEXITCODE -ne 0) { Write-Error "docker compose failed. Is Docker Desktop running?"; exit 1 }

$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    docker exec $DB_CONTAINER psql -U postgres -c "SELECT 1" -q 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Error "Postgres did not become ready in 30 s."; exit 1 }
Write-Host "  Postgres is up." -ForegroundColor Green

# ── 3. Create DB and apply migrations ────────────────────────────────────────
Write-Host "`n[3/7] Applying migrations …" -ForegroundColor Cyan
docker exec $DB_CONTAINER psql -U postgres -c "CREATE DATABASE $DB_NAME;" 2>$null
Get-ChildItem "$ROOT\db\migrations\*.sql" | Sort-Object Name | ForEach-Object {
    Write-Host "  applying $($_.Name) …"
    Get-Content $_.FullName | docker exec -i $DB_CONTAINER psql -U postgres -d $DB_NAME -q
    if ($LASTEXITCODE -ne 0) { Write-Error "Migration $($_.Name) failed."; exit 1 }
}
Write-Host "  Migrations applied." -ForegroundColor Green

# ── 4. Start mock ISO 8583 acquirer host ──────────────────────────────────────
Write-Host "`n[4/7] Starting mock acquirer host on port 9090 …" -ForegroundColor Cyan
$mockHostArgs = @(
    "$ROOT\host-connector\mock_host\mock_host.py",
    "--cert",       "$BACKEND\dev_card_host.crt",
    "--key",        "$BACKEND\dev_card_host.key",
    "--client-ca",  "$BACKEND\dev_ca.crt",
    "--dialect",    "$ROOT\iso8583\dialects\synthetic-host.json",
    "--port",       "9090"
)
Start-Process python -ArgumentList $mockHostArgs -NoNewWindow
Start-Sleep -Seconds 2  # let it bind before card-service connects
Write-Host "  Mock host up at 127.0.0.1:9090." -ForegroundColor Green

# ── 5. Start card-service ─────────────────────────────────────────────────────
Write-Host "`n[5/7] Starting card-service (builds if needed — first run takes a few minutes) …" -ForegroundColor Cyan

$env:CARD_DATA_STORAGE  = "sandbox"
$env:SIM_HSM_BDK_HEX    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
$env:AUDIT_LOG_PATH      = "$BACKEND\card-service-audit.jsonl"
$env:HOST_ADDR           = "127.0.0.1:9090"
$env:HOST_SERVER_NAME    = "card-host-dev"
$env:HOST_CA             = "$BACKEND\dev_ca.crt"
$env:HOST_CLIENT_CERT    = "$BACKEND\dev_card_client.crt"
$env:HOST_CLIENT_KEY     = "$BACKEND\dev_card_client.key"
$env:HOST_DIALECT        = "$ROOT\iso8583\dialects\synthetic-host.json"

# cargo run builds if the binary is stale, otherwise just runs it
Start-Process cargo -ArgumentList @("run", "--manifest-path", "$ROOT\card-service\Cargo.toml") -NoNewWindow
Start-Sleep -Seconds 5  # wait for first connect to acquirer
Write-Host "  card-service starting at http://127.0.0.1:7070 …" -ForegroundColor Green

# ── 6. Start the FastAPI backend ──────────────────────────────────────────────
Write-Host "`n[6/7] Starting Synapse backend on http://localhost:8000 …" -ForegroundColor Cyan

$env:DATABASE_URL            = $DB_URL
$env:CA_CERT_PATH            = "$BACKEND\dev_ca.crt"
$env:CA_KEY_PATH             = "$BACKEND\dev_ca.key"
$env:CA_CRL_PATH             = "$BACKEND\dev_ca.crl"
$env:JWT_PUBLIC_KEY_PATH     = "$BACKEND\dev_jwt_pub.pem"
$env:CHECKOUT_BASE_URL       = "http://localhost:8000/api"
$env:ALLOW_INSECURE_WEBHOOKS = "1"

Start-Process python -ArgumentList @(
    "-m", "uvicorn", "app.main:create_app",
    "--factory", "--host", "0.0.0.0", "--port", "8000", "--reload"
) -WorkingDirectory $BACKEND -NoNewWindow
Start-Sleep -Seconds 3  # let uvicorn finish startup before printing the final message

# ── 7. Start frontend static server ──────────────────────────────────────────
Write-Host "`n[7/7] Starting frontend server on http://localhost:3000 …" -ForegroundColor Cyan
Start-Process python -ArgumentList @("-m", "http.server", "3000", "--directory", "$ROOT\frontend") -NoNewWindow

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  All services started. Open the demo page:" -ForegroundColor Green
Write-Host "  http://localhost:3000/demo.html" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Backend API:    http://localhost:8000/docs"
Write-Host "  Card service:   http://localhost:7070  (internal)"
Write-Host "  Mock host:      127.0.0.1:9090         (internal)"
Write-Host ""
Write-Host "Press Ctrl+C to stop this shell. Background services keep running."
Write-Host "To stop all: docker compose down && Get-Process python,cargo | Stop-Process -Force"
