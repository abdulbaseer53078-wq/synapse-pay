# One-click dev server for Synapse Pay (Windows / PowerShell 7+)
# Usage: .\run_dev.ps1
# Requires: Docker Desktop, Python 3.11+

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BACKEND = Join-Path $PSScriptRoot "backend"
$DB_NAME = "synapse_dev"
$DB_URL  = "postgresql://postgres:postgres@localhost:5432/$DB_NAME"

# ── 1. Generate dev keys if missing ──────────────────────────────────────────
if (-not (Test-Path "$BACKEND\dev_ca.crt")) {
    Write-Host "`n[1/4] Generating dev keys …" -ForegroundColor Cyan
    & python "$BACKEND\scripts\generate_dev_keys.py"
    if ($LASTEXITCODE -ne 0) { Write-Error "Key generation failed."; exit 1 }
} else {
    Write-Host "[1/4] Dev keys already exist — skipping generation." -ForegroundColor Green
}

# ── 2. Start Postgres ─────────────────────────────────────────────────────────
Write-Host "`n[2/4] Starting Postgres …" -ForegroundColor Cyan
docker compose up -d db
if ($LASTEXITCODE -ne 0) { Write-Error "docker compose failed. Is Docker Desktop running?"; exit 1 }

# Wait until Postgres accepts connections inside the container (up to 30 s)
$DB_CONTAINER = "synapse-pay-db-1"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    docker exec $DB_CONTAINER psql -U postgres -c "SELECT 1" -q 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { Write-Error "Postgres did not become ready in 30 s."; exit 1 }
Write-Host "  Postgres is up." -ForegroundColor Green

# ── 3. Create DB and apply migrations ────────────────────────────────────────
Write-Host "`n[3/4] Applying migrations …" -ForegroundColor Cyan
# ignore "already exists" error
docker exec $DB_CONTAINER psql -U postgres -c "CREATE DATABASE $DB_NAME;" 2>$null
Get-ChildItem "$PSScriptRoot\db\migrations\*.sql" | Sort-Object Name | ForEach-Object {
    Write-Host "  applying $($_.Name) …"
    Get-Content $_.FullName | docker exec -i $DB_CONTAINER psql -U postgres -d $DB_NAME -q
    if ($LASTEXITCODE -ne 0) { Write-Error "Migration $($_.Name) failed."; exit 1 }
}
Write-Host "  Migrations applied." -ForegroundColor Green

# ── 4. Start the backend ──────────────────────────────────────────────────────
Write-Host "`n[4/4] Starting Synapse backend on http://localhost:8000 …`n" -ForegroundColor Cyan

$env:DATABASE_URL            = $DB_URL
$env:CA_CERT_PATH            = "$BACKEND\dev_ca.crt"
$env:CA_KEY_PATH             = "$BACKEND\dev_ca.key"
$env:CA_CRL_PATH             = "$BACKEND\dev_ca.crl"
$env:JWT_PUBLIC_KEY_PATH     = "$BACKEND\dev_jwt_pub.pem"
$env:CHECKOUT_BASE_URL       = "http://localhost:8000/api"
$env:ALLOW_INSECURE_WEBHOOKS = "1"

Set-Location $BACKEND
& .\.venv\Scripts\uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --reload
