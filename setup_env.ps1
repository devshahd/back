$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path -LiteralPath $envFile)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $key = [Convert]::ToBase64String($bytes).Replace("+", "-").Replace("/", "_").TrimEnd("=")
    $passwordBytes = New-Object byte[] 18
    $passwordRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $passwordRng.GetBytes($passwordBytes) } finally { $passwordRng.Dispose() }
    $bootstrapPassword = [Convert]::ToBase64String($passwordBytes).Replace("+", "A").Replace("/", "B").TrimEnd("=")
    $lines = @(
        "NODE_ENV=production",
        "DATABASE_URL=sqlite:///../pharmacy.db",
        "SECRET_KEY=$key",
        "BOOTSTRAP_PASSWORD=$bootstrapPassword",
        "ACCESS_TOKEN_MINUTES=15",
        "REFRESH_TOKEN_DAYS=30",
        "LOGIN_MAX_ATTEMPTS=5",
        "LOGIN_LOCKOUT_MINUTES=10",
        "CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:5501,http://localhost:5501"
    )
    Set-Content -LiteralPath $envFile -Encoding UTF8 -Value $lines
    Write-Host "[SETUP] Created backend .env (production-safe defaults)"
    Write-Host "[SETUP] Initial admin username: admin@pharmasys.local"
    Write-Host "[SETUP] Initial admin password (save it now): $bootstrapPassword"
}
