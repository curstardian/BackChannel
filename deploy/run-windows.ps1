# Backchannel — run on Windows behind nginx.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File deploy\run-windows.ps1

$env:PORT = "8787"
$env:BACKCHANNEL_HOST = "127.0.0.1"      # loopback only; nginx faces the network
$env:BACKCHANNEL_TRUST_PROXY = "1"       # trust X-Forwarded-For from nginx

# optional tuning:
# $env:BACKCHANNEL_GLOBAL_RPS = "120"
# $env:BACKCHANNEL_WRITE_PER_MIN = "60"

Set-Location -Path (Split-Path -Parent $PSScriptRoot)
node server.js
