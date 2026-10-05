# Builds splitwire.exe (command line) and splitwire-tray.exe (notification area app).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
go build -o splitwire.exe .
if ($LASTEXITCODE) { exit $LASTEXITCODE }
go build -ldflags '-H=windowsgui' -o splitwire-tray.exe ./cmd/splitwire-tray
if ($LASTEXITCODE) { exit $LASTEXITCODE }
