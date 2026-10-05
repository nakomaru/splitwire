# Builds splitwire.exe: the notification area app when double-clicked, the
# command line from a shell. `go generate` rebuilds the icon and manifest
# resources (rsrc_windows_*.syso) after changes in winres.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
go build -o splitwire.exe .
if ($LASTEXITCODE) { exit $LASTEXITCODE }
