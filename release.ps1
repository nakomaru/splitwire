# Builds a release into dist: splitwire-amd64.exe, splitwire-arm64.exe and
# manifest.json, signed with keys\release.key into manifest.json.sig.
# -Publish then creates the GitHub release v<version> at the pushed HEAD
# with those files, which installed copies pick up as their next update.
# The version is main.go's, which winres\winres.json must match.
param([switch]$Publish)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$version = (Select-String -Path main.go -Pattern '^const version = "(.+)"$').Matches[0].Groups[1].Value
$res = (Get-Content winres\winres.json -Raw | ConvertFrom-Json).RT_VERSION.'#1'.'0000'.info.'0409'.ProductVersion
if ($res -ne $version) {
    throw "winres\winres.json has version $res and main.go $version; match them and run go generate"
}

Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory dist | Out-Null
try {
    foreach ($arch in 'amd64', 'arm64') {
        $env:GOARCH = $arch
        go build -trimpath -o dist\splitwire-$arch.exe .
        if ($LASTEXITCODE) { exit $LASTEXITCODE }
    }
} finally {
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
}
go run ./tools/sign manifest $version dist
if ($LASTEXITCODE) { exit $LASTEXITCODE }

if ($Publish) {
    $head = git rev-parse HEAD
    git merge-base --is-ancestor $head origin/master
    if ($LASTEXITCODE) { throw "HEAD $head is not pushed to origin/master" }
    if (git status --porcelain) { throw "the working tree has changes that the release would not include" }
    gh release create "v$version" (Get-ChildItem dist).FullName --target $head --title "SplitWire $version" --generate-notes
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
