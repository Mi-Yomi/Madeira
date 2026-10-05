param(
    [string]$SourcePath = (Join-Path $PSScriptRoot 'source/custom.c'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'out'),
    [string]$IntegratedSourcePath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Runtime fixture requires Windows; cross-compilation is not a runtime test' }
$request = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'reference-request.json') -Raw | ConvertFrom-Json
if ($request.schema_version -ne 1 -or $request.maximum_job_minutes -ne 10 -or
    $request.expected_cases -ne 8 -or $request.architecture -ne 'x64' -or
    $request.sdk_download -ne $false -or $request.third_party_execution -ne $false -or
    $request.installations -ne $false -or $request.artifact_upload -ne $false -or
    $request.cache -ne $false -or $request.signing_or_ipa -ne $false -or
    $request.production_timeout_added -ne $false) { throw 'Reviewed request scope is invalid' }
$requestedFiles = @('fixture.c', 'own_child.c', 'fixture_common.h', 'extract-helpers.ps1', 'run.ps1', 'source/custom.c')
if (@($request.files_sha256.PSObject.Properties).Count -ne $requestedFiles.Count) {
    throw 'Request must identify exactly the six source/build inputs'
}
foreach ($file in $requestedFiles) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $file) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($request.files_sha256.$file -ne $actual) { throw "Reviewed request hash mismatch: $file" }
}
Write-Host "Verified bounded source-owned request $($request.request)"
$source = (Resolve-Path -LiteralPath $SourcePath).Path
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
if (@(Get-ChildItem -LiteralPath $output -Force).Count -ne 0) {
    throw 'Use an empty output directory, so old results cannot masquerade as this run'
}
& (Join-Path $PSScriptRoot 'extract-helpers.ps1') -SourcePath $source -OutputDirectory $output
$integratedHash = $null
if ($IntegratedSourcePath) {
    $IntegratedSourcePath = (Resolve-Path -LiteralPath $IntegratedSourcePath).Path
    $integratedHash = (Get-FileHash -LiteralPath $IntegratedSourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($integratedHash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Integrated custom.c does not match the frozen reviewed source'
    }
    Write-Host "Integrated source also matches: $integratedHash"
}

# The standard runner has MSVC and the Windows SDK. Do not install or download anything.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Preinstalled Visual Studio discovery tool was not found' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installation)) { throw 'Preinstalled MSVC C/C++ tools were not found' }
$vsdev = Join-Path $installation 'Common7/Tools/VsDevCmd.bat'
$environment = & $env:ComSpec /d /s /c "call `"$vsdev`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'MSVC environment initialization failed' }
foreach ($line in $environment) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }
}
$cl = (Get-Command cl.exe -ErrorAction Stop).Source
Push-Location $output
try {
    $common = @('/nologo', '/std:c11', '/W4', '/WX', '/O2', '/DUNICODE', '/D_UNICODE', "/I$output")
    & $cl @common "/Fe:$output/own_child.exe" "/Fo:$output/own_child.obj" (Join-Path $PSScriptRoot 'own_child.c') /link /DYNAMICBASE /NXCOMPAT
    if ($LASTEXITCODE -ne 0) { throw 'Own child compilation failed' }
    & $cl @common "/Fe:$output/fixture.exe" "/Fo:$output/fixture.obj" (Join-Path $PSScriptRoot 'fixture.c') /link /DYNAMICBASE /NXCOMPAT
    if ($LASTEXITCODE -ne 0) { throw 'Reference fixture compilation failed' }
    $build = [ordered]@{
        architecture = 'x64'
        request = $request.request
        compiler = $cl
        compiler_version = (Get-Item -LiteralPath $cl).VersionInfo.FileVersion
        flags = $common
        fixture_sha256 = (Get-FileHash -LiteralPath './fixture.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
        own_child_sha256 = (Get-FileHash -LiteralPath './own_child.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        integrated_source_path = $IntegratedSourcePath
        integrated_source_sha256 = $integratedHash
    }
    $build | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath 'build-identity.json' -Encoding utf8
    Write-Host ("BUILD_IDENTITY " + ($build | ConvertTo-Json -Depth 5 -Compress))
    & './fixture.exe'
    $fixtureExit = $LASTEXITCODE
    foreach ($log in Get-ChildItem -Filter 'case-*.log' | Sort-Object Name) {
        Write-Host "--- $($log.Name) ---"
        Get-Content -LiteralPath $log.FullName | Write-Host
    }
    if (-not (Test-Path -LiteralPath 'windows-results.json')) { throw "Fixture did not write a results report (exit $fixtureExit)" }
    Get-Content -LiteralPath 'windows-results.json' | Write-Host
    $report = Get-Content -LiteralPath 'windows-results.json' -Raw | ConvertFrom-Json
    if ($env:GITHUB_STEP_SUMMARY) {
        @(
            '### Source-owned Windows API reference fixture',
            "Production source SHA-256: $((Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant())",
            "Ran $($report.ran) / $($report.planned) cases; passed $($report.passed)",
            'This is x64 Windows API compatibility evidence only. It is not Wine, Madeira, iOS, or 1C acceptance.',
            '',
            '| Case | Actually ran | Result | Watchdog |',
            '|---|---|---|---|'
        ) | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
        foreach ($case in $report.cases) {
            "| $($case.name) | $($case.ran) | $($case.status) | $($case.watchdog_fired) |" |
                Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
        }
    }
    if ((Get-FileHash -LiteralPath './fixture.exe' -Algorithm SHA256).Hash.ToLowerInvariant() -ne $build.fixture_sha256 -or
        (Get-FileHash -LiteralPath './own_child.exe' -Algorithm SHA256).Hash.ToLowerInvariant() -ne $build.own_child_sha256) {
        throw 'Compiled fixture executables changed during execution'
    }
    Write-Host 'BUILD_OUTPUTS_UNCHANGED true'
    if ($fixtureExit -ne 0 -or $report.ran -ne 8 -or $report.passed -ne 8 -or
        @($report.cases | Where-Object { $_.status -ne 'passed' -or -not $_.ran -or $_.watchdog_fired }).Count) {
        throw "Windows reference fixture failed or was incomplete (exit $fixtureExit)"
    }
}
finally { Pop-Location }
