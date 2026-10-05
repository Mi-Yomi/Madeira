param(
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$expectedSource = '0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f'
$expectedSpan = '4eab607ab3dd71f8df9e03b46b7f5cd7757f889c38f9f93a26072a002e1d0f7b'
$source = (Resolve-Path -LiteralPath $SourcePath).Path
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSource) {
    throw 'Final production custom.c identity does not match the reviewed source'
}
$bytes = [System.IO.File]::ReadAllBytes($source)
$encoding = [System.Text.UTF8Encoding]::new($false, $true)
$text = $encoding.GetString($bytes)
$begin = '/* Finish server-pipe operations before releasing their caller-owned storage. */'
$end = 'static DWORD custom_start_server('
$start = $text.IndexOf($begin, [StringComparison]::Ordinal)
$stop = $text.IndexOf($end, [StringComparison]::Ordinal)
if ($start -lt 0 -or $stop -le $start -or
    $text.IndexOf($begin, $start + 1, [StringComparison]::Ordinal) -ge 0 -or
    $text.IndexOf($end, $stop + 1, [StringComparison]::Ordinal) -ge 0) {
    throw 'Production helper boundary markers are missing, repeated, or out of order'
}
$span = $text.Substring($start, $stop - $start)
foreach ($declaration in @(
    'static BOOL custom_pipe_result( HANDLE pipe, OVERLAPPED *overlapped, DWORD *size )',
    'static DWORD custom_connect_server( HANDLE pipe, HANDLE process )',
    'static BOOL custom_pipe_io( HANDLE pipe, void *buffer, DWORD count, DWORD *size, BOOL write )'
)) {
    if ([regex]::Matches($span, [regex]::Escape($declaration)).Count -ne 1) {
        throw "Expected exact unique function declaration: $declaration"
    }
}
if (-not $span.EndsWith("}`n`n", [StringComparison]::Ordinal) -or
    [regex]::Matches($span, '(?m)^static (BOOL|DWORD) ').Count -ne 3) {
    throw 'Helper extraction did not end at the exact three-function boundary'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$output = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path 'production_helpers.inc'
[System.IO.File]::WriteAllBytes($output, $encoding.GetBytes($span))
if ((Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSpan) {
    throw 'Extracted helper byte identity does not match the reviewed production span'
}
$identity = [ordered]@{
    source_sha256 = $expectedSource
    helper_span_sha256 = $expectedSpan
    helper_bytes = (Get-Item -LiteralPath $output).Length
    functions = @('custom_pipe_result', 'custom_connect_server', 'custom_pipe_io')
    source_path = $source
    generated_include_path = $output
}
$identity | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'source-identity.json') -Encoding utf8
Write-Host "Verified exact production source $expectedSource and extracted all three helpers ($expectedSpan)"
