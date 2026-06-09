# Builds the sample plugin JARs from their (dependency-free) sources.
# Note: native tools (javac/jar) may print notes to stderr, so we check $LASTEXITCODE
# explicitly rather than running under 'Stop' mode (which treats native stderr as fatal).
$ErrorActionPreference = 'Continue'
$dir = $PSScriptRoot

# Resolve a JDK bin that actually contains jar.exe (the javac on PATH may be a shim without it).
$jdkBin = $null
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\jar.exe'))) {
    $jdkBin = Join-Path $env:JAVA_HOME 'bin'
}
if (-not $jdkBin) {
    $jarCmd = Get-Command jar.exe -ErrorAction SilentlyContinue
    if ($jarCmd) { $jdkBin = Split-Path $jarCmd.Source }
}
if (-not $jdkBin) {
    # cmd handles the 2>&1 so PowerShell does not wrap the stderr output as errors.
    $homeLine = (cmd /c 'java -XshowSettings:properties -version 2>&1') | Select-String 'java.home'
    if ($homeLine) {
        $jh = $homeLine.ToString().Split('=')[1].Trim()
        if (Test-Path (Join-Path $jh 'bin\jar.exe')) { $jdkBin = Join-Path $jh 'bin' }
    }
}
if (-not $jdkBin) { throw 'Could not locate a JDK with jar.exe. Set JAVA_HOME to a full JDK.' }
$javac = Join-Path $jdkBin 'javac.exe'
$jar = Join-Path $jdkBin 'jar.exe'

function Build-One($name, $out) {
    $src = Join-Path $dir $name
    $work = Join-Path $env:TEMP ("pg_" + [guid]::NewGuid())
    $classes = Join-Path $work 'classes'
    New-Item -ItemType Directory -Force -Path $classes | Out-Null
    $sources = Get-ChildItem -Recurse -Path (Join-Path $src 'src') -Filter *.java | ForEach-Object { $_.FullName }
    & $javac -d $classes $sources
    if ($LASTEXITCODE -ne 0) { throw "javac failed for $name" }
    Copy-Item (Join-Path $src 'plugin.yml') (Join-Path $classes 'plugin.yml')
    & $jar --create --file (Join-Path $dir $out) -C $classes .
    if ($LASTEXITCODE -ne 0) { throw "jar failed for $name" }
    Remove-Item -Recurse -Force $work
    Write-Host "built $out"
}

Build-One 'benign-plugin' 'BenignChat-1.2.0.jar'
Build-One 'malicious-plugin' 'FreeRanks-2.3.jar'
