# Install Checkstead under $env:USERPROFILE\checkstead.
# A second run leaves Python, java, the pinned engine, and the package in place.
# This script does not call the NVD and does not publish a database.
# No administrator rights. macOS and Linux use scripts/setup.sh.
$ErrorActionPreference = "Stop"

$Root = Join-Path $env:USERPROFILE "checkstead"
# CHECKSTEAD_REF installs a release tag instead of the main branch, for example v0.1.1.
$Ref = if ($env:CHECKSTEAD_REF) { $env:CHECKSTEAD_REF } else { "main" }
if ($Ref -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$' -or $Ref.Contains("..")) {
    throw "CHECKSTEAD_REF is not a branch or tag name: $Ref"
}
$RefKind = if ($Ref -match '^v[0-9]') { "tags" } else { "heads" }
$PackageUrl = "https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/$RefKind/$Ref.tar.gz"
$RawBase = "https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/$Ref"
$PinUrl = "$RawBase/engine.version"
$PythonRelease = "https://github.com/astral-sh/python-build-standalone/releases/download/20261013"
# SHA-256 of each pinned download, read from the upstream release and checked
# against GitHub's asset digest. A download that does not match is refused.
$PythonSha256 = @{
    "x86_64-pc-windows-msvc" = "bbc902d4d187ac4914915bf538196a064b49109a33a104965b5164ced5b80a1e"
    "aarch64-pc-windows-msvc" = "5a2aa29c73e72b512279bfc3f795b51dc6ae09b8fb7cea801459f49896d3bac6"
}
$JdkRelease = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1"
$JdkAssets = @{
    "x64" = @("OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip", "f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e")
    "aarch64" = @("OpenJDK21U-jdk_aarch64_windows_hotspot_21.0.12.1_1.zip", "ccf2e51f527d542a70ba5794a600d3aac04b4e967950e227834c7566cb1bec7b")
}

function Save-Download {
    param([string]$Uri, [string]$OutFile)
    if (-not $Uri.StartsWith("https://")) { throw "Refusing a download that is not https: $Uri" }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 1200
            return
        } catch {
            if ($attempt -ge 5) { throw }
            Start-Sleep -Seconds (3 * $attempt)
        }
    }
}

function Assert-Sha256 {
    param([string]$Path, [string]$Expected, [string]$What)
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        Remove-Item -Force -LiteralPath $Path
        throw "Refusing $What. Expected SHA-256 $Expected but downloaded $actual."
    }
}

function Test-Python311 {
    param([string]$Bin)
    if (-not (Test-Path -LiteralPath $Bin)) { return $false }
    & $Bin -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    return $LASTEXITCODE -eq 0
}

function Select-Python {
    $bundled = Join-Path $Root "python\python.exe"
    if (Test-Python311 $bundled) { return $bundled }
    foreach ($name in @("python", "python3", "py")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { continue }
        if ($name -eq "py") {
            & py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
            if ($LASTEXITCODE -eq 0) { return "py -3" }
            continue
        }
        if (Test-Python311 $cmd.Source) { return $cmd.Source }
    }
    return $null
}

function Test-JavaRuns {
    $java = Get-Command java -ErrorAction SilentlyContinue
    if ($null -eq $java) { return $false }
    & java -version 2>$null
    return $LASTEXITCODE -eq 0
}

function Get-MachineArch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    switch ($arch) {
        "X64" { return "x64" }
        "Arm64" { return "arm64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Install-Python {
    $arch = Get-MachineArch
    $triple = if ($arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    $url = "$PythonRelease/cpython-3.12.15+20261013-$triple-install_only.tar.gz"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("checkstead-python-" + [guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $archive = Join-Path $tmp "python.tar.gz"
    Save-Download -Uri $url -OutFile $archive
    Assert-Sha256 -Path $archive -Expected $PythonSha256[$triple] -What "the Python download"
    # Windows' own bsdtar. GNU tar from Git's usr\bin, when it is earlier on
    # PATH, reads "C:\..." as a remote host and fails.
    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    if (-not (Test-Path -LiteralPath $tar)) { $tar = "tar" }
    & $tar -xzf $archive -C $tmp
    if ($LASTEXITCODE -ne 0) { throw "Could not extract the Python archive." }
    $extracted = Join-Path $tmp "python"
    if (Test-Path (Join-Path $Root "python")) { Remove-Item -Recurse -Force (Join-Path $Root "python") }
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    Move-Item $extracted (Join-Path $Root "python")
    Remove-Item -Recurse -Force $tmp
    Write-Output "Installed Python under $Root\python"
}

function Install-Jdk {
    $arch = Get-MachineArch
    $jdkArch = if ($arch -eq "arm64") { "aarch64" } else { "x64" }
    $asset = $JdkAssets[$jdkArch]
    $url = "$JdkRelease/$($asset[0])"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("checkstead-jdk-" + [guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $archive = Join-Path $tmp "jdk.zip"
    Save-Download -Uri $url -OutFile $archive
    Assert-Sha256 -Path $archive -Expected $asset[1] -What "the JDK download"
    Expand-Archive -Path $archive -DestinationPath (Join-Path $tmp "unpacked") -Force
    $java = Get-ChildItem -Path (Join-Path $tmp "unpacked") -Filter java.exe -Recurse | Select-Object -First 1
    if ($null -eq $java) { throw "The JDK archive did not contain bin\java.exe." }
    # Not $home: that is PowerShell's read-only $HOME, and assigning it throws.
    $jdkHome = $java.Directory.Parent.FullName
    if (Test-Path (Join-Path $Root "jdk")) { Remove-Item -Recurse -Force (Join-Path $Root "jdk") }
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    Move-Item $jdkHome (Join-Path $Root "jdk")
    Remove-Item -Recurse -Force $tmp
    Write-Output "Installed a JDK under $Root\jdk"
}

function Read-Pin {
    $checkstead = Join-Path $Root "venv\Scripts\checkstead.exe"
    if (Test-Path $checkstead) {
        $reported = (& $checkstead version 2>$null | Out-String).Trim()
        if ($reported -match '^[0-9]+\.[0-9]+\.[0-9]+$') { return $reported }
    }
    $here = Split-Path -Parent $PSCommandPath
    $versionFile = Join-Path $here "..\engine.version"
    if (Test-Path $versionFile) { return (Get-Content -Raw $versionFile).Trim() }
    return (Invoke-WebRequest -Uri $PinUrl -UseBasicParsing).Content.Trim()
}

function Test-EnginePin {
    param([string]$Bin, [string]$Pin)
    if (-not (Test-Path -LiteralPath $Bin)) { return $false }
    $reported = & $Bin --version 2>&1 | Out-String
    return $reported -match "(^|\s)$([regex]::Escape($Pin))($|\s)"
}

function Find-PinnedEngine {
    param([string]$Pin)
    $candidates = @(
        (Join-Path $Root "dependency-check\bin\dependency-check.bat"),
        (Get-Command dependency-check.bat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    )
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-EnginePin $candidate $Pin) { return $candidate }
    }
    return $null
}

# Replace the vulnerable library jars the pinned engine bundles. Each one is
# pinned by SHA-256 in scripts/engine-overrides.txt, as in the container image.
function Install-EngineOverrides {
    param([string]$Src, [string]$Tmp, [string]$Pin)
    $list = $null
    if (Test-Path Env:ENGINE_OVERRIDES) {
        $list = $env:ENGINE_OVERRIDES
    } elseif ($PSCommandPath -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSCommandPath) "engine-overrides.txt"))) {
        $list = Join-Path (Split-Path -Parent $PSCommandPath) "engine-overrides.txt"
    } else {
        $list = Join-Path $Tmp "engine-overrides.txt"
        Save-Download -Uri "$RawBase/scripts/engine-overrides.txt" -OutFile $list
    }
    if ([string]::IsNullOrWhiteSpace($list)) { return }
    foreach ($line in Get-Content -LiteralPath $list) {
        $text = $line.Trim()
        if ($text -eq "" -or $text.StartsWith("#")) { continue }
        $fields = $text -split '\s+'
        if ($fields.Count -ne 3 -or $fields[0] -notmatch '^[A-Za-z0-9._-]+\.jar$' -or $fields[1] -notmatch '^[A-Za-z0-9._/-]+\.jar$' -or $fields[1].Contains("..") -or $fields[2] -notmatch '^[0-9a-f]{64}$') {
            throw "Refusing to install. Bad line in the engine override list: $text"
        }
        $target = Join-Path $Src ("lib\" + $fields[0])
        if (-not (Test-Path -LiteralPath $target)) { throw "Refusing to install. $($fields[0]) is not in Dependency-Check $Pin." }
        $download = Join-Path $Tmp "override.jar"
        Save-Download -Uri ("https://repo1.maven.org/maven2/" + $fields[1]) -OutFile $download
        Assert-Sha256 -Path $download -Expected $fields[2] -What ($fields[1] -split '/')[-1]
        Move-Item -Force $download $target
        Write-Output "Replaced lib\$($fields[0])"
    }
}

# The gpg in Git for Windows is an MSYS build. It treats only paths that
# start with "/" as absolute, so "C:\x" and "C:/x" both become relative to
# the working directory. It reports its home as "/c/..." in --version; native
# GnuPG (GnuPG for Windows, Gpg4win) reports "C:\..." and takes Windows paths.
function ConvertTo-GpgPath {
    param([string]$Path)
    $homeLine = (& gpg --version 2>$null | Select-String -Pattern '^Home:' | Select-Object -First 1)
    if ($homeLine -and ($homeLine.ToString() -match '^Home:\s*/')) {
        $drive = $Path.Substring(0, 1).ToLowerInvariant()
        return "/" + $drive + $Path.Substring(2).Replace('\', '/')
    }
    return $Path
}

function Install-Engine {
    param([string]$Pin, [string]$Python)
    # Jeremy Long's Dependency-Check release key. The fingerprint is the pin.
    $ExpectedFingerprint = if ($env:ENGINE_KEY_FINGERPRINT) { $env:ENGINE_KEY_FINGERPRINT } else { "259A55407DD6C00299E6607EFFDE55BE73A2D1ED" }
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if ($null -eq $gpg) { throw "Refusing to install. gpg is required to verify the Dependency-Check signature." }
    $url = "https://github.com/dependency-check/DependencyCheck/releases/download/v$Pin/dependency-check-$Pin-release.zip"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("checkstead-engine-" + [guid]::NewGuid().ToString("n"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $previousGnupg = $env:GNUPGHOME
    try {
        $archive = Join-Path $tmp "dc.zip"
        $signature = Join-Path $tmp "dc.zip.asc"
        Save-Download -Uri $url -OutFile $archive
        Save-Download -Uri ($url + ".asc") -OutFile $signature
        $keyFile = $env:ENGINE_PUBLIC_KEY
        $archivePy = $null
        if ($PSCommandPath) {
            $here = Split-Path -Parent $PSCommandPath
            if (-not $keyFile) {
                $localKey = Join-Path $here "keys\dependency-check-release.asc"
                if (Test-Path -LiteralPath $localKey) { $keyFile = $localKey }
            }
            $localArchive = Join-Path $here "..\src\checkstead\archive.py"
            if (Test-Path -LiteralPath $localArchive) { $archivePy = (Resolve-Path -LiteralPath $localArchive).Path }
        }
        if (-not $keyFile) {
            $keyFile = Join-Path $tmp "dependency-check-release.asc"
            Save-Download -Uri "$RawBase/scripts/keys/dependency-check-release.asc" -OutFile $keyFile
        }
        if (-not $archivePy) {
            $archivePy = Join-Path $tmp "archive.py"
            Save-Download -Uri "$RawBase/src/checkstead/archive.py" -OutFile $archivePy
        }
        $gnupg = Join-Path $tmp "gnupg"
        New-Item -ItemType Directory -Path $gnupg | Out-Null
        $env:GNUPGHOME = ConvertTo-GpgPath $gnupg
        $imported = & gpg --batch --import (ConvertTo-GpgPath $keyFile) 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Refusing to install. The engine signing key could not be imported. gpg said: $imported" }
        $shown = & gpg --batch --with-colons --show-keys (ConvertTo-GpgPath $keyFile) 2>$null
        $fprLine = $shown | Where-Object { $_ -like "fpr:*" } | Select-Object -First 1
        $fpr = ""
        if ($fprLine) { $fpr = $fprLine.Split(":")[9] }
        if ($fpr -ne $ExpectedFingerprint) { throw "Refusing engine key. Expected fingerprint $ExpectedFingerprint but found $fpr." }
        $verified = & gpg --batch --verify (ConvertTo-GpgPath $signature) (ConvertTo-GpgPath $archive) 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Refusing the downloaded engine. The release signature does not verify. gpg said: $verified" }
        $unpacked = Join-Path $tmp "unpacked"
        New-Item -ItemType Directory -Path $unpacked | Out-Null
        if ($Python -eq "py -3") {
            & py -3 $archivePy $archive $unpacked
        } else {
            & $Python $archivePy $archive $unpacked
        }
        if ($LASTEXITCODE -ne 0) { throw "Refusing the downloaded engine. The archive was rejected." }
        $bat = Get-ChildItem -Path $unpacked -Filter dependency-check.bat -Recurse | Select-Object -First 1
        if ($null -eq $bat) { throw "The Dependency-Check archive did not contain bin\dependency-check.bat" }
        $src = $bat.Directory.Parent.FullName
        Install-EngineOverrides -Src $src -Tmp $tmp -Pin $Pin
        if (Test-Path (Join-Path $Root "dependency-check")) { Remove-Item -Recurse -Force (Join-Path $Root "dependency-check") }
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        Move-Item $src (Join-Path $Root "dependency-check")
        $installed = Join-Path $Root "dependency-check\bin\dependency-check.bat"
        if (-not (Test-EnginePin $installed $Pin)) {
            Remove-Item -Recurse -Force (Join-Path $Root "dependency-check")
            throw "Refusing the downloaded engine. Expected $Pin."
        }
        Write-Output "Installed Dependency-Check $Pin under $Root\dependency-check"
    } finally {
        if ($null -eq $previousGnupg) { Remove-Item Env:GNUPGHOME -ErrorAction SilentlyContinue } else { $env:GNUPGHOME = $previousGnupg }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -Recurse -Force $tmp }
    }
}

function Test-ChecksteadCurrent {
    $exe = Join-Path $Root "venv\Scripts\checkstead.exe"
    if (-not (Test-Path $exe)) { return $false }
    & $exe version 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    $scan = Get-ChildItem -Path (Join-Path $Root "venv") -Filter scan.py -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\checkstead\\scan\.py$' } |
        Select-Object -First 1
    if ($null -eq $scan) { return $true }
    $text = Get-Content -Raw $scan.FullName
    if ($text -notmatch '--disableYarnAudit') { return $false }
    if ($text -notmatch 'dependency-check\.bat') { return $false }
    $dir = Split-Path $scan.FullName
    return (Test-Path (Join-Path $dir "score.py")) -and (Test-Path (Join-Path $dir "github_app.py"))
}

function Install-ChecksteadPackage {
    param([string]$Python)
    $venvPython = Join-Path $Root "venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        if (Test-Path (Join-Path $Root "venv")) { Remove-Item -Recurse -Force (Join-Path $Root "venv") }
        if ($Python -eq "py -3") {
            & py -3 -m venv (Join-Path $Root "venv")
        } else {
            & $Python -m venv (Join-Path $Root "venv")
        }
    }
    & $venvPython -m pip install --disable-pip-version-check --upgrade --force-reinstall --no-cache-dir $PackageUrl
    if ($LASTEXITCODE -ne 0) { throw "checkstead could not be installed." }
    Write-Output "Installed checkstead under $Root\venv"
}

function Install-Command {
    $bin = Join-Path $Root "bin"
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $cmd = @'
@echo off
set "ROOT=%USERPROFILE%\checkstead"
java -version >nul 2>&1
if errorlevel 1 (
  if exist "%ROOT%\jdk\bin\java.exe" (
    set "JAVA_HOME=%ROOT%\jdk"
    set "PATH=%JAVA_HOME%\bin;%PATH%"
  )
)
"%ROOT%\venv\Scripts\checkstead.exe" %*
'@
    Set-Content -Path (Join-Path $bin "checkstead.cmd") -Value $cmd -Encoding ascii
}

function Install-UserPath {
    $bin = Join-Path $Root "bin"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrEmpty($userPath)) { $userPath = "" }
    $parts = $userPath -split ';' | Where-Object { $_ -ne "" }
    if ($parts -contains $bin) {
        Write-Output "PATH already includes $bin."
        return
    }
    $updated = if ([string]::IsNullOrEmpty($userPath)) { $bin } else { "$userPath;$bin" }
    [Environment]::SetEnvironmentVariable("Path", $updated, "User")
    Write-Output "Added $bin to the user PATH."
}

New-Item -ItemType Directory -Path $Root -Force | Out-Null

# CHECKSTEAD_INSTALL_RUNTIMES=1 installs the pinned Python and JDK even when the
# machine has its own, so their checksum paths are exercised (CI does this).
$forceRuntimes = $env:CHECKSTEAD_INSTALL_RUNTIMES -eq "1"

$python = if ($forceRuntimes) { $null } else { Select-Python }
if ($python) {
    Write-Output "Python 3.11+ already present."
} else {
    Install-Python
    $python = Join-Path $Root "python\python.exe"
}

$bundledJdk = $false
if ((-not $forceRuntimes) -and (Test-JavaRuns)) {
    Write-Output "java already runs."
} elseif ((-not $forceRuntimes) -and (Test-Path (Join-Path $Root "jdk\bin\java.exe"))) {
    Write-Output "JDK already installed."
    $bundledJdk = $true
} else {
    Install-Jdk
    $bundledJdk = $true
}
if ($bundledJdk) {
    $env:JAVA_HOME = Join-Path $Root "jdk"
    $env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$env:Path"
}

$Pin = (Read-Pin).Trim()
if ($Pin -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Refusing to install. The engine pin is not a release number: $Pin"
}

if (Find-PinnedEngine $Pin) {
    Write-Output "Dependency-Check $Pin already present."
} else {
    Install-Engine $Pin $python
}

if (Test-ChecksteadCurrent) {
    Write-Output "checkstead already installed."
} else {
    Install-ChecksteadPackage $python
}

Install-Command
Install-UserPath
Write-Output "Open a new terminal, then run: checkstead scan --scan . --project my-service"
Write-Output "From any directory, checkstead ui starts the local server."
