# Build on Windows x64 with Python 3.12, Node.js 22, Rust stable and MSVC tools.
[CmdletBinding()]
param(
    [switch]$SkipDependencyInstall,
    [switch]$SkipTests,
    [switch]$EngineOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') {
    throw 'This script must run on Windows. The Windows Hello adapter requires real Windows acceptance testing.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$desktopRoot = Join-Path $repoRoot 'desktop'
$venvRoot = Join-Path $desktopRoot '.venv'
$pythonExe = Join-Path $venvRoot 'Scripts/python.exe'
$buildRoot = Join-Path $desktopRoot '.build'
$binaryRoot = Join-Path $desktopRoot 'src-tauri/binaries'
$sidecarName = 'desktop-engine-x86_64-pc-windows-msvc'
$env:PYTHONUTF8 = '1'
$env:SKYSEAL_TEST_PYTHON = $pythonExe

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repoRoot
try {
    if (-not (Test-Path $pythonExe)) {
        Invoke-Checked -Program 'python' -Arguments @('-m', 'venv', $venvRoot)
    }
    Invoke-Checked -Program $pythonExe -Arguments @('-c', 'import struct,sys; assert sys.version_info >= (3,12), "Python 3.12+ required"; assert struct.calcsize("P") == 8, "64-bit Python required"')
    if (-not $SkipDependencyInstall) {
        Invoke-Checked -Program $pythonExe -Arguments @('-m', 'pip', 'install', '-r', (Join-Path $desktopRoot 'requirements-build.txt'))
    }
    if (-not $SkipTests) {
        # Existing service/Drive regression tests assert POSIX permissions and
        # invoke bash. CI runs those separately on Linux.
        foreach ($suite in @('desktop/tests')) {
            Invoke-Checked -Program $pythonExe -Arguments @('-m', 'unittest', 'discover', '-s', $suite, '-v')
        }
    }

    New-Item -ItemType Directory -Force -Path $binaryRoot, $buildRoot | Out-Null
    Invoke-Checked -Program $pythonExe -Arguments @(
        '-m', 'PyInstaller', '--clean', '--noconfirm', '--onefile', '--console',
        '--name', $sidecarName,
        '--distpath', $binaryRoot,
        '--workpath', (Join-Path $buildRoot 'pyinstaller'),
        '--specpath', $buildRoot,
        '--paths', $repoRoot,
        '--hidden-import', 'opentimestamps.core.timestamp',
        '--hidden-import', 'opentimestamps.core.notary',
        '--hidden-import', 'opentimestamps.core.op',
        '--hidden-import', 'opentimestamps.core.serialize',
        '--hidden-import', 'bitcoin.core',
        '--exclude-module', 'otsclient',
        '--exclude-module', 'bitcoin.wallet',
        '--exclude-module', 'bitcoin.rpc',
        '--exclude-module', 'bitcoin.core.key',
        '--exclude-module', 'opentimestamps.core.git',
        '--copy-metadata', 'opentimestamps',
        '--copy-metadata', 'python-bitcoinlib',
        '--copy-metadata', 'cryptography',
        (Join-Path $PSScriptRoot 'engine_entry.py')
    )
    $sidecarExe = Join-Path $binaryRoot ($sidecarName + '.exe')
    Invoke-Checked -Program $pythonExe -Arguments @((Join-Path $PSScriptRoot 'smoke_engine.py'), $sidecarExe)

    if (-not $EngineOnly) {
        Push-Location $desktopRoot
        try {
            if (-not $SkipDependencyInstall) {
                if (Test-Path 'package-lock.json') {
                    Invoke-Checked -Program 'npm.cmd' -Arguments @('ci')
                } else {
                    Invoke-Checked -Program 'npm.cmd' -Arguments @('install')
                }
            }
            Invoke-Checked -Program 'npm.cmd' -Arguments @('run', 'check')
            if (-not $SkipTests) {
                Invoke-Checked -Program 'npm.cmd' -Arguments @('test')
            }
            Invoke-Checked -Program 'npm.cmd' -Arguments @('run', 'build', '--', '--bundles', 'nsis')
        } finally {
            Pop-Location
        }
    }
    Write-Host 'Build finished. Installer output: desktop/src-tauri/target/release/bundle/nsis'
    Write-Host 'This development build is unsigned. A successful build does not establish real-device ORCID/Windows Hello acceptance.'
} finally {
    Pop-Location
}
