# Install the generated package on an ephemeral Windows runner, then launch its
# real GUI. No ORCID login, certificate trust, or authenticator ceremony occurs.
[CmdletBinding()]
param([string]$InstallerPath = '', [string]$DiagnosticDirectory = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Installed-package smoke testing requires Windows.' }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $InstallerPath) {
    $candidates = @(Get-ChildItem (Join-Path $repoRoot 'desktop/src-tauri/target/release/bundle/nsis') -Filter '*.exe')
    if ($candidates.Count -ne 1) { throw 'Expected exactly one generated NSIS installer.' }
    $InstallerPath = $candidates[0].FullName
}
$InstallerPath = (Resolve-Path $InstallerPath).Path
if (-not $DiagnosticDirectory) { $DiagnosticDirectory = Join-Path $repoRoot 'desktop/.build/installed-smoke' }
New-Item -ItemType Directory -Force -Path $DiagnosticDirectory | Out-Null
$DiagnosticDirectory = (Resolve-Path $DiagnosticDirectory).Path
$temporaryBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$testRoot = Join-Path $temporaryBase ('SkySeal-installed-smoke-' + [Guid]::NewGuid().ToString('N'))
$installRoot = Join-Path $testRoot 'app'
$guiDataRoot = Join-Path $testRoot 'gui-data'
$webviewRoot = Join-Path $testRoot 'webview'
New-Item -ItemType Directory -Force -Path $testRoot | Out-Null

$originalData = $env:SKYSEAL_DESKTOP_DATA_DIR
$originalWebview = $env:WEBVIEW2_USER_DATA_FOLDER
$guiProcess = $null
$failure = $null
$renderFailure = $null
$report = [ordered]@{
    passed = $false
    installer = [IO.Path]::GetFileName($InstallerPath)
    installer_sha256 = (Get-FileHash $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    session_id = (Get-Process -Id $PID).SessionId
    user_interactive = [Environment]::UserInteractive
    installed_sidecar = $false
    installed_sidecar_smoke = $false
    native_window = $false
    gui_started_engine = $false
    rendered_status_marker = $false
    limits = @('No ORCID login, certificate trust, Windows Hello ceremony, or visual pixel comparison is performed.')
}

function Stop-TestProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            & "$env:WINDIR/System32/taskkill.exe" /PID $Process.Id /T /F 2>$null | Out-Null
        }
    } catch { }
}

function Invoke-BoundedProcess {
    param([string]$Executable, [string]$ArgumentLine, [int]$TimeoutSeconds, [string]$LogName)
    $start = @{ FilePath = $Executable; ArgumentList = $ArgumentLine; PassThru = $true }
    if ($LogName) {
        $start.RedirectStandardOutput = Join-Path $DiagnosticDirectory ($LogName + '.stdout.txt')
        $start.RedirectStandardError = Join-Path $DiagnosticDirectory ($LogName + '.stderr.txt')
    }
    $process = Start-Process @start
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        while (-not $process.WaitForExit(500)) {
            if ([DateTime]::UtcNow -gt $deadline) { throw "Timed out after $TimeoutSeconds seconds: $([IO.Path]::GetFileName($Executable))" }
        }
        $process.Refresh()
        if ($process.ExitCode -ne 0) { throw "$([IO.Path]::GetFileName($Executable)) exited with code $($process.ExitCode)" }
    } finally {
        Stop-TestProcessTree $process
        $process.Dispose()
    }
}

try {
    # NSIS /D must be the final argument and must not be quoted, including when
    # its absolute path contains spaces. The install mode is currentUser.
    Invoke-BoundedProcess $InstallerPath ("/S /D=" + $installRoot) 120 ''
    $guiExe = Join-Path $installRoot 'skyseal-desktop.exe'
    $sidecarExe = Join-Path $installRoot 'desktop-engine.exe'
    if (-not (Test-Path -LiteralPath $guiExe -PathType Leaf)) { throw 'The installer did not place skyseal-desktop.exe in the requested directory.' }
    if (-not (Test-Path -LiteralPath $sidecarExe -PathType Leaf)) { throw 'The installer did not place desktop-engine.exe beside the application.' }
    $report.installed_sidecar = $true
    $report.gui_sha256 = (Get-FileHash $guiExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.sidecar_sha256 = (Get-FileHash $sidecarExe -Algorithm SHA256).Hash.ToLowerInvariant()

    $pythonExe = Join-Path $repoRoot 'desktop/.venv/Scripts/python.exe'
    $engineSmoke = Join-Path $PSScriptRoot 'smoke_engine.py'
    Invoke-BoundedProcess $pythonExe ('"' + $engineSmoke + '" "' + $sidecarExe + '"') 60 'installed-engine'
    $report.installed_sidecar_smoke = $true

    # The harness above uses a different temporary profile. Only the GUI may
    # create this fresh SQLite file, through the JS -> Tauri -> sidecar bridge.
    if (Test-Path $guiDataRoot) { throw 'The GUI test profile was not fresh.' }
    $env:SKYSEAL_DESKTOP_DATA_DIR = $guiDataRoot
    $env:WEBVIEW2_USER_DATA_FOLDER = $webviewRoot
    $guiProcess = Start-Process -FilePath $guiExe -WorkingDirectory $installRoot -PassThru
    $report.gui_pid = $guiProcess.Id
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        Start-Sleep -Milliseconds 250
        $guiProcess.Refresh()
        if ($guiProcess.HasExited) { throw "The installed GUI exited during startup (code $($guiProcess.ExitCode))." }
        $report.native_window = $guiProcess.MainWindowHandle -ne [IntPtr]::Zero -and $guiProcess.MainWindowTitle -eq 'SkySeal'
        $report.gui_started_engine = Test-Path -LiteralPath (Join-Path $guiDataRoot 'state.sqlite3') -PathType Leaf
    } until (($report.native_window -and $report.gui_started_engine) -or [DateTime]::UtcNow -gt $deadline)
    $report.window_title = $guiProcess.MainWindowTitle
    if (-not $report.native_window) { throw 'The installed GUI did not expose its SkySeal main window within 25 seconds.' }
    if (-not $report.gui_started_engine) { throw 'The installed GUI did not call its engine through the initial JavaScript/Tauri bridge.' }

    # UI Automation is diagnostic: service/noninteractive desktops sometimes
    # expose only the host window. Give it an independent eight-second bound.
    try {
        $uiaScript = Join-Path $testRoot 'read-uia.ps1'
        @'
param([long]$WindowHandle)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$window = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]::new($WindowHandle))
$deadline = [DateTime]::UtcNow.AddSeconds(5)
do {
    $elements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    $names = @()
    $fileButtonEnabled = $false
    for ($index = 0; $index -lt [Math]::Min($elements.Count, 1000); $index++) {
        try {
            $item = $elements[$index].Current
            if (-not $item.IsOffscreen -and $item.Name) { $names += $item.Name }
            if (-not $item.IsOffscreen -and $item.Name -eq 'ファイルを選択' -and $item.IsEnabled) { $fileButtonEnabled = $true }
        } catch { }
    }
    $text = $names -join ' '
    $domSeen = $text.Contains('研究の記録を、確かな証拠に。')
    $ready = $text.Contains('本人登録が必要です') -and $text.Contains('ORCIDと署名鍵を設定') -and $text.Contains('最初に本人登録を行ってください') -and $fileButtonEnabled -and -not $text.Contains('画面プレビューです。')
    if ($ready) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
@{names = $names; dom_seen = $domSeen; ready = $ready; file_button_enabled = $fileButtonEnabled} | ConvertTo-Json -Depth 4
'@ | Set-Content -LiteralPath $uiaScript -Encoding utf8BOM
        $uiaArguments = '-NoProfile -NonInteractive -File "' + $uiaScript + '" -WindowHandle ' + $guiProcess.MainWindowHandle.ToInt64()
        Invoke-BoundedProcess 'powershell.exe' $uiaArguments 8 'ui-automation'
        $uia = Get-Content (Join-Path $DiagnosticDirectory 'ui-automation.stdout.txt') -Raw -Encoding utf8 | ConvertFrom-Json
        $report.rendered_status_marker = $uia.ready -eq $true
        $report.file_button_enabled = $uia.file_button_enabled -eq $true
        if ($uia.dom_seen -and -not $uia.ready) {
            $renderFailure = 'UI Automation exposed the page, but its ready status and enabled file button did not appear.'
        }
        if (-not $report.rendered_status_marker) {
            $report.limits += 'The native window and GUI-initiated engine call passed; UI Automation did not expose the rendered Japanese status marker.'
        }
    } catch {
        $report.uia_diagnostic = $_.Exception.Message
        $report.limits += 'The native window and GUI-initiated engine call passed; rendered DOM text could not be inspected by UI Automation.'
    }
    if ($null -ne $renderFailure) { throw $renderFailure }

    # Check that startup survives beyond the first window event.
    Start-Sleep -Seconds 2
    $guiProcess.Refresh()
    if ($guiProcess.HasExited) { throw 'The installed GUI exited immediately after initialization.' }
    $report.passed = $true
} catch {
    $failure = $_
    $report.error = $_.Exception.Message
} finally {
    # This is an ephemeral CI desktop containing only the application's empty
    # test profile. Screenshot failure must not turn a successful launch into a
    # failed test; its presence alone never counts as a rendering assertion.
    if ($null -ne $guiProcess) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
            if ($screen.Width -le 0 -or $screen.Height -le 0) { throw 'No desktop capture surface.' }
            $bitmap = [System.Drawing.Bitmap]::new($screen.Width, $screen.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.CopyFromScreen($screen.X, $screen.Y, 0, 0, $screen.Size)
                $bitmap.Save((Join-Path $DiagnosticDirectory 'installed-window.png'), [System.Drawing.Imaging.ImageFormat]::Png)
                $report.screenshot = 'installed-window.png'
            } finally { $graphics.Dispose(); $bitmap.Dispose() }
        } catch { $report.screenshot_diagnostic = $_.Exception.Message }
        try {
            $guiProcess.Refresh()
            if (-not $guiProcess.HasExited) {
                $null = $guiProcess.CloseMainWindow()
                $null = $guiProcess.WaitForExit(4000)
            }
        } catch { }
        Stop-TestProcessTree $guiProcess
    }
    # Remove this test's per-user shortcuts and uninstall registration as well
    # as its files. _?= keeps NSIS in this process so the wait remains bounded.
    $uninstaller = Join-Path $installRoot 'uninstall.exe'
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        try { Invoke-BoundedProcess $uninstaller ('/S _?=' + $installRoot) 15 '' }
        catch { $report.cleanup_diagnostic = $_.Exception.Message }
    }
    $env:SKYSEAL_DESKTOP_DATA_DIR = $originalData
    $env:WEBVIEW2_USER_DATA_FOLDER = $originalWebview
    $report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $DiagnosticDirectory 'result.json') -Encoding utf8
}

Get-Content (Join-Path $DiagnosticDirectory 'result.json') -Raw
if ($null -ne $failure) { throw $failure }
