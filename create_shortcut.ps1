# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BitWitness - Desktop Shortcut Creator
#  Run this once:  powershell -ExecutionPolicy Bypass -File create_shortcut.ps1
#  It will place a BitWitness shortcut on your Desktop.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$PythonW = Join-Path $ProjectDir "venv\Scripts\pythonw.exe"
$Script = Join-Path $ProjectDir "gui_app.py"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "BitWitness.lnk"

# Check pythonw exists
if (-not (Test-Path $PythonW)) {
    Write-Host "[ERROR] pythonw.exe not found at: $PythonW" -ForegroundColor Red
    Write-Host "Make sure the virtual environment is set up:" -ForegroundColor Yellow
    Write-Host "  python -m venv venv"
    Write-Host "  venv\Scripts\pip install -r requirements.txt"
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if icon exists; use it if available
$IconPath = Join-Path $ProjectDir "bitwitness.ico"
$HasIcon = Test-Path $IconPath

# Create .lnk shortcut via WScript.Shell COM object
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

$Shortcut.TargetPath = $PythonW
$Shortcut.Arguments = "`"$Script`""
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.Description = "BitWitness - Digital Forensics and Evidence Analysis"
$Shortcut.WindowStyle = 7

if ($HasIcon) {
    $Shortcut.IconLocation = "$IconPath,0"
}

$Shortcut.Save()

Write-Host ""
Write-Host "  BitWitness shortcut created on Desktop!" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Location: $ShortcutPath" -ForegroundColor Green
if ($HasIcon) {
    Write-Host "  Icon:     $IconPath" -ForegroundColor Green
}
else {
    Write-Host "  Tip: Place a bitwitness.ico file in the project root for a custom icon." -ForegroundColor Yellow
}
Write-Host ""
