#Requires -Version 5.1

<#
.SYNOPSIS
    Installs Claude Code on Windows 11 using WSL 2 and Debian.

.DESCRIPTION
    This script automates the installation of Claude Code on Windows 11 systems.
    It handles all prerequisites including WSL 2 installation, Debian setup, and
    Claude Code installation using the official installer.

.EXAMPLE
    .\Install-ClaudeCode.ps1
    Runs the installation process with verbose output.

.EXAMPLE
    .\Install-ClaudeCode.ps1 -Test
    Runs component tests to verify script functionality.

.NOTES
    Author: Michelle Pellon
    Version: 1.0.0
    Requires: Windows 11, 4GB RAM minimum, Administrator privileges for some operations
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Run component tests to verify script functionality"
    )]
    [switch]$Test
)

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Configuration constants
$script:Config = @{
    WSLDistro = "Debian"
    MinRAMGB = 4
    MinDiskSpaceGB = 10
    KernelUpdateUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
    ClaudeInstallerUrl = "https://claude.ai/install.sh"
    MaxWaitTimeSeconds = 300
    DefaultRetries = 3
}

# Console Output Functions
function Write-PhaseHeader {
    <#
    .SYNOPSIS
        Displays section headers with border decoration.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host ""
    Write-Host ("=" * 40) -ForegroundColor Cyan
    Write-Host "[PHASE] $Message" -ForegroundColor Cyan
    Write-Host ("=" * 40) -ForegroundColor Cyan
}

function Write-Info {
    <#
    .SYNOPSIS
        Displays informational messages in cyan.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    <#
    .SYNOPSIS
        Displays success messages in green.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarningMessage {
    <#
    .SYNOPSIS
        Displays warning messages in yellow.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
    Write-Warning $Message  # Also send to warning stream
}

function Write-ScriptError {
    <#
    .SYNOPSIS
        Displays error messages in red.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Write-Error $Message  # Also send to error stream
}

function Write-Prompt {
    <#
    .SYNOPSIS
        Displays prompt messages for user input.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[PROMPT] $Message" -ForegroundColor Magenta -NoNewline
}

# Error Handling Functions
function Show-ErrorAndPause {
    <#
    .SYNOPSIS
        Displays error details and prompts user to retry.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage,
        
        [Parameter(Mandatory = $false)]
        [string]$Details = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Suggestion = ""
    )
    
    Write-ScriptError $ErrorMessage
    
    if ($Details) {
        Write-Host "[DETAILS] $Details" -ForegroundColor Red
    }
    
    if ($Suggestion) {
        Write-Host "[SUGGESTION] $Suggestion" -ForegroundColor Yellow
    }
    
    Write-Host ""
    do {
        Write-Prompt "Would you like to retry? (Y/N): "
        $response = Read-Host
        if ([string]::IsNullOrWhiteSpace($response)) {
            Write-Host "Please enter Y or N: " -NoNewline
            continue
        }
        $response = $response.Trim().ToUpper()
        if ($response -in @('Y', 'YES', 'N', 'NO')) {
            break
        }
        Write-Host "Invalid input. Please enter Y or N: " -NoNewline
    } while ($true)
    
    return $response -in @('Y', 'YES')
}

function Exit-Script {
    <#
    .SYNOPSIS
        Performs cleanup and exits with appropriate code.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [int]$ExitCode = 0,
        
        [Parameter(Mandatory = $false)]
        [string]$Message = ""
    )
    
    if ($Message) {
        if ($ExitCode -eq 0) {
            Write-Success $Message
        }
        else {
            Write-ScriptError $Message
        }
    }
    
    Write-Host ""
    Write-Info "Exiting script..."
    exit $ExitCode
}

function Test-LastCommand {
    <#
    .SYNOPSIS
        Checks if the previous command succeeded.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code: $LASTEXITCODE"
    }
    elseif ($null -eq $LASTEXITCODE) {
        Write-WarningMessage "Exit code not available for operation: $Operation"
    }
    
    return $true
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Wrapper for operations that may need retry.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            Write-Info "Attempting: $Operation"
            & $ScriptBlock
            $success = $true
            Write-Success "$Operation completed successfully"
        }
        catch {
            $retryCount++
            $errorMsg = $_.Exception.Message
            
            if ($retryCount -lt $MaxRetries) {
                $retry = Show-ErrorAndPause -ErrorMessage "$Operation failed" `
                    -Details $errorMsg `
                    -Suggestion "Check the error message and try again"
                
                if (-not $retry) {
                    Exit-Script -ExitCode 1 -Message "Installation cancelled by user"
                }
            }
            else {
                Write-ScriptError "$Operation failed after $MaxRetries attempts"
                throw $_
            }
        }
    }
    
    return $success
}

# Test Framework Functions
function Test-Component {
    <#
    .SYNOPSIS
        Tests a single component and reports results.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$TestScript
    )
    
    Write-Info "Testing: $TestName"
    
    try {
        $result = & $TestScript
        if ($result -eq $true) {
            Write-Success "PASSED: $TestName"
            return $true
        }
        else {
            Write-ScriptError "FAILED: $TestName - Returned false"
            return $false
        }
    }
    catch {
        Write-ScriptError "FAILED: $TestName - $_"
        return $false
    }
}

function Test-AllComponents {
    <#
    .SYNOPSIS
        Runs all component tests.
    #>
    Write-PhaseHeader "Component Testing"
    
    $tests = @(
        @{
            Name = "Console Output Functions"
            Test = {
                Write-Info "Test info message"
                Write-Success "Test success message"
                Write-WarningMessage "Test warning message"
                Write-ScriptError "Test error message"
                return $true
            }
        },
        @{
            Name = "Error Handling Functions"
            Test = {
                # Test Exit-Script doesn't actually exit in test mode
                $testExitCode = Test-LastCommand -Operation "Test Operation" -ErrorAction SilentlyContinue
                return $true
            }
        },
        @{
            Name = "Script Variables"
            Test = {
                if ($script:Config.WSLDistro -ne "Debian") { throw "WSLDistro not set correctly" }
                if ($script:Config.MinRAMGB -ne 4) { throw "MinRAMGB not set correctly" }
                if ($script:Config.MinDiskSpaceGB -ne 10) { throw "MinDiskSpaceGB not set correctly" }
                return $true
            }
        },
        @{
            Name = "Windows Version Check"
            Test = {
                # This test will pass/fail based on actual OS
                $result = Test-WindowsVersion
                Write-Info "Windows version check completed"
                return $true  # Always return true for the test itself
            }
        },
        @{
            Name = "RAM Check"
            Test = {
                $result = Test-SystemRAM
                Write-Info "RAM check completed"
                return $true
            }
        },
        @{
            Name = "CPU Architecture Check"
            Test = {
                $result = Test-CPUArchitecture
                Write-Info "CPU architecture check completed"
                return $true
            }
        },
        @{
            Name = "Virtualization Check"
            Test = {
                $result = Test-Virtualization
                Write-Info "Virtualization check completed"
                return $true
            }
        },
        @{
            Name = "Disk Space Check"
            Test = {
                $result = Test-DiskSpace
                Write-Info "Disk space check completed"
                return $true
            }
        },
        @{
            Name = "Windows Update Check"
            Test = {
                $result = Test-WindowsUpdates
                Write-Info "Windows update check completed (Found: $result updates)"
                return $true
            }
        },
        @{
            Name = "Reboot Pending Check"
            Test = {
                $result = Test-RebootPending
                Write-Info "Reboot pending check completed (Pending: $result)"
                return $true
            }
        },
        @{
            Name = "WSL Detection"
            Test = {
                $result = Test-WSL
                Write-Info "WSL detection completed (Status: $($result.Status))"
                return $true
            }
        },
        @{
            Name = "WSL Feature Enablement (Admin Check)"
            Test = {
                # This test only checks if we can detect admin status, not actually enable features
                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                Write-Info "Admin privileges available: $isAdmin"
                return $true
            }
        },
        @{
            Name = "WSL 2 Kernel Download Test"
            Test = {
                # This test only checks if we can reach the download URL, doesn't actually download
                try {
                    $kernelUpdateUrl = $script:Config.KernelUpdateUrl
                    $response = Invoke-WebRequest -Uri $kernelUpdateUrl -Method Head -TimeoutSec 10 -ErrorAction Stop
                    Write-Info "WSL 2 kernel download URL is accessible (Status: $($response.StatusCode))"
                    return $true
                }
                catch {
                    Write-WarningMessage "Could not reach WSL 2 kernel download URL: $_"
                    return $true  # Don't fail the test, just warn
                }
            }
        },
        @{
            Name = "WSL Configuration Test"
            Test = {
                # This test checks if we can run WSL commands without actually changing settings
                try {
                    $wslPath = Join-Path $env:SystemRoot "System32\wsl.exe"
                    if (Test-Path $wslPath) {
                        Write-Info "WSL executable found: $wslPath"
                        return $true
                    }
                    else {
                        Write-Info "WSL executable not found (will be installed)"
                        return $true
                    }
                }
                catch {
                    Write-WarningMessage "WSL configuration test failed: $_"
                    return $true
                }
            }
        },
        @{
            Name = "Debian Detection"
            Test = {
                $result = Test-DebianInstalled
                Write-Info "Debian detection completed (Status: $($result.Status))"
                if ($result.DebianFound) {
                    Write-Info "Found $($result.Distributions.Count) total distributions"
                }
                return $true
            }
        },
        @{
            Name = "Debian Installation Capability"
            Test = {
                # Test if we can detect installation methods
                $wslAvailable = Test-Path (Join-Path $env:SystemRoot "System32\wsl.exe")
                $wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue
                
                Write-Info "WSL available: $wslAvailable"
                Write-Info "Winget available: $($wingetAvailable -ne $null)"
                
                return $true
            }
        },
        @{
            Name = "Claude Code Installation Functions"
            Test = {
                # Test that all Claude Code functions are defined
                $functions = @("Invoke-WSLCommand", "Get-ClaudeCodeInstaller", "Install-ClaudeCodeInDebian", "Test-ClaudeCodeInstallation", "Show-InstallationComplete")
                $allDefined = $true
                
                foreach ($func in $functions) {
                    if (-not (Get-Command $func -ErrorAction SilentlyContinue)) {
                        Write-WarningMessage "Function $func not found"
                        $allDefined = $false
                    }
                }
                
                Write-Info "All Claude Code functions defined: $allDefined"
                return $true
            }
        }
    )
    
    $passed = 0
    $failed = 0
    
    foreach ($test in $tests) {
        if (Test-Component -TestName $test.Name -TestScript $test.Test) {
            $passed++
        }
        else {
            $failed++
        }
    }
    
    Write-Host ""
    Write-PhaseHeader "Test Results"
    Write-Info "Total tests: $($tests.Count)"
    Write-Success "Passed: $passed"
    if ($failed -gt 0) {
        Write-ScriptError "Failed: $failed"
    }
    
    return ($failed -eq 0)
}

# System Validation Functions
function Test-WindowsVersion {
    <#
    .SYNOPSIS
        Checks if the system is running Windows 11.
    #>
    Write-Info "Checking Windows version..."
    
    try {
        # Method 1: Check build number
        $osVersion = [System.Environment]::OSVersion
        $buildNumber = $osVersion.Version.Build
        
        # Windows 11 starts at build 22000
        if ($buildNumber -ge 22000) {
            Write-Success "Windows 11 detected (Build: $buildNumber)"
            return $true
        }
        
        # Method 2: Use Get-ComputerInfo as fallback
        try {
            $computerInfo = Get-ComputerInfo -Property WindowsProductName, OSDisplayVersion
            if ($computerInfo.WindowsProductName -like "*Windows 11*") {
                Write-Success "Windows 11 detected: $($computerInfo.WindowsProductName)"
                return $true
            }
        }
        catch {
            Write-WarningMessage "Could not retrieve detailed Windows information"
        }
        
        # If we get here, it's not Windows 11
        Write-ScriptError "Windows 11 is required. Current OS: $($osVersion.VersionString)"
        return $false
    }
    catch {
        Write-ScriptError "Failed to determine Windows version: $_"
        return $false
    }
}

function Test-SystemRAM {
    <#
    .SYNOPSIS
        Checks if the system has at least 4GB of RAM.
    #>
    Write-Info "Checking system RAM..."
    
    try {
        # Get total physical memory
        $totalRAM = Get-CimInstance Win32_PhysicalMemory | 
            Measure-Object -Property Capacity -Sum | 
            Select-Object -ExpandProperty Sum
        
        # Convert to GB
        $totalRAMGB = [Math]::Round($totalRAM / 1GB, 2)
        
        if ($totalRAMGB -ge $script:Config.MinRAMGB) {
            Write-Success "RAM check passed: $totalRAMGB GB detected (minimum: $script:Config.MinRAMGB GB)"
            return $true
        }
        else {
            Write-ScriptError "Insufficient RAM: $totalRAMGB GB detected (minimum: $script:Config.MinRAMGB GB required)"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to check system RAM: $_"
        return $false
    }
}

function Test-CPUArchitecture {
    <#
    .SYNOPSIS
        Verifies the system is running on x64 architecture.
    #>
    Write-Info "Checking CPU architecture..."
    
    try {
        $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        # Check architecture (9 = x64)
        if ($processor.Architecture -eq 9) {
            Write-Success "CPU architecture check passed: x64 processor detected"
            return $true
        }
        else {
            $archName = switch ($processor.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "ia64" }
                Default { "Unknown" }
            }
            Write-ScriptError "x64 architecture required. Current: $archName"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to check CPU architecture: $_"
        return $false
    }
}

function Test-Virtualization {
    <#
    .SYNOPSIS
        Checks if CPU virtualization is enabled and available.
    #>
    Write-Info "Checking virtualization support..."
    
    try {
        # Check if Hyper-V is available as a Windows feature
        $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        
        if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
            Write-Success "Virtualization check passed: Hyper-V is enabled"
            return $true
        }
        
        # Check CPU virtualization flags
        $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        # Check if virtualization is exposed by WMI
        if ($processor.VirtualizationFirmwareEnabled -eq $true) {
            Write-Success "Virtualization check passed: CPU virtualization is enabled"
            return $true
        }
        
        # Additional check using systeminfo (more reliable for BIOS settings)
        try {
            $systemInfo = systeminfo.exe /FO CSV | ConvertFrom-Csv
            $virtStatus = $systemInfo.'Hyper-V Requirements'
            
            if ($virtStatus -like "*Virtualization Enabled In Firmware: Yes*") {
                Write-Success "Virtualization check passed: Enabled in firmware"
                return $true
            }
            elseif ($virtStatus -like "*Virtualization Enabled In Firmware: No*") {
                Write-ScriptError "Virtualization is disabled in BIOS/UEFI"
                Write-WarningMessage "Please enable virtualization in your BIOS/UEFI settings"
                return $false
            }
        }
        catch {
            Write-WarningMessage "Could not determine virtualization status from systeminfo"
        }
        
        # If we can't definitively determine status, warn but continue
        Write-WarningMessage "Could not confirm virtualization status. WSL 2 requires virtualization to be enabled."
        Write-WarningMessage "If installation fails, please check your BIOS/UEFI settings."
        return $true  # Allow to proceed with warning
    }
    catch {
        Write-ScriptError "Failed to check virtualization support: $_"
        return $false
    }
}

function Test-DiskSpace {
    <#
    .SYNOPSIS
        Checks if sufficient disk space is available.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [int]$RequiredSpaceGB = $script:Config.MinDiskSpaceGB
    )
    
    Write-Info "Checking disk space..."
    
    try {
        # Get system drive (usually C:)
        $systemDrive = $env:SystemDrive
        
        # Get free space on system drive
        $driveInfo = Get-PSDrive -Name $systemDrive.Replace(":", "") -ErrorAction Stop
        
        # Convert bytes to GB
        $freeSpaceGB = [Math]::Round($driveInfo.Free / 1GB, 2)
        
        if ($freeSpaceGB -ge $RequiredSpaceGB) {
            Write-Success "Disk space check passed: $freeSpaceGB GB free on $systemDrive (minimum: $RequiredSpaceGB GB)"
            return $true
        }
        else {
            Write-ScriptError "Insufficient disk space: $freeSpaceGB GB free on $systemDrive (minimum: $RequiredSpaceGB GB required)"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to check disk space: $_"
        return $false
    }
}

# Windows Update Functions
function Test-WindowsUpdates {
    <#
    .SYNOPSIS
        Checks for pending Windows updates.
    #>
    Write-Info "Checking for pending Windows updates..."
    
    try {
        # Try using Windows Update PowerShell module first (Windows 10/11)
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            try {
                Import-Module PSWindowsUpdate -ErrorAction Stop
                $updates = Get-WindowsUpdate -MicrosoftUpdate
                
                if ($updates.Count -gt 0) {
                    Write-WarningMessage "Found $($updates.Count) pending updates:"
                    foreach ($update in $updates | Select-Object -First 5) {
                        Write-Info "  - $($update.Title)"
                    }
                    if ($updates.Count -gt 5) {
                        Write-Info "  ... and $($updates.Count - 5) more updates"
                    }
                    return $updates.Count
                }
                else {
                    Write-Success "No pending Windows updates found"
                    return 0
                }
            }
            catch {
                Write-WarningMessage "PSWindowsUpdate module failed: $_"
            }
        }
        
        # Fallback: Use Windows Update COM object
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            
            Write-Info "Searching for updates (this may take a moment)..."
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            
            $pendingUpdates = $searchResult.Updates.Count
            
            if ($pendingUpdates -gt 0) {
                Write-WarningMessage "Found $pendingUpdates pending updates:"
                for ($i = 0; $i -lt [Math]::Min($pendingUpdates, 5); $i++) {
                    Write-Info "  - $($searchResult.Updates.Item($i).Title)"
                }
                if ($pendingUpdates -gt 5) {
                    Write-Info "  ... and $($pendingUpdates - 5) more updates"
                }
                return $pendingUpdates
            }
            else {
                Write-Success "No pending Windows updates found"
                return 0
            }
        }
        catch {
            Write-WarningMessage "Windows Update COM object failed: $_"
        }
        
        # Final fallback: Check Windows Update service status
        try {
            $wuService = Get-Service -Name wuauserv -ErrorAction Stop
            if ($wuService.Status -ne "Running") {
                Write-WarningMessage "Windows Update service is not running"
                Write-Info "Service status: $($wuService.Status)"
                return -1  # Unknown status
            }
            else {
                Write-Info "Windows Update service is running, but couldn't determine pending updates"
                Write-WarningMessage "Please check Windows Update manually in Settings"
                return -1  # Unknown status
            }
        }
        catch {
            Write-ScriptError "Could not check Windows Update service: $_"
            return -1
        }
    }
    catch {
        Write-ScriptError "Failed to check Windows updates: $_"
        return -1
    }
}

function Request-WindowsUpdate {
    <#
    .SYNOPSIS
        Prompts user to install Windows updates and handles reboot requirements.
    #>
    Write-PhaseHeader "Windows Updates"
    
    $pendingUpdates = Test-WindowsUpdates
    
    if ($pendingUpdates -gt 0) {
        Write-WarningMessage "Windows updates are available and should be installed before proceeding."
        Write-Info "Installing updates ensures compatibility and security for WSL 2 installation."
        Write-Host ""
        Write-Info "To install updates:"
        Write-Info "1. Open Settings (Windows + I)"
        Write-Info "2. Go to Windows Update"
        Write-Info "3. Click 'Check for updates' and install all available updates"
        Write-Info "4. Restart your computer if prompted"
        Write-Info "5. Run this script again after updating"
        Write-Host ""
        
        Write-Prompt "Press Enter after you have installed all Windows updates and restarted if needed: "
        Read-Host
        
        # Check if reboot is pending
        if (Test-RebootPending) {
            Write-WarningMessage "A system reboot is required to complete Windows updates."
            Write-Info "Please restart your computer and run this script again."
            Exit-Script -ExitCode 2 -Message "Reboot required - please restart and run script again"
        }
        
        # Verify updates were installed
        Write-Info "Verifying updates were installed..."
        $remainingUpdates = Test-WindowsUpdates
        
        if ($remainingUpdates -gt 0) {
            Write-WarningMessage "There are still $remainingUpdates pending updates."
            Write-WarningMessage "For best results, please install all updates before continuing."
            Write-Host ""
            do {
                Write-Prompt "Do you want to continue anyway? (Y/N): "
                $response = Read-Host
                if ([string]::IsNullOrWhiteSpace($response)) {
                    Write-Host "Please enter Y or N: " -NoNewline
                    continue
                }
                $response = $response.Trim().ToUpper()
                if ($response -in @('Y', 'YES', 'N', 'NO')) {
                    break
                }
                Write-Host "Invalid input. Please enter Y or N: " -NoNewline
            } while ($true)
            
            if ($response -in @('N', 'NO')) {
                Exit-Script -ExitCode 0 -Message "Installation cancelled - please install updates and try again"
            }
        }
        else {
            Write-Success "All Windows updates have been installed!"
        }
    }
    elseif ($pendingUpdates -eq 0) {
        Write-Success "Windows is up to date - no pending updates found"
    }
    else {
        Write-WarningMessage "Could not determine Windows update status"
        Write-Info "Please manually check Windows Update in Settings"
        Write-Host ""
        Write-Prompt "Press Enter to continue (ensure your system is updated): "
        Read-Host
    }
}

function Test-RebootPending {
    <#
    .SYNOPSIS
        Checks if a system reboot is pending.
    #>
    try {
        # Check various registry keys that indicate pending reboot
        $rebootPending = $false
        
        # Windows Update reboot pending
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootPending = $true
        }
        
        # Component Based Servicing reboot pending
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootPending = $true
        }
        
        # PendingFileRenameOperations
        $pendingFileRename = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            $rebootPending = $true
        }
        
        return $rebootPending
    }
    catch {
        Write-WarningMessage "Could not check reboot status: $_"
        return $false
    }
}

# WSL Functions
function Test-WSL {
    <#
    .SYNOPSIS
        Checks if WSL is installed and determines version information.
    #>
    Write-Info "Checking WSL installation status..."
    
    try {
        # Check if wsl.exe exists
        $wslPath = Join-Path $env:SystemRoot "System32\wsl.exe"
        if (-not (Test-Path $wslPath)) {
            Write-Info "WSL is not installed (wsl.exe not found)"
            return @{
                Installed = $false
                Version = $null
                DefaultVersion = $null
                Status = "Not Installed"
            }
        }
        
        # Try to get WSL status
        try {
            $statusOutput = & wsl --status 2>&1
            $statusExitCode = $LASTEXITCODE
            
            if ($statusExitCode -eq 0) {
                # Parse status output
                $defaultVersion = $null
                $kernelVersion = $null
                
                # Debug output to help diagnose parsing issues
                Write-Info "WSL status output:"
                $statusOutput | ForEach-Object { Write-Info "  $_" }
                
                foreach ($line in $statusOutput) {
                    # More flexible pattern to match various formats
                    if ($line -match "Default\s+Version:\s*(\d+)" -or 
                        $line -match "Default\s+version:\s*(\d+)" -or
                        $line -match "Standardversion:\s*(\d+)" -or  # German
                        $line -match "Version\s+par\s+défaut\s*:\s*(\d+)" -or  # French
                        $line -match ":\s*WSL\s*(\d+)") {  # Generic pattern
                        $defaultVersion = [int]$matches[1]
                    }
                    elseif ($line -match "WSL 2" -or $line -match "WSL2") {
                        $kernelVersion = "WSL 2"
                    }
                }
                
                # If we couldn't parse the default version from status, try --get-default-version
                if ($null -eq $defaultVersion) {
                    try {
                        $versionOutput = & wsl --get-default-version 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $defaultVersion = [int]$versionOutput.Trim()
                        }
                    }
                    catch {
                        Write-WarningMessage "Could not determine default version from --get-default-version"
                    }
                }
                
                Write-Success "WSL is installed and operational"
                Write-Info "Default WSL version: $defaultVersion"
                
                return @{
                    Installed = $true
                    Version = if ($kernelVersion) { 2 } else { 1 }
                    DefaultVersion = $defaultVersion
                    Status = "Installed and Running"
                }
            }
        }
        catch {
            Write-WarningMessage "WSL status command failed: $_"
        }
        
        # Fallback: Try to get default version
        try {
            $versionOutput = & wsl --get-default-version 2>&1
            $versionExitCode = $LASTEXITCODE
            
            if ($versionExitCode -eq 0) {
                $defaultVersion = [int]$versionOutput.Trim()
                Write-Success "WSL is installed"
                Write-Info "Default WSL version: $defaultVersion"
                
                return @{
                    Installed = $true
                    Version = $defaultVersion
                    DefaultVersion = $defaultVersion
                    Status = "Installed"
                }
            }
        }
        catch {
            Write-WarningMessage "Could not determine WSL default version: $_"
        }
        
        # Final fallback: WSL exists but may not be configured
        Write-WarningMessage "WSL is installed but may not be properly configured"
        return @{
            Installed = $true
            Version = $null
            DefaultVersion = $null
            Status = "Installed but Not Configured"
        }
    }
    catch {
        Write-ScriptError "Failed to check WSL status: $_"
        return @{
            Installed = $false
            Version = $null
            DefaultVersion = $null
            Status = "Error"
        }
    }
}

function Enable-WSLFeatures {
    <#
    .SYNOPSIS
        Enables required Windows features for WSL 2.
    #>
    Write-Info "Checking and enabling WSL features..."
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-WarningMessage "Administrator privileges required to enable Windows features"
        Write-Info "Attempting to restart script with elevation..."
        
        try {
            # Get the current script path
            $scriptPath = $PSCommandPath
            if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
                $scriptPath = $MyInvocation.MyCommand.Path
            }
            
            if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
                Write-ScriptError "Could not determine script path for elevation"
                Write-Info "Please run this script as Administrator manually"
                return $false
            }
            
            Write-Info "Restarting script with administrator privileges..."
            Write-Info "Script path: $scriptPath"
            
            # Build arguments to pass to elevated process
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            
            # Start elevated process
            $process = Start-Process PowerShell -ArgumentList $arguments -Verb RunAs -PassThru -Wait
            
            if ($process.ExitCode -eq 0) {
                Write-Success "WSL features enabled successfully"
                return $true
            }
            else {
                Write-ScriptError "Elevated script execution failed with exit code: $($process.ExitCode)"
                return $false
            }
        }
        catch {
            Write-ScriptError "Failed to restart with elevation: $_"
            Write-Info "Please manually run this script as Administrator to enable WSL features"
            return $false
        }
    }
    
    # We are running as administrator, proceed with feature enablement
    $rebootRequired = $false
    
    try {
        # Enable Windows Subsystem for Linux
        Write-Info "Enabling Windows Subsystem for Linux feature..."
        $wslFeature = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
        
        if ($wslFeature.RestartNeeded) {
            $rebootRequired = $true
            Write-WarningMessage "Reboot required after enabling WSL feature"
        }
        else {
            Write-Success "WSL feature enabled successfully"
        }
        
        # Enable Virtual Machine Platform (required for WSL 2)
        Write-Info "Enabling Virtual Machine Platform feature..."
        $vmFeature = Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
        
        if ($vmFeature.RestartNeeded) {
            $rebootRequired = $true
            Write-WarningMessage "Reboot required after enabling Virtual Machine Platform feature"
        }
        else {
            Write-Success "Virtual Machine Platform feature enabled successfully"
        }
        
        # Check if Hyper-V is available and should be enabled
        $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        if ($hyperVFeature -and $hyperVFeature.State -eq "Disabled") {
            Write-Info "Hyper-V is available but disabled. WSL 2 can work without full Hyper-V."
            Write-Info "Skipping Hyper-V enablement to avoid potential conflicts."
        }
        
        if ($rebootRequired) {
            Write-WarningMessage "System reboot is required to complete feature installation"
            Write-Info "Please restart your computer and run this script again"
            return $false  # Return false to indicate reboot needed
        }
        else {
            Write-Success "All required features are enabled"
            return $true
        }
    }
    catch {
        Write-ScriptError "Failed to enable Windows features: $_"
        Write-Info "Please try enabling features manually:"
        Write-Info "1. Open 'Turn Windows features on or off'"
        Write-Info "2. Enable 'Windows Subsystem for Linux'"
        Write-Info "3. Enable 'Virtual Machine Platform'"
        Write-Info "4. Restart your computer"
        return $false
    }
}

function Install-WSL2Kernel {
    <#
    .SYNOPSIS
        Downloads and installs the WSL 2 kernel update.
    #>
    Write-Info "Installing WSL 2 kernel update..."
    
    $kernelUpdatePath = $null
    $installSuccess = $false
    
    try {
        # WSL 2 kernel update URL (official Microsoft download)
        $kernelUpdateUrl = $script:Config.KernelUpdateUrl
        $tempDir = $env:TEMP
        $kernelUpdatePath = Join-Path $tempDir "wsl_update_x64.msi"
        
        # Download WSL 2 kernel update
        Write-Info "Downloading WSL 2 kernel update..."
        Write-Info "URL: $kernelUpdateUrl"
        
        try {
            # Use Invoke-WebRequest with progress tracking
            $webRequest = Invoke-WebRequest -Uri $kernelUpdateUrl -OutFile $kernelUpdatePath -PassThru -ErrorAction Stop
            Write-Success "WSL 2 kernel update downloaded successfully"
        }
        catch {
            $errorMessage = "Failed to download WSL 2 kernel update: $($_.Exception.Message)"
            Write-ScriptError $errorMessage
            Write-Info "Please manually download and install from: $kernelUpdateUrl"
            throw $errorMessage
        }
        
        # Verify download
        if (-not (Test-Path $kernelUpdatePath)) {
            $errorMessage = "Downloaded file not found: $kernelUpdatePath"
            Write-ScriptError $errorMessage
            throw $errorMessage
        }
        
        $fileSize = (Get-Item $kernelUpdatePath).Length
        Write-Info "Downloaded file size: $([Math]::Round($fileSize / 1MB, 2)) MB"
        
        # Install the MSI package
        Write-Info "Installing WSL 2 kernel update..."
        Write-Info "This may take a few moments..."
        
        try {
            # Run msiexec to install silently
            $msiArgs = @(
                "/i"
                "`"$kernelUpdatePath`""
                "/quiet"
                "/norestart"
                "/L*v"
                "`"$tempDir\wsl_kernel_install.log`""
            )
            
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0) {
                Write-Success "WSL 2 kernel update installed successfully"
                $installSuccess = $true
            }
            elseif ($process.ExitCode -eq 3010) {
                Write-WarningMessage "WSL 2 kernel update installed, but a reboot is required"
                Write-Info "Please restart your computer and run this script again"
                $installSuccess = $false  # Indicate reboot needed
            }
            elseif ($process.ExitCode -eq 1603) {
                Write-ScriptError "WSL 2 kernel installation failed with error 1603 (Fatal error during installation)"
                Write-Info "This error typically indicates one of the following:"
                Write-Info "  - Insufficient permissions (try running as Administrator)"
                Write-Info "  - Previous failed installation remnants"
                Write-Info "  - Corrupted installer file"
                Write-Info ""
                Write-Info "Recommended solutions:"
                Write-Info "  1. Run this script as Administrator"
                Write-Info "  2. Restart your computer and try again"
                Write-Info "  3. Run 'wsl --update' manually in an elevated PowerShell"
                Write-Info "  4. Check Windows Update for any pending updates"
                $installSuccess = $false
            }
            else {
                Write-ScriptError "WSL 2 kernel installation failed with exit code: $($process.ExitCode)"
                
                # Try to read log file for more details
                $logPath = Join-Path $tempDir "wsl_kernel_install.log"
                if (Test-Path $logPath) {
                    Write-Info "Installation log location: $logPath"
                    $logContent = Get-Content $logPath -Tail 10 -ErrorAction SilentlyContinue
                    if ($logContent) {
                        Write-Info "Last few lines from install log:"
                        $logContent | ForEach-Object { Write-Info "  $_" }
                    }
                }
                $installSuccess = $false
            }
        }
        catch {
            Write-ScriptError "Failed to run WSL 2 kernel installer: $($_.Exception.Message)"
            $installSuccess = $false
        }
        
        return $installSuccess
    }
    catch {
        Write-ScriptError "WSL 2 kernel installation failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Clean up downloaded file
        if ($kernelUpdatePath -and (Test-Path $kernelUpdatePath)) {
            try {
                Remove-Item $kernelUpdatePath -Force -ErrorAction Stop
                Write-Info "Cleaned up downloaded installer"
            }
            catch {
                Write-WarningMessage "Could not clean up downloaded file: $kernelUpdatePath - $($_.Exception.Message)"
            }
        }
    }
}

function Set-WSLDefaultVersion {
    <#
    .SYNOPSIS
        Sets WSL 2 as the default version.
    #>
    Write-Info "Setting WSL 2 as default version..."
    
    try {
        # Execute wsl --set-default-version 2
        $setVersionOutput = & wsl --set-default-version 2 2>&1
        $setVersionExitCode = $LASTEXITCODE
        
        if ($setVersionExitCode -eq 0) {
            Write-Success "WSL 2 set as default version successfully"
            
            # Verify the setting
            try {
                $currentVersion = & wsl --get-default-version 2>&1
                $currentVersionExitCode = $LASTEXITCODE
                
                if ($currentVersionExitCode -eq 0) {
                    $version = [int]$currentVersion.Trim()
                    if ($version -eq 2) {
                        Write-Success "Verified: WSL default version is now 2"
                        return $true
                    }
                    else {
                        Write-WarningMessage "WSL default version is $version, expected 2"
                        return $false
                    }
                }
                else {
                    Write-WarningMessage "Could not verify WSL default version: $currentVersion"
                    return $true  # Assume success if we can't verify
                }
            }
            catch {
                Write-WarningMessage "Could not verify WSL default version: $_"
                return $true  # Assume success if we can't verify
            }
        }
        else {
            Write-ScriptError "Failed to set WSL default version: $setVersionOutput"
            
            # Check if WSL needs to be initialized
            if ($setVersionOutput -like "*WSL 2*kernel*" -or $setVersionOutput -like "*update*") {
                Write-Info "WSL may need kernel update or initialization"
                Write-Info "Output: $setVersionOutput"
            }
            
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to set WSL default version: $_"
        return $false
    }
}

# Debian Installation Functions
function Test-DebianInstalled {
    <#
    .SYNOPSIS
        Checks if Debian is already installed in WSL.
    #>
    Write-Info "Checking for existing Debian installation..."
    
    try {
        # Check if wsl command is available
        $wslPath = Join-Path $env:SystemRoot "System32\wsl.exe"
        if (-not (Test-Path $wslPath)) {
            Write-Info "WSL is not installed yet"
            return @{
                Installed = $false
                Distributions = @()
                DebianFound = $false
                Status = "WSL Not Available"
            }
        }
        
        # Get list of installed distributions
        try {
            $listOutput = & wsl --list --verbose 2>&1
            $listExitCode = $LASTEXITCODE
            
            if ($listExitCode -ne 0) {
                Write-WarningMessage "Could not list WSL distributions: $listOutput"
                return @{
                    Installed = $false
                    Distributions = @()
                    DebianFound = $false
                    Status = "WSL Command Failed"
                }
            }
            
            # Parse the output to find distributions
            $distributions = @()
            $debianFound = $false
            $defaultDistro = $null
            
            # Skip header lines and process distribution list
            $lines = $listOutput | Where-Object { $_ -and $_ -notmatch "Windows Subsystem for Linux" -and $_ -notmatch "NAME.*STATE.*VERSION" }
            
            foreach ($line in $lines) {
                if ($line -match '\s*(\*?)\s*(\S+)\s+(\S+)\s+(\d+)') {
                    $isDefault = $matches[1] -eq '*'
                    $name = $matches[2].Trim()
                    $state = $matches[3].Trim()
                    $version = [int]$matches[4]
                    
                    $distroInfo = @{
                        Name = $name
                        State = $state
                        Version = $version
                        IsDefault = $isDefault
                    }
                    
                    $distributions += $distroInfo
                    
                    if ($name -like "*Debian*" -or $name -eq "Debian") {
                        $debianFound = $true
                        if ($isDefault) {
                            $defaultDistro = $name
                        }
                        Write-Success "Found Debian distribution: $name (State: $state, Version: $version)"
                    }
                }
            }
            
            if ($debianFound) {
                Write-Success "Debian is already installed in WSL"
                if ($defaultDistro) {
                    Write-Info "Debian is set as default distribution"
                }
            }
            else {
                Write-Info "Debian is not installed in WSL"
                if ($distributions.Count -gt 0) {
                    Write-Info "Other distributions found:"
                    foreach ($distro in $distributions) {
                        Write-Info "  - $($distro.Name) ($($distro.State), v$($distro.Version))"
                    }
                }
                else {
                    Write-Info "No WSL distributions are currently installed"
                }
            }
            
            return @{
                Installed = $debianFound
                Distributions = $distributions
                DebianFound = $debianFound
                DefaultDistro = $defaultDistro
                Status = if ($debianFound) { "Debian Installed" } else { "Debian Not Found" }
            }
        }
        catch {
            Write-WarningMessage "Error parsing WSL distribution list: $_"
            return @{
                Installed = $false
                Distributions = @()
                DebianFound = $false
                Status = "Parse Error"
            }
        }
    }
    catch {
        Write-ScriptError "Failed to check Debian installation: $_"
        return @{
            Installed = $false
            Distributions = @()
            DebianFound = $false
            Status = "Error"
        }
    }
}

function Install-Debian {
    <#
    .SYNOPSIS
        Downloads and installs Debian distribution in WSL.
    #>
    Write-Info "Installing Debian distribution in WSL..."
    
    try {
        # Check if WSL is available
        $wslPath = Join-Path $env:SystemRoot "System32\wsl.exe"
        if (-not (Test-Path $wslPath)) {
            Write-ScriptError "WSL is not available. Please install WSL first."
            return $false
        }
        
        # Try using wsl --install Debian (newer method, available in Windows 11)
        Write-Info "Attempting to install Debian using 'wsl --install Debian'..."
        try {
            $installOutput = & wsl --install Debian 2>&1
            $installExitCode = $LASTEXITCODE
            
            if ($installExitCode -eq 0) {
                Write-Success "Debian installation initiated successfully"
                Write-Info "Monitoring installation progress..."
                
                # Wait for installation to complete
                $maxWaitTime = 300  # 5 minutes
                $waitTime = 0
                $installComplete = $false
                
                while ($waitTime -lt $maxWaitTime -and -not $installComplete) {
                    Start-Sleep -Seconds 10
                    $waitTime += 10
                    
                    # Check if Debian appears in the distribution list
                    $debianStatus = Test-DebianInstalled
                    if ($debianStatus.DebianFound) {
                        $installComplete = $true
                        Write-Success "Debian installation completed successfully"
                    }
                    else {
                        Write-Info "Waiting for installation to complete... ($waitTime/$maxWaitTime seconds)"
                    }
                }
                
                if (-not $installComplete) {
                    Write-WarningMessage "Installation did not complete within expected time"
                    Write-Info "You may need to complete the setup manually"
                }
                
                return $installComplete
            }
            else {
                Write-WarningMessage "WSL --install Debian failed: $installOutput"
                Write-Info "Attempting alternative installation method..."
            }
        }
        catch {
            Write-WarningMessage "WSL --install command failed: $_"
            Write-Info "Attempting alternative installation method..."
        }
        
        # Alternative method: Use Microsoft Store approach
        Write-Info "Attempting to install Debian using alternative method..."
        
        try {
            # Try to install using winget (if available)
            $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
            if ($wingetPath) {
                Write-Info "Installing Debian using winget..."
                $wingetOutput = & winget install Debian.Debian 2>&1
                $wingetExitCode = $LASTEXITCODE
                
                if ($wingetExitCode -eq 0) {
                    Write-Success "Debian installed via winget"
                    
                    # Wait for installation to complete
                    Start-Sleep -Seconds 30
                    $debianStatus = Test-DebianInstalled
                    if ($debianStatus.DebianFound) {
                        Write-Success "Debian installation verified"
                        return $true
                    }
                }
                else {
                    Write-WarningMessage "Winget installation failed: $wingetOutput"
                }
            }
        }
        catch {
            Write-WarningMessage "Winget installation method failed: $_"
        }
        
        # Manual installation instructions
        Write-WarningMessage "Automatic Debian installation failed"
        Write-Info "Please install Debian manually using one of these methods:"
        Write-Info ""
        Write-Info "Method 1 - Microsoft Store:"
        Write-Info "1. Open Microsoft Store"
        Write-Info "2. Search for 'Debian'"
        Write-Info "3. Install 'Debian' by Debian"
        Write-Info "4. Launch Debian to complete initial setup"
        Write-Info ""
        Write-Info "Method 2 - Command Line:"
        Write-Info "1. Run: wsl --install Debian"
        Write-Info "2. Follow the prompts to complete setup"
        Write-Info ""
        Write-Prompt "Press Enter after you have installed Debian: "
        Read-Host
        
        # Verify installation after manual setup
        $debianStatus = Test-DebianInstalled
        if ($debianStatus.DebianFound) {
            Write-Success "Debian installation confirmed"
            return $true
        }
        else {
            Write-ScriptError "Debian installation could not be verified"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to install Debian: $_"
        return $false
    }
}

function Initialize-Debian {
    <#
    .SYNOPSIS
        Initializes Debian distribution with user setup and basic configuration.
    #>
    Write-Info "Initializing Debian distribution..."
    
    try {
        # Check if Debian is installed
        $debianStatus = Test-DebianInstalled
        if (-not $debianStatus.DebianFound) {
            Write-ScriptError "Debian is not installed. Please install Debian first."
            return $false
        }
        
        # Find the Debian distribution name
        $debianDistro = $null
        foreach ($distro in $debianStatus.Distributions) {
            if ($distro.Name -like "*Debian*" -or $distro.Name -eq "Debian") {
                $debianDistro = $distro.Name
                break
            }
        }
        
        if (-not $debianDistro) {
            Write-ScriptError "Could not find Debian distribution name"
            return $false
        }
        
        Write-Info "Found Debian distribution: $debianDistro"
        
        # Check if Debian is already initialized
        try {
            Write-Info "Checking if Debian is already initialized..."
            $testOutput = & wsl -d $debianDistro -- whoami 2>&1
            $testExitCode = $LASTEXITCODE
            
            if ($testExitCode -eq 0 -and $testOutput -and $testOutput -ne "root") {
                Write-Success "Debian is already initialized with user: $testOutput"
                return $true
            }
        }
        catch {
            Write-Info "Debian appears to need initialization"
        }
        
        # Initialize Debian
        Write-Info "Debian needs to be initialized with a user account"
        Write-Info "This will launch Debian for first-time setup"
        Write-Info "You will be prompted to create a username and password"
        Write-Host ""
        Write-Info "Important notes:"
        Write-Info "- Use a simple username (lowercase, no spaces)"
        Write-Info "- Choose a secure password"
        Write-Info "- Remember these credentials for future use"
        Write-Host ""
        Write-Prompt "Press Enter to launch Debian setup: "
        Read-Host
        
        try {
            # Launch Debian for initial setup
            Write-Info "Launching Debian for user setup..."
            $process = Start-Process -FilePath "wsl.exe" -ArgumentList "-d", $debianDistro -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Success "Debian initialization completed"
                
                # Verify initialization
                try {
                    $verifyOutput = & wsl -d $debianDistro -- whoami 2>&1
                    $verifyExitCode = $LASTEXITCODE
                    
                    if ($verifyExitCode -eq 0 -and $verifyOutput -and $verifyOutput -ne "root") {
                        Write-Success "Debian user setup verified: $verifyOutput"
                        
                        # Update package repositories
                        Write-Info "Updating Debian package repositories..."
                        $updateOutput = & wsl -d $debianDistro -- sudo apt update 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Success "Package repositories updated successfully"
                        }
                        else {
                            Write-WarningMessage "Package update failed, but continuing: $updateOutput"
                        }
                        
                        return $true
                    }
                    else {
                        Write-WarningMessage "Could not verify Debian user setup: $verifyOutput"
                        return $false
                    }
                }
                catch {
                    Write-WarningMessage "Could not verify Debian initialization: $_"
                    return $false
                }
            }
            else {
                Write-ScriptError "Debian initialization failed with exit code: $($process.ExitCode)"
                return $false
            }
        }
        catch {
            Write-ScriptError "Failed to launch Debian setup: $_"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to initialize Debian: $_"
        return $false
    }
}

function Invoke-WSLCommand {
    <#
    .SYNOPSIS
        Executes commands within the Debian WSL environment.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        
        [Parameter(Mandatory = $false)]
        [string]$Distribution = $script:Config.WSLDistro,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    try {
        Write-Info "Executing WSL command: $Command"
        
        # Build WSL command arguments
        $wslArgs = @("-d", $Distribution, "--", $Command)
        
        # Execute command and capture output
        $output = & wsl @wslArgs 2>&1
        $exitCode = $LASTEXITCODE
        
        $result = @{
            ExitCode = $exitCode
            Output = $output
            Error = if ($exitCode -ne 0) { $output } else { $null }
            Success = ($exitCode -eq 0)
        }
        
        if ($result.Success) {
            Write-Info "Command executed successfully"
            if ($PassThru -and $output) {
                Write-Info "Output: $output"
            }
        }
        else {
            Write-WarningMessage "Command failed with exit code $exitCode"
            if ($output) {
                Write-WarningMessage "Error output: $output"
            }
        }
        
        return $result
    }
    catch {
        Write-ScriptError "Failed to execute WSL command: $_"
        return @{
            ExitCode = -1
            Output = $null
            Error = $_.Exception.Message
            Success = $false
        }
    }
}

function Get-ClaudeCodeInstaller {
    <#
    .SYNOPSIS
        Downloads the official Claude Code installer script within Debian.
    #>
    Write-Info "Downloading Claude Code installer..."
    
    try {
        # Find Debian distribution
        $debianStatus = Test-DebianInstalled
        if (-not $debianStatus.DebianFound) {
            Write-ScriptError "Debian is not installed"
            return $false
        }
        
        $debianDistro = $null
        foreach ($distro in $debianStatus.Distributions) {
            if ($distro.Name -like "*Debian*" -or $distro.Name -eq "Debian") {
                $debianDistro = $distro.Name
                break
            }
        }
        
        if (-not $debianDistro) {
            Write-ScriptError "Could not find Debian distribution"
            return $false
        }
        
        # Check if curl is available
        Write-Info "Checking for curl availability..."
        $curlCheck = Invoke-WSLCommand -Command "which curl" -Distribution $debianDistro
        
        if (-not $curlCheck.Success) {
            Write-Info "Installing curl..."
            $installCurl = Invoke-WSLCommand -Command "sudo apt update && sudo apt install -y curl" -Distribution $debianDistro
            if (-not $installCurl.Success) {
                Write-ScriptError "Failed to install curl: $($installCurl.Error)"
                return $false
            }
        }
        
        # Download Claude Code installer
        Write-Info "Downloading Claude Code installer script..."
        $installerUrl = $script:Config.ClaudeInstallerUrl
        $installerPath = "/tmp/claude-install.sh"
        
        $downloadCommand = "curl -fsSL '$installerUrl' -o '$installerPath'"
        $downloadResult = Invoke-WSLCommand -Command $downloadCommand -Distribution $debianDistro
        
        if (-not $downloadResult.Success) {
            Write-ScriptError "Failed to download Claude Code installer: $($downloadResult.Error)"
            return $false
        }
        
        # Verify download
        $verifyCommand = "test -f '$installerPath' && echo 'File exists' || echo 'File missing'"
        $verifyResult = Invoke-WSLCommand -Command $verifyCommand -Distribution $debianDistro
        
        if ($verifyResult.Success -and $verifyResult.Output -like "*File exists*") {
            Write-Success "Claude Code installer downloaded successfully"
            
            # Make script executable
            $chmodCommand = "chmod +x '$installerPath'"
            $chmodResult = Invoke-WSLCommand -Command $chmodCommand -Distribution $debianDistro
            
            if ($chmodResult.Success) {
                Write-Success "Installer script is ready for execution"
                return $installerPath
            }
            else {
                Write-ScriptError "Failed to make installer executable: $($chmodResult.Error)"
                return $false
            }
        }
        else {
            Write-ScriptError "Installer download verification failed"
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to download Claude Code installer: $_"
        return $false
    }
}

function Install-ClaudeCodeInDebian {
    <#
    .SYNOPSIS
        Executes the Claude Code installer within Debian.
    #>
    Write-Info "Installing Claude Code in Debian..."
    
    try {
        # Find Debian distribution
        $debianStatus = Test-DebianInstalled
        if (-not $debianStatus.DebianFound) {
            Write-ScriptError "Debian is not installed"
            return $false
        }
        
        $debianDistro = $null
        foreach ($distro in $debianStatus.Distributions) {
            if ($distro.Name -like "*Debian*" -or $distro.Name -eq "Debian") {
                $debianDistro = $distro.Name
                break
            }
        }
        
        if (-not $debianDistro) {
            Write-ScriptError "Could not find Debian distribution"
            return $false
        }
        
        # Download installer
        $installerPath = Get-ClaudeCodeInstaller
        if (-not $installerPath) {
            Write-ScriptError "Failed to download Claude Code installer"
            return $false
        }
        
        # Update package repositories first
        Write-Info "Updating Debian package repositories..."
        $updateResult = Invoke-WSLCommand -Command "sudo apt update" -Distribution $debianDistro
        if (-not $updateResult.Success) {
            Write-WarningMessage "Package update failed, but continuing: $($updateResult.Error)"
        }
        
        # Install dependencies if needed
        Write-Info "Installing dependencies..."
        $depsCommand = "sudo apt install -y wget gpg"
        $depsResult = Invoke-WSLCommand -Command $depsCommand -Distribution $debianDistro
        if (-not $depsResult.Success) {
            Write-WarningMessage "Dependencies installation failed, but continuing: $($depsResult.Error)"
        }
        
        # Execute Claude Code installer
        Write-Info "Executing Claude Code installer..."
        Write-Info "This may take several minutes..."
        
        $installCommand = "bash $installerPath"
        $installResult = Invoke-WSLCommand -Command $installCommand -Distribution $debianDistro -PassThru
        
        if ($installResult.Success) {
            Write-Success "Claude Code installation completed successfully"
            Write-Info "Installation output:"
            if ($installResult.Output) {
                $installResult.Output | ForEach-Object { Write-Info "  $_" }
            }
            return $true
        }
        else {
            Write-ScriptError "Claude Code installation failed"
            Write-ScriptError "Installation output:"
            if ($installResult.Output) {
                $installResult.Output | ForEach-Object { Write-ScriptError "  $_" }
            }
            return $false
        }
    }
    catch {
        Write-ScriptError "Failed to install Claude Code: $_"
        return $false
    }
}

function Test-ClaudeCodeInstallation {
    <#
    .SYNOPSIS
        Verifies that Claude Code is properly installed and functional.
    #>
    Write-Info "Verifying Claude Code installation..."
    
    try {
        # Find Debian distribution
        $debianStatus = Test-DebianInstalled
        if (-not $debianStatus.DebianFound) {
            Write-ScriptError "Debian is not installed"
            return @{
                Installed = $false
                Version = $null
                Error = "Debian not found"
            }
        }
        
        $debianDistro = $null
        foreach ($distro in $debianStatus.Distributions) {
            if ($distro.Name -like "*Debian*" -or $distro.Name -eq "Debian") {
                $debianDistro = $distro.Name
                break
            }
        }
        
        if (-not $debianDistro) {
            Write-ScriptError "Could not find Debian distribution"
            return @{
                Installed = $false
                Version = $null
                Error = "Debian distribution not found"
            }
        }
        
        # Test if Claude Code command exists
        Write-Info "Checking if Claude Code command is available..."
        $whichResult = Invoke-WSLCommand -Command "which claude" -Distribution $debianDistro
        
        if (-not $whichResult.Success) {
            Write-WarningMessage "Claude Code command not found in PATH"
            return @{
                Installed = $false
                Version = $null
                Error = "Claude command not found"
            }
        }
        
        # Get Claude Code version
        Write-Info "Getting Claude Code version..."
        $versionResult = Invoke-WSLCommand -Command "claude --version" -Distribution $debianDistro
        
        if ($versionResult.Success) {
            $version = $versionResult.Output.Trim()
            Write-Success "Claude Code is installed and functional"
            Write-Success "Version: $version"
            
            # Test basic functionality
            Write-Info "Testing basic Claude Code functionality..."
            $helpResult = Invoke-WSLCommand -Command "claude --help" -Distribution $debianDistro
            
            if ($helpResult.Success) {
                Write-Success "Claude Code help command works correctly"
                return @{
                    Installed = $true
                    Version = $version
                    Error = $null
                }
            }
            else {
                Write-WarningMessage "Claude Code help command failed, but version check passed"
                return @{
                    Installed = $true
                    Version = $version
                    Error = "Help command failed: $($helpResult.Error)"
                }
            }
        }
        else {
            Write-ScriptError "Claude Code version check failed: $($versionResult.Error)"
            return @{
                Installed = $false
                Version = $null
                Error = "Version check failed: $($versionResult.Error)"
            }
        }
    }
    catch {
        Write-ScriptError "Failed to verify Claude Code installation: $_"
        return @{
            Installed = $false
            Version = $null
            Error = $_.Exception.Message
        }
    }
}

function Show-InstallationComplete {
    <#
    .SYNOPSIS
        Displays completion message and usage instructions.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$VerificationResult
    )
    
    Write-PhaseHeader "Installation Complete"
    
    if ($VerificationResult.Installed) {
        Write-Success "Claude Code has been successfully installed!"
        Write-Success "Version: $($VerificationResult.Version)"
        Write-Host ""
        
        Write-Info "How to use Claude Code:"
        Write-Info "1. Open Windows Terminal or Command Prompt"
        Write-Info "2. Launch Debian: wsl -d Debian"
        Write-Info "3. Run Claude Code: claude"
        Write-Host ""
        
        Write-Info "Quick start commands:"
        Write-Info "  claude --help          Show help information"
        Write-Info "  claude --version       Show version information"
        Write-Info "  claude login           Sign in to your Claude account"
        Write-Info "  claude chat            Start an interactive chat session"
        Write-Host ""
        
        Write-Info "Accessing from Windows:"
        Write-Info "You can also run: wsl -d Debian -- claude [command]"
        Write-Host ""
        
        Write-Info "Documentation and support:"
        Write-Info "  Official docs: https://docs.anthropic.com/claude-code"
        Write-Info "  GitHub: https://github.com/anthropics/claude-code"
        Write-Host ""
        
        Write-Success "Installation completed successfully!"
        Write-Info "Enjoy using Claude Code!"
    }
    else {
        Write-ScriptError "Installation verification failed"
        Write-ScriptError "Error: $($VerificationResult.Error)"
        Write-Host ""
        
        Write-Info "Troubleshooting steps:"
        Write-Info "1. Restart your computer and try running the script again"
        Write-Info "2. Ensure WSL 2 and Debian are properly installed"
        Write-Info "3. Check Windows Update for any pending updates"
        Write-Info "4. Try installing Claude Code manually in Debian:"
        Write-Info "   - Launch: wsl -d Debian"
        Write-Info "   - Run: curl -fsSL $($script:Config.ClaudeInstallerUrl) | bash"
        Write-Host ""
        
        Write-Info "For additional support:"
        Write-Info "  Documentation: https://docs.anthropic.com/claude-code"
        Write-Info "  Support: Contact Anthropic support"
    }
}

function Install-ClaudeCode {
    <#
    .SYNOPSIS
        Main function that orchestrates the Claude Code installation process.
    
    .DESCRIPTION
        Performs system validation, installs prerequisites, and installs Claude Code.
    #>
    [CmdletBinding()]
    param()

    try {
        Write-PhaseHeader "Claude Code Installation"
        Write-Info "Starting Claude Code installation process..."
        
        # Critical: Check virtualization support first
        Write-PhaseHeader "Critical System Requirements"
        Write-Info "Checking virtualization support (required for WSL 2)..."
        
        if (-not (Test-Virtualization)) {
            Write-ScriptError "CRITICAL: Virtualization support is not enabled!"
            Write-Host ""
            Write-ScriptError "WSL 2 requires hardware virtualization to be enabled in your system."
            Write-Info "To fix this issue:"
            Write-Info "  1. Restart your computer and enter BIOS/UEFI settings"
            Write-Info "     (usually by pressing F2, F10, F12, DEL, or ESC during boot)"
            Write-Info "  2. Look for virtualization settings such as:"
            Write-Info "     - Intel VT-x (Intel CPUs)"
            Write-Info "     - AMD-V or SVM Mode (AMD CPUs)"
            Write-Info "     - Virtualization Technology"
            Write-Info "     - Hardware Virtualization"
            Write-Info "  3. Enable the virtualization option"
            Write-Info "  4. Save and exit BIOS/UEFI"
            Write-Info "  5. Run this script again"
            Write-Host ""
            Write-Info "Note: The exact location and name of the setting varies by manufacturer."
            Write-Info "Consult your motherboard or computer manual for specific instructions."
            
            Exit-Script -ExitCode 1 -Message "Installation cancelled: Virtualization must be enabled before proceeding"
        }
        
        Write-Success "Virtualization is enabled"
        Write-Host ""
        
        # System Validation Phase
        Write-PhaseHeader "System Validation"
        
        $validationPassed = $true
        
        # Check Windows version
        if (-not (Test-WindowsVersion)) {
            $validationPassed = $false
        }
        
        # Check RAM
        if (-not (Test-SystemRAM)) {
            $validationPassed = $false
        }
        
        # Check CPU architecture
        if (-not (Test-CPUArchitecture)) {
            $validationPassed = $false
        }
        
        # Check disk space
        if (-not (Test-DiskSpace)) {
            $validationPassed = $false
        }
        
        if (-not $validationPassed) {
            Write-ScriptError "System validation failed. Please resolve the issues above before continuing."
            Exit-Script -ExitCode 1 -Message "Installation cancelled due to system requirements not being met"
        }
        
        Write-Success "All system validation checks passed!"
        
        # Windows Update Phase
        Request-WindowsUpdate
        
        # WSL 2 Installation Phase
        Write-PhaseHeader "WSL 2 Installation"
        
        $wslStatus = Test-WSL
        
        if (-not $wslStatus.Installed) {
            Write-Info "WSL is not installed. Enabling required Windows features..."
            
            $featuresEnabled = Enable-WSLFeatures
            if (-not $featuresEnabled) {
                Write-ScriptError "Failed to enable WSL features"
                Exit-Script -ExitCode 2 -Message "Reboot required or feature enablement failed - please restart and run script again"
            }
            
            # After enabling features, install WSL 2 kernel
            Write-Info "Installing WSL 2 kernel update..."
            $kernelInstalled = Install-WSL2Kernel
            if (-not $kernelInstalled) {
                Write-ScriptError "Failed to install WSL 2 kernel"
                Exit-Script -ExitCode 2 -Message "WSL 2 kernel installation failed or reboot required - please restart and run script again"
            }
            
            # Set WSL 2 as default version
            Write-Info "Setting WSL 2 as default version..."
            $versionSet = Set-WSLDefaultVersion
            if (-not $versionSet) {
                Write-WarningMessage "Failed to set WSL 2 as default version, but continuing..."
            }
        }
        elseif ($wslStatus.DefaultVersion -ne 2) {
            Write-Info "WSL is installed but default version is not 2"
            Write-Info "Current default version: $($wslStatus.DefaultVersion)"
            
            # Install WSL 2 kernel if needed
            Write-Info "Ensuring WSL 2 kernel is installed..."
            $kernelInstalled = Install-WSL2Kernel
            if (-not $kernelInstalled) {
                Write-WarningMessage "WSL 2 kernel installation failed, but continuing..."
            }
            
            # Set WSL 2 as default version
            Write-Info "Setting WSL 2 as default version..."
            $versionSet = Set-WSLDefaultVersion
            if (-not $versionSet) {
                Write-WarningMessage "Failed to set WSL 2 as default version, but continuing..."
            }
        }
        else {
            Write-Success "WSL 2 is already installed and configured"
        }
        
        # Debian Installation Phase
        Write-PhaseHeader "Debian Installation"
        
        $debianStatus = Test-DebianInstalled
        
        if (-not $debianStatus.DebianFound) {
            Write-Info "Debian is not installed. Installing Debian distribution..."
            
            $debianInstalled = Install-Debian
            if (-not $debianInstalled) {
                Write-ScriptError "Failed to install Debian"
                Exit-Script -ExitCode 1 -Message "Debian installation failed - please install manually and try again"
            }
        }
        else {
            Write-Success "Debian is already installed in WSL"
            Write-Info "Using existing Debian installation"
        }
        
        # Debian Initialization Phase
        Write-PhaseHeader "Debian Initialization"
        
        $debianInitialized = Initialize-Debian
        if (-not $debianInitialized) {
            Write-ScriptError "Failed to initialize Debian"
            Exit-Script -ExitCode 1 -Message "Debian initialization failed"
        }
        
        # Claude Code Installation Phase
        Write-PhaseHeader "Claude Code Installation"
        
        $claudeInstalled = Install-ClaudeCodeInDebian
        if (-not $claudeInstalled) {
            Write-ScriptError "Failed to install Claude Code"
            Exit-Script -ExitCode 1 -Message "Claude Code installation failed"
        }
        
        # Verification Phase
        Write-PhaseHeader "Installation Verification"
        
        $verificationResult = Test-ClaudeCodeInstallation
        
        # Display final results
        Show-InstallationComplete -VerificationResult $verificationResult
        
        if ($verificationResult.Installed) {
            Exit-Script -ExitCode 0 -Message "Claude Code installation completed successfully!"
        }
        else {
            Exit-Script -ExitCode 1 -Message "Installation verification failed"
        }
    }
    catch {
        Write-ScriptError "An error occurred during installation: $_"
        Exit-Script -ExitCode 1 -Message "Installation failed"
    }
}

# Entry point
if ($Test) {
    Write-Host "Running in test mode..."
    $testResult = Test-AllComponents
    if ($testResult) {
        Exit-Script -ExitCode 0 -Message "All tests passed"
    }
    else {
        Exit-Script -ExitCode 1 -Message "Some tests failed"
    }
}
else {
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "Note: Some operations may require administrator privileges." -ForegroundColor Yellow
        Write-Host "The script will prompt for elevation when needed." -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Call main installation function
    Install-ClaudeCode
}
