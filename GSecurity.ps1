<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, and keyloggers. 
                 Protects critical system processes and specific trusted drivers from termination.
    Version: 1.3
    License: Free for personal use
#>

# Logging utility
function Write-Log {
    param ([string]$Message)
    $logFile = "$env:USERPROFILE\Documents\GSecurity.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $Message"
}

# Path to EmptyStandbyList executable
$rammapPath = "C:\Windows\GShield\EmptyStandbyList.exe"

# Whitelist of critical system processes to protect
$protectedProcesses = @(
    "System",
    "smss",       # Session Manager Subsystem
    "csrss",      # Client/Server Runtime
    "wininit",    # Windows Initialization Process
    "services",   # Service Control Manager
    "lsass",      # Local Security Authority
    "svchost",    # Generic Host Process for Services
    "dwm",        # Desktop Window Manager
    "explorer",   # File Explorer and Desktop
    "taskhostw",  # Task Host Window
    "winlogon",   # Windows Logon Process
    "conhost",    # Console Window Host
    "cmd",        # Command Prompt
    "powershell"  # PowerShell itself
)

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*",  # Microsoft drivers
    "*NVIDIA*",     # NVIDIA GPU drivers
    "*Intel*",      # Intel drivers
    "*AMD*",        # AMD GPU and CPU drivers
    "*Realtek*"     # Realtek audio/network drivers
)

# Detect and terminate web servers
function Detect-And-Terminate-WebServers {
    $ports = @(80, 443, 8080) # Common web server ports
    $connections = Get-NetTCPConnection | Where-Object { $ports -contains $_.LocalPort }
    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Web server detected: $($process.ProcessName) (PID: $($process.Id)) on Port $($connection.LocalPort)"
            Stop-Process -Id $process.Id -Force
            Write-Log "Web server process terminated: $($process.ProcessName)"
        }
    }
}

# Terminate suspicious web server services
function Detect-And-Terminate-WebServerServices {
    $webServices = @("w3svc", "apache2", "nginx") # Known web server services
    foreach ($serviceName in $webServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Log "Web server service detected: $($serviceName)"
            Stop-Service -Name $serviceName -Force
            Write-Log "Web server service stopped: $($serviceName)"
        }
    }
}

# Detect and terminate screen overlays
function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object {
        $_.MainWindowTitle -ne "" -and 
        (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Log "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Log "Overlay process terminated: $($process.ProcessName)"
    }
}

# Detect and terminate keyloggers
function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Log "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

# Detect and terminate untrusted drivers
function Detect-And-Terminate-SuspiciousDrivers {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {
        ($_.DisplayName -notlike $trustedDriverVendors) -and $_.Started -eq $true
    }
    foreach ($driver in $drivers) {
        Write-Log "Suspicious driver detected: $($driver.DisplayName)"
        Stop-Service -Name $driver.Name -Force
        Write-Log "Suspicious driver stopped: $($driver.DisplayName)"
    }
}

# Clear Standby List and Working Sets
function Clear-Memory {
    Start-Process -FilePath $rammapPath -ArgumentList "standbylist" -NoNewWindow -Wait
    Start-Process -FilePath $rammapPath -ArgumentList "workingsets" -NoNewWindow -Wait
    Write-Log "Memory cleared (standby list and working sets)."
}

# Block Remote Services and Disable Unwanted Features
function Block-Remote-Services {
    # Prevent Remote Desktop Protocol (RDP)
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    Stop-Service -Name "TermService" -Force
    Set-Service -Name "TermService" -StartupType Disabled
    Write-Log "RDP disabled."

    # Disable Remote Assistance
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    Write-Log "Remote Assistance disabled."

    # Block PowerShell Remoting
    Disable-PSRemoting -Force
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
    Write-Log "PowerShell Remoting disabled."

    # Disable Telnet (if enabled)
    Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart
    Write-Log "Telnet disabled."

    # Block SMB (File Sharing)
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
    Write-Log "SMB blocked."

    # Disable Wake-on-LAN (WOL)
    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled"
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled"
    }
    Write-Log "Wake-on-LAN disabled."

    # Block SSH (if OpenSSH Server is installed)
    Stop-Service -Name "sshd" -Force
    Set-Service -Name "sshd" -StartupType Disabled
    Write-Log "SSH blocked."

    # Block VNC Services (if installed)
    Get-Service -Name "*VNC*" | ForEach-Object {
        Stop-Service -Name $_.Name -Force
        Set-Service -Name $_.Name -StartupType Disabled
    }
    Write-Log "VNC blocked."

    # Enforce Firewall Rules
    New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block SMB TCP 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block SMB TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block SMB UDP 137-138" -Direction Inbound -LocalPort 137-138 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
    Write-Log "Firewall rules enforced."

    # Disable UPnP
    Get-Service -Name "SSDPSRV", "upnphost" | ForEach-Object {
        Stop-Service -Name $_.Name -Force
        Set-Service -Name $_.Name -StartupType Disabled
    }
    Write-Log "UPnP disabled."

    # Disable Remote Assistance firewall rule
    Get-NetFirewallRule -DisplayName "Remote Assistance*" | Disable-NetFirewallRule
    Write-Log "Remote Assistance firewall rule disabled."
}

# Main monitoring loop
function Start-GSecurity {
    Write-Log "GSecurity started."
    while ($true) {
        try {
            # Detect and mitigate threats
            Detect-And-Terminate-WebServers
            Detect-And-Terminate-WebServerServices
            Detect-And-Terminate-Overlays
            Detect-And-Terminate-Keyloggers
            Detect-And-Terminate-SuspiciousDrivers
            Block-Remote-Services
            Clear-Memory

            Start-Sleep -Seconds 10 # Adjust as needed
        } catch {
            Write-Log "Error occurred: $($_.Exception.Message)"
        }
    }
}

# Start monitoring in the background
Start-Job -ScriptBlock {
    Start-GSecurity
}
Write-Log "GSecurity initialized and running."
