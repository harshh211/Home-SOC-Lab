# Windows Endpoint Logging Configuration
# Run as Administrator on the target Windows VM
# Enables the logging telemetry required for all detections in this lab

# ============================================================
# 1. Process Creation Auditing
# Generates Event ID 4688 for every new process started
# ============================================================
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# ============================================================
# 2. Command-Line Argument Capture
# Without this, 4688 logs the process name but NOT the arguments
# e.g. you'd see powershell.exe but not what command it ran
# ============================================================
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# ============================================================
# 3. Logon & Account Lockout Auditing
# Generates Event ID 4625 for failed logons (brute-force detection)
# ============================================================
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# ============================================================
# 4. PowerShell Script Block Logging
# Logs every PowerShell command BEFORE execution, including the
# decoded version of any Base64-encoded or obfuscated commands
# ============================================================
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# ============================================================
# 5. PowerShell Module Logging
# Logs every cmdlet executed
# ============================================================
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -Value 1 -Type DWord

# ============================================================
# 6. Allow ICMP (ping) for network diagnostics
# ============================================================
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow

# ============================================================
# 7. Enable RDP and allow through firewall
# ============================================================
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# ============================================================
# Verify settings applied correctly
# ============================================================
Write-Host "`n=== Audit Policy Verification ===" -ForegroundColor Green
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"Logon"

Write-Host "`n=== Command-Line Capture ===" -ForegroundColor Green
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled"

Write-Host "`n=== Script Block Logging ===" -ForegroundColor Green
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging"

Write-Host "`n=== RDP Status ===" -ForegroundColor Green
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name "fDenyTSConnections"
