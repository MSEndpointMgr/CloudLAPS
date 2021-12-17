<#
.SYNOPSIS
    Proaction Remediation script for CloudLAPS solution used within Endpoint Analytics with Microsoft Endpoint Manager to rotate a local administrator password.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used by the CloudLAPS solution.
    
    It will create an event log named CloudLAPS-Client if it doesn't already exist and ensure the remediation script is always triggered.

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-09-14
    Updated:     2020-09-14

    Version history:
    1.0.0 - (2020-09-14) Script created
    1.0.1 - (2021-12-17) Add delay
#>
Process {
    # Delay for Detection
    $Delay = 30

    # Create new event log if it doesn't already exist
    $EventLogName = "CloudLAPS-Client"
    $EventLogSource = "CloudLAPS-Client"
    $CloudLAPSEventLog = Get-WinEvent -LogName $EventLogName -ErrorAction SilentlyContinue
    if ($CloudLAPSEventLog -eq $null) {
        try {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Failed to create new event log. Error message: $($_.Exception.Message)"
        }
    }
    if((Get-EventLog -LogName $EventLogName -InstanceId 40)[0].TimeGenerated -ge (Get-Date).AddDays($Delay)){
        exit 1
    }

    # Trigger remediation script
    exit 0
}