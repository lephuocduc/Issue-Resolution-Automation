function Write-WindowsEventLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogName,
        
        [Parameter(Mandatory=$true)]
        [string]$Source,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(0,65535)]
        [int]$EventID,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Information','Warning','Error')]
        [string]$EntryType,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    # Define the remote script block with verification
    $scriptBlock = {
        param ($LogName, $Source, $EventID, $EntryType, $Message)

        $result = @{
            Success = $false
            Error = $null
        }

        try {
            # Handle source existence
            $exists = @(Get-EventLog -LogName $LogName -Source $Source -Newest 1 -ErrorAction SilentlyContinue).Count -gt 0
            if (-not $exists) {
                try {
                    New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop
                }
                catch {
                    $result.Error = "Failed to create event source '$Source' in log '$LogName': $_"
                    return $result
                }
            }

            # Get timestamp before writing for verification
            $timeBeforeWrite = Get-Date -Format "dd-MMM-yy h:mm:ss tt"

            # Write event
            Write-EventLog -LogName $LogName -Source $Source -EventId $EventID -EntryType $EntryType -Message $Message

            # Verify the event was written
            Start-Sleep -Milliseconds 500  # Allow time for event to be written
            $newEvent = @(Get-EventLog -LogName $LogName -Source $Source -Newest 1 |
                Where-Object { 
                    $_.TimeGenerated -ge $timeBeforeWrite -and 
                    $_.EventID -eq $EventID -and 
                    $_.EntryType -eq $EntryType
                }).Count -gt 0

            if ($newEvent) {
                $result.Success = $true
            } else {
                $result.Error = "Event log entry not found after writing"
            }
        }
        catch {
            $result.Error = "Failed to write/verify event to log '$LogName' with source '$Source': $_"
        }

        return $result
    }

    # Invoke the script block remotely and get the result
    $result = Invoke-Command -Session $Session -ScriptBlock $scriptBlock -ArgumentList $LogName, $Source, $EventID, $EntryType, $Message

    if (-not $result.Success) {
        Write-Host "Error writing event log entry: $($result.Error)"
    }
}