# module.ps1

# Function to write message to user about script execution
<#function Write-Message {
    param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    # Create temp directory if not exists
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp"
    }

    $message | Out-File "C:\temp\script_status.txt" -Force
}#>

# Function to prompt for server name and check availability
function Test-ServerAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [string]$serverName
    )
    return (Test-Connection -ComputerName $serverName -Count 1 -Quiet)
}


# Function to attempt to create a session and handle credential failures
function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        $credential = Get-Credential
        if ($null -eq $credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            if ($retryCount -ge $maxRetries) {
                return $null
            }
        }
    } while ($true)
}