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
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        # Only call Get-Credential if no credential was provided
        if ($null -eq $Credential) {
            $Credential = Get-Credential
        }
        if ($null -eq $Credential -or $retryCount -ge $maxRetries) {
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

<#
function Get-Session {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [scriptblock]$SetTrustedHosts = { param($server) Set-Item WSMan:\localhost\Client\TrustedHosts -Value $server -Concatenate -Force },
        [scriptblock]$CreateSession = { param($server, $cred) New-PSSession -ComputerName $server -Credential $cred -ErrorAction Stop }
    )

    $retryCount = 0
    $success = $false
    $session = $null

    while ($retryCount -lt $MaxRetries -and -not $success) {
        # Use provided credential or prompt if none given
        $effectiveCredential = $Credential
        if ($null -eq $effectiveCredential) {
            $effectiveCredential = Get-Credential -Message "Enter credentials for $ServerName (Attempt $($retryCount + 1) of $MaxRetries)"
            if ($null -eq $effectiveCredential) {
                return $null # User canceled the prompt
            }
        }

        try {
            $null = & $SetTrustedHosts -server $ServerName
            $session = & $CreateSession -server $ServerName -cred $effectiveCredential
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                return $null
            }
            # If credential was provided explicitly, don’t retry with a prompt
            if ($Credential) {
                return $null
            }
        }
    }

    return $session
}#>