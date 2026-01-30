<#
.SYNOPSIS
    Demonstrates a simple "Single Hop" PowerShell Remoting execution.
    Based on patterns in the repository.

.DESCRIPTION
    This script connects directly to a target computer and executes a command (Get-ComputerInfo).
    It mimics the direct connection style used in the first step of multi-hop workflows.

.PARAMETER TargetComputer
    The hostname or IP of the target server.

.PARAMETER Credential
    The credentials to use for the connection.

.EXAMPLE
    .\Demo-SingleHop.ps1 -TargetComputer "Server01" -Credential (Get-Credential)
#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,

    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$Credential
)

Write-Host "Starting Single Hop Demo..." -ForegroundColor Cyan
Write-Host "Connecting to $TargetComputer..."

try {
    # 1. Create the session (mimicking Get-Session logic from the repo)
    # in a real scenario, we might handle TrustedHosts here, but for simplicity:
    $session = New-PSSession -ComputerName $TargetComputer -Credential $Credential -ErrorAction Stop

    Write-Host "Session created successfully." -ForegroundColor Green

    # 2. Execute a command on the remote target
    # This is the 'Single Hop' - we are executing code directly on the target from our machine.
    $result = Invoke-Command -Session $session -ScriptBlock {
        $hostname = $env:COMPUTERNAME
        $os = (Get-CimInstance Win32_OperatingSystem).Caption
        return "Hello from $hostname running $os"
    }

    Write-Host "Result from Remote Server:" -ForegroundColor Yellow
    Write-Host $result

}
catch {
    Write-Host "Error occurred: $_" -ForegroundColor Red
}
finally {
    if ($session) {
        Remove-PSSession $session
        Write-Host "Session removed." -ForegroundColor Gray
    }
}
