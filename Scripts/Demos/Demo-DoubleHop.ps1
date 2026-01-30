<#
.SYNOPSIS
    Demonstrates "Double Hop" PowerShell Remoting via Explicit Credential Passing.
    Based on the architecture of Scripts/LowFreeSpace/LowFreeSpace.ps1.

.DESCRIPTION
    This script performs a nested remote execution:
    Client -> JumpHost -> TargetComputer
    
    It solves the "Double Hop" authentication issue by explicitly passing the 
    PSCredential object into the remote session, allowing the JumpHost to 
    authenticate to the TargetComputer.

.PARAMETER JumpHost
    The intermediate server (first hop).

.PARAMETER TargetComputer
    The final destination server (second hop).

.PARAMETER Credential
    The credentials to use for BOTH connections (assumed same account).

.EXAMPLE
    .\Demo-DoubleHop.ps1 -JumpHost "JumpBox01" -TargetComputer "BackendDb01" -Credential (Get-Credential)
#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$JumpHost,

    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,

    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$Credential
)

Write-Host "Starting Double Hop Demo (Credential Passing)..." -ForegroundColor Cyan
Write-Host "Step 1: Connecting to JumpHost: $JumpHost..."

try {
    # STEP 1: Connect to the First Hop (JumpHost)
    $jumpSession = New-PSSession -ComputerName $JumpHost -Credential $Credential -ErrorAction Stop
    Write-Host " -> Connected to JumpHost." -ForegroundColor Green

    # Define the scriptblock that will run ON THE JUMPHOST.
    # We pass the final target and the credentials TO this block.
    $remoteScriptBlock = {
        param($Target, $Creds)

        Write-Host "[JumpHost] Received request to connect to $Target"
        
        # This is running ON the JumpHost.
        # We now use the PASSED credentials to create a nested session to the final target.
        try {
            # Mimic Get-Session / New-PSSession on the JumpHost
            $finalSession = New-PSSession -ComputerName $Target -Credential $Creds -ErrorAction Stop
            
            # Execute command on the final target
            $output = Invoke-Command -Session $finalSession -ScriptBlock {
                $hostname = $env:COMPUTERNAME
                # Return a distinct message to prove we are on the final hop
                return "SUCCESS: Code executed on Final Target: $hostname"
            }
            
            # Clean up nested session
            Remove-PSSession $finalSession
            
            return $output
        }
        catch {
            return "ERROR on JumpHost connecting to Target: $_"
        }
    }

    Write-Host "Step 2: Executing nested command via JumpHost..."
    
    # STEP 2: Invoke the block on the JumpHost, passing the parameters
    # The 'ArgumentList' matches the 'param($Target, $Creds)' in $remoteScriptBlock
    $result = Invoke-Command -Session $jumpSession -ScriptBlock $remoteScriptBlock -ArgumentList $TargetComputer, $Credential

    Write-Host "Result from Double Hop:" -ForegroundColor Yellow
    Write-Host $result

}
catch {
    Write-Host "Fatal Error: $_" -ForegroundColor Red
}
finally {
    if ($jumpSession) {
        Remove-PSSession $jumpSession
        Write-Host "JumpHost Session removed." -ForegroundColor Gray
    }
}
