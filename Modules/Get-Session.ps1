function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    try {
        if (Get-PSProvider -PSProvider WSMan -ErrorAction SilentlyContinue) {
            $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            # Skip update if wildcard exists
                if ($currentTrustedHosts -ne "*") {
                    # Get current list as array
                    $hostList = if (-not [string]::IsNullOrEmpty($currentTrustedHosts)) {
                        $currentTrustedHosts -split ',' | ForEach-Object { $_.Trim() }
                    } else {
                        @()
                    }
                    
                    # Add server if not already present
                    if ($serverName -notin $hostList) {
                        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $serverName -Concatenate -Force -ErrorAction SilentlyContinue
                    }
                }
        }
        try {
            
            $session = New-PSSession -ComputerName $serverName -Credential $Credential -ErrorAction SilentlyContinue
            if ($null -eq $session) {
                return $null
            }
            return $session
        } catch {
            return $null
        }
    }
    catch {
        return $null
    }
}