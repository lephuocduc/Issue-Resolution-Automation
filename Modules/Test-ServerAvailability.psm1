function Test-ServerAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9\.\-]+$')]
        [string]$ServerName
    )

    $result = [PSCustomObject]@{
        RemotingAvailable = $false
        PingReachable    = $false
        DNSResolvable   = $false
        ErrorDetails     = $null
    }

    try {
        # Test WinRM availability first
        $null = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        $result.RemotingAvailable = $true
        return $result
    }
    catch {
        $result.ErrorDetails = "WinRM test failed: $($_.Exception.Message)"
    }

    # If WinRM fails, test ping connectivity
    $pingFailed = $true
    try {
        $reply = Test-Connection -ComputerName $ServerName -Count 1 -ErrorAction Stop

        if ($reply.StatusCode -eq 0) {
            $pingFailed = $false
            $result.PingReachable = $true
            return $result
        }
        else {
            $result.ErrorDetails += "; Ping failed ($($reply.Status))"
        }
    }
    catch {
        $result.ErrorDetails += "; Ping test failed: $($_.Exception.Message)"
    }

    # If both WinRM and Ping fail, test DNS resolution
    if ($pingFailed) {
        try {
            $dnsResult = Resolve-DnsName -Name $ServerName -ErrorAction Stop
            if ($dnsResult) {
                $result.DNSResolvable = $true
                $result.ErrorDetails += "; DNS resolution succeeded but ping failed"
            }
        }
        catch {
            $result.DNSResolvable = $false
            $result.ErrorDetails += "; DNS resolution failed: $($_.Exception.Message)"
        }
    }
    return $result
}