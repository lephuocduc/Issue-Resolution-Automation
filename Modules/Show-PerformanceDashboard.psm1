function Show-PerformanceDashboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Uptime,
        [Parameter(Mandatory = $true)]
        [object]$TopCPU,
        [Parameter(Mandatory = $true)]
        [object]$TopMemory,
        [Parameter(Mandatory = $true)]
        [object]$SystemMetrics,
        [Parameter(Mandatory = $false)]
        [string]$LogDirectory = "C:\temp"
    )
    
    # Create temp directory if it doesn't exist
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        Write-Log "Created temporary directory: $LogDirectory" "Info"
    }
    
    Write-Log "Generating performance dashboard for $($Uptime.ServerName)" "Info"
    try {
        # Generate dashboard content
        $collectionTime = Get-Date -Format "hh:mm tt on MMMM dd, yyyy"
        $memPercent = $SystemMetrics.AvgMemoryPercent
        $memGB = [math]::Round($SystemMetrics.AvgMemoryBytes / 1GB, 1)
        $totalGB = [math]::Round($SystemMetrics.TotalMemoryBytes / 1GB, 1)

        $output = @()
        $output += ("=" * 60)
        $output += "SERVER: $($Uptime.ServerName) | UPTIME: $($Uptime.Days) DAYS $($Uptime.Hours) HOURS $($Uptime.Minutes) MINUTES"
        $output += "Data Collected at $collectionTime"
        $output += ("=" * 60)
        $output += "OVERVIEW:"
        $output += "[CPU]: $($SystemMetrics.AvgCPU)%`t[MEM]: ${memGB}GB ($memPercent%)"
        $output += ("=" * 60)
        $output += "TOP PROCESSES (CPU):"
        $output += ("{0,-30} {1,-15} {2,-15} {3}" -f "Process name (PID)", "CPU", "RAM", "Run as")
        
        $i = 1
        foreach ($p in $TopCPU) {
            $pMemGB = [math]::Round($p.AvgMemoryBytes / 1GB, 1)
            $pMemPercent = [math]::Round(($p.AvgMemoryBytes / $SystemMetrics.TotalMemoryBytes) * 100, 1)
            
            # Format each component with fixed-width spacing
            $line = ("{0}. {1} {2}  - {3}  - {4}GB ({5}%)  - {6}" -f 
                ($i++).ToString().PadLeft(2),
                ($p.ProcessName).PadRight(15),
                "($($p.PID))".PadRight(8),  # PID in parentheses with padding
                ($p.AvgCPU.ToString("0.00") + "%").PadLeft(7),
                $pMemGB.ToString("0.0").PadLeft(4),
                $pMemPercent.ToString("0.0").PadLeft(4),
                $p.User)
            
            $output += $line
        }
        
        $output += ("=" * 60)
        $output += "TOP PROCESSES (MEM):"
        $output += ("{0,-30} {1,-15} {2,-15} {3}" -f "Process name (PID)", "CPU", "RAM", "Run as")
        
        $i = 1
        foreach ($p in $TopMemory) {
            $pMemGB = [math]::Round($p.AvgMemoryBytes / 1GB, 1)
            $pMemPercent = [math]::Round(($p.AvgMemoryBytes / $SystemMetrics.TotalMemoryBytes) * 100, 1)
            
            # Format each component with fixed-width spacing
            $line = ("{0}. {1} {2}  - {3}  - {4}GB ({5}%)  - {6}" -f 
                ($i++).ToString().PadLeft(2),
                ($p.ProcessName).PadRight(15),
                "($($p.PID))".PadRight(8),  # PID in parentheses with padding
                ($p.AvgCPU.ToString("0.00") + "%").PadLeft(7),
                $pMemGB.ToString("0.0").PadLeft(4),
                $pMemPercent.ToString("0.0").PadLeft(4),
                $p.User)
            
            $output += $line
        }
        
        $output += ("=" * 60)
        
        # Display dashboard to console
        $output | Out-Host
        
        # Export to file
        $timestamp = Get-Date -Format "ddMMyyyy_HHmmss"
        $fileName = "PerformanceDashboard_$($Uptime.ServerName)_${timestamp}.txt"
        $filePath = Join-Path $LogDirectory $fileName
        
        $output -join "`n" | Out-File -FilePath $filePath -Force
        
        Write-Log "Performance dashboard exported to $filePath" "Info"
        
        return $filePath
    }
    catch {
        Write-Log "Error generating performance dashboard: $_" "Error"
        throw
    }
}