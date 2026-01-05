$Content = {

    # --- Module: Clear-SystemCache.psm1 ---
function Clear-SystemCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    try {
        Write-Host "Starting to clear system cache"
        $ScriptBlock = {
            # Define cache locations and configurations
            $cacheConfigs = @(
                @{ 
                    Name = "Windows Update cache"
                    Path = "C:\Windows\SoftwareDistribution\Download\*"
                },
                @{ 
                    Name = "Windows Installer patch cache"
                    Path = "C:\Windows\Installer\$PatchCache$\*"
                },
                @{ 
                    Name = "SCCM cache"
                    Path = 'C:\Windows\ccmcache\*' 
                },
                @{ 
                    Name = "Windows Temp files"
                    Path = "C:\Windows\Temp\*"
                }
            )

            $daysOld = 5
            $cutoffDate = (Get-Date).AddDays(-$daysOld)

            # Process all file-based caches
            foreach ($config in $cacheConfigs) {
                try {
                    Write-Host "`nProcessing $($config.Name)..."
                    
                    if (-not (Test-Path -Path $config.Path -ErrorAction SilentlyContinue)) {
                        Write-Host "$($config.Name) not found - Skipping" -ForegroundColor Yellow
                        continue
                    }

                    $filesToDelete = Get-ChildItem -Path $config.Path -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutoffDate }

                    if (-not $filesToDelete) {
                        Write-Host "No expired files found in $($config.Name)"
                        continue
                    }

                    Write-Host "Found $($filesToDelete.Count) files to delete:"
                    $successCount = 0
                    $errorCount = 0

                    foreach ($file in $filesToDelete) {
                        try {
                            Remove-Item -Path $file.FullName -Force -Recurse -ErrorAction Stop
                            Write-Host "  Deleted: $($file.FullName)" -ForegroundColor Green
                            $successCount++
                        }
                        catch {
                            Write-Host "  Error deleting: $($file.FullName)" -ForegroundColor Red
                            Write-Host "    Reason: $($_.Exception.Message)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                    
                    Write-Host "`n$($config.Name) results: $successCount deleted, $errorCount errors" -ForegroundColor Cyan
                }
                catch {
                    Write-Host "Error processing $($config.Name): $_" -ForegroundColor Red
                }
            }

            # Process Recycle Bin separately
            try {
                Write-Host "`nClearing Recycle Bin..."
                Clear-RecycleBin -Force -ErrorAction Stop
                Write-Host "Recycle Bin cleared" -ForegroundColor Green
            }
            catch {
                Write-Host "Error clearing Recycle Bin: $_" -ForegroundColor Red
            }
        }
        
        Invoke-Command -Session $session -ScriptBlock $ScriptBlock
        Write-Host "`nCache clearing operation completed" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error clearing system cache: $_" -ForegroundColor Red
    }
}

    # --- Module: Compress-IISLogs.psm1 ---
function Compress-IISLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [string]$IISLogPath = "C:\inetpub\logs\LogFiles",
        [string]$ArchivePath = "C:\inetpub\logs\Archive"
    )

    try {
        $ScriptBlock = {
            param($IISLogPath, $ArchivePath)

            # Ensure the archive directory exists
            try {
                if (Test-Path -Path $IISLogPath) {
                    Write-Host "IIS log path exists: $IISLogPath"
                    if (-not (Test-Path -Path $ArchivePath)) {
                        Write-Host "Creating archive path: $ArchivePath"
                        New-Item -Path $ArchivePath -ItemType Directory -Force | Out-Null
                    }
                    else {
                        Write-Host "Archive path already exists: $ArchivePath"
                    }
                    $OldLogs = Get-ChildItem -Path "$IISLogPath\*" -Recurse -Force |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-6) }

                    Write-Host "Found $($OldLogs.Count) old log(s) to process"

                    # Then process the files
                    foreach ($Log in $OldLogs) {                    
                        try {
                            $ArchiveFileName = "$ArchivePath\$($Log.Name).zip"
                            Compress-Archive -Path $Log.FullName -DestinationPath $ArchiveFileName -Update -ErrorAction SilentlyContinue
                            if (Test-Path -Path $ArchiveFileName) {
                                Write-Host "Compressed IIS log file: $($Log.FullName) to $ArchiveFileName"
                                Remove-Item -Path $Log.FullName -Force -Verbose -ErrorAction SilentlyContinue
                                if ((Test-Path -Path $Log.FullName)) {
                                    Write-Host "Error removing log file: $($Log.FullName)"
                                }else {
                                    Write-Host "Removed log file: $($Log.FullName)"
                                }
                            }
                        } catch {
                            Write-Host "Error compressing or removing log file: $($Log.FullName). Error: $_"
                        }
                    }
                } else {
                    Write-Host "IIS log path not found: $IISLogPath"
                }
            } catch {
                return "Error processing Compress-IISLogs: $_"
            }
        }

        Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $IISLogPath, $ArchivePath
    }
    catch {
        return "Error executing Compress-IISLogs: $_"
    }
}

    # --- Module: Export-DiskReport.psm1 ---
function Export-DiskReport {
    <#
    .SYNOPSIS
        Exports a disk report to an HTML file.
    .DESCRIPTION
        This function generates an HTML report for a specified disk on a remote server.
        It includes disk usage details, cleanup logs, and top users/folders based on disk space usage.
    .PARAMETER serverName
        The name of the remote server where the disk report will be generated.
    .PARAMETER diskName
        The name of the disk to report on (e.g., "C", "D").
    .PARAMETER diskInfo
        A PSObject containing disk information such as used space, free space, total size, and free percentage.
    .PARAMETER beforeDiskInfo
        A PSObject containing disk information before cleanup (optional, used for C: drive).
    .PARAMETER systemCacheLog
        A string containing the system cache cleanup log (optional).
    .PARAMETER iisLogCleanupLog
        A string containing the IIS log cleanup log (optional).
    .PARAMETER topUsers
        An array of PSObjects representing the top users consuming disk space (optional).
    .PARAMETER topRoot
        An array of PSObjects representing the top root folders consuming disk space (optional).
    .PARAMETER topItems
        An array of PSObjects representing the top items (files/folders) consuming disk space (optional).
    .EXAMPLE
        $diskInfo = Get-DiskSpaceDetails -session $session -diskName "C"
        Export-DiskReport -serverName "Server01" -diskName "C" -diskInfo $diskInfo -beforeDiskInfo $beforeDiskInfo `
                        -systemCacheLog $systemCacheLog `
                        -iisLogCleanupLog $iisLogCleanupLog -topUsers $topUsers `
                        -topRoot $topRoot -topItems $topItems
        This will generate an HTML report for the C: drive on Server01, including disk usage details and cleanup logs.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$serverName,
        [Parameter(Mandatory)]
        [string]$diskName,
        [Parameter(Mandatory)]
        [PSObject]$diskInfo,
        [Parameter(Mandatory = $false)]
        [PSObject]$beforeDiskInfo,
        [Parameter(Mandatory = $false)]
        [string]$systemCacheLog,
        [Parameter(Mandatory = $false)]
        [string]$iisLogCleanupLog,
        [Parameter(Mandatory = $false)]
        [array]$topUsers,
        [Parameter(Mandatory = $false)]
        [array]$topRoot,
        [Parameter(Mandatory = $false)]
        [array]$topItems
    )

    function Format-TopItemsHtml {
        <#
        .SYNOPSIS
            Formats the top items (users or folders) into HTML for the disk report.
        .DESCRIPTION
            This function generates HTML tables for the top users or folders based on disk space usage.
            It creates a table with user names and their total size or folder names with their sub-items and sizes.
        .PARAMETER items
            An array of PSObjects representing the top items (users or folders).
        .PARAMETER type
            The type of items to format ("Users" for top users, "Folders" for top folders).
        .EXAMPLE
            $topUsers = @(
                [PSCustomObject]@{ Name = "User1"; SizeGB = 10 },
                [PSCustomObject]@{ Name = "User2"; SizeGB = 5 }
            )
            $html = Format-TopItemsHtml -items $topUsers -type "Users"
            This will generate an HTML table for the top users with their names and total sizes.
        #>
        param(
            [Parameter(Mandatory=$true)]
            [array]$items,
            [Parameter(Mandatory=$true)]
            [string]$type
        )
        if (-not $items) { return "" }

        if ($type -eq "Users") {
            $html = "<table class='top-users'>`n"
            $html += "<thead><tr><th>User</th><th>Total Size</th></tr></thead>`n"
            $html += "<tbody>`n"
            foreach ($item in $items) {
                $html += "<tr><td><strong>$($item.Name)</strong></td><td>$($item.SizeGB)GB</td></tr>`n"
            }
            $html += "</tbody>`n</table>`n"
        } else {
            $html = "<table class='top-folders'>`n"
            $html += "<thead><tr><th>Folder</th><th>Subfolder/File</th><th>Size</th></tr></thead>`n"
            $html += "<tbody>`n"
            foreach ($item in $items) {
                if ($item.SubItems -and $item.SubItems.Count -gt 0) {
                    $rowspan = $item.SubItems.Count
                    $firstSubItem = $item.SubItems[0]
                    $html += "<tr><td rowspan='$rowspan'><strong>$($item.Name)</strong> ($($item.SizeGB)GB)</td><td>$($firstSubItem.Name)</td><td>$($firstSubItem.SizeMB)MB</td></tr>`n"
                    for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                        $subItem = $item.SubItems[$i]
                        $html += "<tr><td>$($subItem.Name)</td><td>$($subItem.SizeMB)MB</td></tr>`n"
                    }
                } else {
                    $html += "<tr><td><strong>$($item.Name)</strong> ($($item.SizeGB)GB)</td><td colspan='2'>Empty</td></tr>`n"
                }
            }
            $html += "</tbody>`n</table>`n"
        }
        return $html
    }

    try {
        Write-Host "Exporting disk report for $diskName on $serverName"
        if (-not (Test-Path "C:\temp")) { 
            New-Item -ItemType Directory -Path "C:\temp" | Out-Null
        }

        $timestamp = Get-Date -Format "ddMMyyyy-HHmm"
        $reportPath = "C:\temp\LowFreeSpace-$diskName-$serverName-$timestamp.html"

        $html = @"
<html>
<head>
    <title>Disk Report for $serverName - $diskName</title>
    <style>
        body { font-family: Arial, sans-serif; }
        h1 { color: #333; }
        h2 { color: #555; }
        h3 { margin-top: 20px; }
        .section { margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        td strong { color: #333; }
        .top-users th, .top-users td { vertical-align: middle; }
        .top-folders th, .top-folders td { vertical-align: top; }
        .top-folders td[rowspan] { background-color: #f9f9f9; font-weight: bold; }
        pre { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>Disk Report for $serverName - $diskName</h1>
    <p>Date: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</p>
"@

        # Disk Usage Section (unchanged)
        if ($diskName -eq "C" -and $beforeDiskInfo) {
            $spaceSaved = [math]::Round($diskInfo.FreeSpace - $beforeDiskInfo.FreeSpace, 2)
            $html += @"
    <h2>Disk Usage</h2>
    <table>
        <tr><th>State</th><th>Drive</th><th>Used GB</th><th>Free GB</th><th>Total GB</th><th>Free Percentage</th></tr>
        <tr><td>Before Cleanup</td><td>$diskName</td><td>$($beforeDiskInfo.UsedSpace)</td><td>$($beforeDiskInfo.FreeSpace)</td><td>$($beforeDiskInfo.TotalSize)</td><td>$($beforeDiskInfo.FreePercentage)%</td></tr>
        <tr><td>After Cleanup</td><td>$diskName</td><td>$($diskInfo.UsedSpace)</td><td>$($diskInfo.FreeSpace)</td><td>$($diskInfo.TotalSize)</td><td>$($diskInfo.FreePercentage)%</td></tr>
    </table>
    <p>Space saved: $spaceSaved GB</p>
"@
        } else {
            $html += @"
    <h2>Disk Usage</h2>
    <table>
        <tr><th>Drive</th><th>Used GB</th><th>Free GB</th><th>Total GB</th><th>Free Percentage</th></tr>
        <tr><td>$diskName</td><td>$($diskInfo.UsedSpace)</td><td>$($diskInfo.FreeSpace)</td><td>$($diskInfo.TotalSize)</td><td>$($diskInfo.FreePercentage)%</td></tr>
    </table>
"@
        }

        # Cleanup Logs for C drive (unchanged)
        if ($diskName -eq "C") {
            $html += @"
    <h2>Cleanup Logs</h2>
    <h3>System Cache Cleaning</h3>
    <pre>$systemCacheLog</pre>
    <h3>IIS Log Compression</h3>
    <pre>$iisLogCleanupLog</pre>
"@
        }

        # Top Folders Section
        if ($diskName -eq "C" -and ($topUsers -or $topRoot)) {
            $html += "<div class='section'><h2>Top Folders (Space Still Low)</h2>`n"
            if ($topUsers) {
                $html += "<h3>Top Users in C:\Users</h3>`n"
                $html += Format-TopItemsHtml -items $topUsers -type "Users"
            }
            if ($topRoot) {
                $html += "<h3>Top Root Folders in C:\ (excluding system folders)</h3>`n"
                $html += Format-TopItemsHtml -items $topRoot -type "Root"
            }
            $html += "</div>`n"
        } elseif ($topItems) {
            $html += "<div class='section'><h2>Top Folders on $diskName</h2>`n"
            $html += Format-TopItemsHtml -items $topItems -type "Root"
            $html += "</div>`n"
        }

        $html += "</body></html>"

        $html | Out-File -FilePath $reportPath -Force

        return $reportPath
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Host "Error exporting disk report for $diskName on $serverName': $errorDetails"
    }
}

    # --- Module: Get-DiskSpaceDetails.psm1 ---
function Get-DiskSpaceDetails {
    <#
    .SYNOPSIS
        Gets disk space details for a specified disk on a remote server.
    .DESCRIPTION
        This function retrieves disk space details such as used space, free space, total size, and free percentage for a specified disk on a remote server.
    .PARAMETER session
        The PowerShell session to the remote server where the disk space details will be retrieved.
    .PARAMETER diskName
        The name of the disk to check (e.g., "C", "D").
    .EXAMPLE
        $session = Get-Session -serverName "Server01"
        $diskDetails = Get-DiskSpaceDetails -session $session -diskName "C"
        if ($diskDetails) {
            Write-Log "Disk space details for C: Used $($diskDetails.UsedSpace)GB, Free $($diskDetails.FreeSpace)GB, Total $($diskDetails.TotalSize)GB, Free Percentage $($diskDetails.FreePercentage)%"
        } else {
            Write-Log "Failed to retrieve disk space details for C" "Error"
        }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )

    try {
        Write-Log "Getting disk space details for $diskName"
        $diskDetails = Invoke-Command -Session $session -ScriptBlock {
            param($diskName)
            $drive = Get-PSDrive -Name $diskName -ErrorAction SilentlyContinue
            if ($null -eq $drive) {
                return $null
            }
    
            $freeSpace = [math]::Round($drive.Free / 1GB, 2)
            $totalSize = [math]::Round(($drive.Free + $drive.Used) / 1GB, 2)
            $freePercentage = [math]::Round(($drive.Free / ($drive.Free + $drive.Used)) * 100, 2)
    
            return [PSCustomObject]@{
                UsedSpace = [math]::Round(($drive.Used / 1GB), 2)
                FreeSpace = $freeSpace
                TotalSize = $totalSize
                FreePercentage = $freePercentage
            }
        } -ArgumentList $diskName
    
        return $diskDetails
    }
    catch {
        return "Error retrieving disk space details: $_"
    }
}

    # --- Module: Get-PerformanceMetrics.psm1 ---
function Get-PerformanceMetrics {
    <#
    .SYSNOPSIS
    Collects performance metrics from a remote Windows system using PowerShell remoting.

    .DESCRIPTION
    This function connects to a remote Windows system using PowerShell remoting and collects performance metrics such as CPU usage, memory usage, and process information. It supports multiple samples and intervals for more accurate data collection.

    .PARAMETER Session
    Specifies the PowerShell session to use for remote execution.

    .PARAMETER Samples
    Specifies the number of samples to collect. Default is 2.

    .PARAMETER Interval
    Specifies the interval in seconds between samples. Default is 2 seconds.

    .EXAMPLE
    $metrics = Get-PerformanceMetrics -Session $session -Samples 5 -Interval 1
    This example collects 5 samples of performance metrics from the remote system specified in the $session variable, with a 1-second interval between samples.
    #>
    [CmdletBinding()]   
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $false)]
        [int]$Samples = 2,
        [Parameter(Mandatory = $false)]
        [int]$Interval = 2
    )

    # Scriptblock to collect static system information
    $staticScriptBlock = {
        return @{
            TotalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
        }
    }

    # Scriptblock to collect performance samples
    $sampleScriptBlock = {
        param(
            $totalMemory,     # Total physical memory in bytes
            $ownerCache       # Process owner lookup cache
        )

        # Function to get process owner with caching
        function Get-ProcessOwner {
            param($ProcessId)
            try {
                $cimProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId"
                $owner = $cimProcess | Invoke-CimMethod -MethodName GetOwner
                if ($null -eq $owner) {
                    return "Unknown"
                } else {
                    return "$($owner.Domain)\$($owner.User)"
                }
            } catch {
                return "Unknown"
            }
        }

        # Collect system-wide metrics
        $cpuSample = (Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples.CookedValue
        $available = (Get-Counter -Counter "\Memory\Available Bytes" -ErrorAction Stop).CounterSamples.CookedValue
        $memorySample = [math]::Round((($totalMemory - $available) / $totalMemory * 100), 2)

        # Build CPU usage map for all processes using PID mapping
        $cpuUsageMap = @{}
        $counterData = Get-Counter -Counter "\Process(*)\% Processor Time", "\Process(*)\ID Process" -ErrorAction SilentlyContinue
        if ($counterData) {
            $pidMap = @{}
            $cpuMap = @{}
            
            # First pass: map instance names to PIDs
            $counterData.CounterSamples | Where-Object { $_.Path -like "*\ID Process" } | ForEach-Object {
                $pidMap[$_.InstanceName] = [int]$_.CookedValue
            }
            
            # Second pass: map PIDs to CPU values
            $counterData.CounterSamples | Where-Object { $_.Path -like "*\% Processor Time" } | ForEach-Object {
                $instance = $_.InstanceName
                if ($pidMap.ContainsKey($instance) -and $instance -notin @('_Total', 'Idle')) {
                    $processid = $pidMap[$instance]
                    $cpuMap[$processid] = [math]::Round($_.CookedValue, 2)
                }
            }
            $cpuUsageMap = $cpuMap
        }

        # Collect process data
        $processData = @()
        if (-not $ownerCache) { $ownerCache = @{} }  # Initialize cache if not provided
        Get-Process | Where-Object { $_.Id -ne 0} | ForEach-Object {
            $process = $_
            $cpuUsage = if ($cpuUsageMap.ContainsKey($process.Id)) { $cpuUsageMap[$process.Id] } else { 0 }
            
            # Cache process owners to reduce lookups
            if (-not $ownerCache.ContainsKey($process.Id)) {
                $ownerCache[$process.Id] = Get-ProcessOwner -ProcessId $process.Id
            }

            $processData += [PSCustomObject]@{
                PID         = $process.Id
                ProcessName = $process.ProcessName
                CPU         = $cpuUsage
                MemoryBytes = $process.WorkingSet64
                User        = $ownerCache[$process.Id]
            }
        }

        return @{
            CpuSample    = $cpuSample
            MemorySample = $memorySample
            ProcessData  = $processData
            OwnerCache   = $ownerCache
        }
    }

    try {
        # Get static system information
        $staticResult = Invoke-Command -Session $Session -ScriptBlock $staticScriptBlock
        $totalMemory = $staticResult.TotalMemory

        # Initialize data collectors
        $cpuSamples = New-Object System.Collections.Generic.List[double]
        $memorySamples = New-Object System.Collections.Generic.List[double]
        $processAggregates = @{}
        $ownerCache = @{}

        # Collect performance samples
        for ($i = 1; $i -le $Samples; $i++) {
            Update-StatusLabel -text "Collecting sample $i of $Samples with $Interval seconds interval."
            $sampleResult = Invoke-Command -Session $Session -ScriptBlock $sampleScriptBlock -ArgumentList $totalMemory, $ownerCache
            
            $cpuSamples.Add($sampleResult.CpuSample) # Add CPU sample to collection
            $memorySamples.Add($sampleResult.MemorySample) # Add memory sample to collection
            $ownerCache = $sampleResult.OwnerCache  # Preserve owner cache between samples

            # Aggregate process data across samples
            $sampleResult.ProcessData | ForEach-Object {
                $procId = $_.PID
                if (-not $processAggregates.ContainsKey($procId)) {
                    $processAggregates[$procId] = [PSCustomObject]@{
                        PID             = $procId
                        ProcessName     = $_.ProcessName
                        User            = $_.User
                        TotalCPU        = 0
                        TotalMemoryBytes = 0
                        SampleCount     = 0
                    }
                }
                $agg = $processAggregates[$procId]
                $agg.TotalCPU += $_.CPU
                $agg.TotalMemoryBytes += $_.MemoryBytes
                $agg.SampleCount++
            }

            if ($i -lt $Samples) { Start-Sleep -Seconds $Interval }
        }

        # Calculate system averages
        $avgCPU = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 2)
        $avgMemoryPercent = [math]::Round(($memorySamples | Measure-Object -Average).Average, 2)
        $avgMemoryBytes = [math]::Round(($avgMemoryPercent / 100 * $totalMemory), 0)

        # Build per-process summary
        $processSummary = $processAggregates.Values | ForEach-Object {
            [PSCustomObject]@{
                PID           = $_.PID
                ProcessName   = $_.ProcessName
                User          = $_.User
                AvgCPU        = [math]::Round($_.TotalCPU / $_.SampleCount, 2)
                AvgMemoryBytes = [math]::Round($_.TotalMemoryBytes / $_.SampleCount, 0)
            }
        }

        # Group processes by ProcessName and User, summing averages
        $groupedSummary = @()
        $groups = $processSummary | Group-Object ProcessName, User
        foreach ($group in $groups) {
            $pids = $group.Group.PID
            $representativePID = ($pids | Measure-Object -Minimum).Minimum
            $pidDisplay = $representativePID.ToString()
            $groupedSummary += [PSCustomObject]@{
                ProcessName    = $group.Group[0].ProcessName
                User           = $group.Group[0].User
                AvgCPU         = [math]::Round(($group.Group | Measure-Object AvgCPU -Sum).Sum, 2)
                AvgMemoryBytes = [math]::Round(($group.Group | Measure-Object AvgMemoryBytes -Sum).Sum, 0)
                PID            = $pidDisplay
            }
        }

        return [PSCustomObject]@{
            SystemMetrics = [PSCustomObject]@{
                AvgCPU           = $avgCPU
                AvgMemoryPercent = $avgMemoryPercent
                AvgMemoryBytes   = $avgMemoryBytes
                TotalMemoryBytes = $totalMemory
            }
            ProcessMetrics = $groupedSummary
        }

    } catch {
        Update-StatusLabel -text "Error collecting performance metrics: $_"
        Write-Log "Error collecting performance metrics: $_" "Error"
        throw
    }
}

    # --- Module: Get-Session.psm1 ---
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

    # --- Module: Get-SystemUptime.psm1 ---
function Get-SystemUptime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    
    $scriptBlock = {
        $lastBoot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $uptime = [datetime]::Now - $lastBoot
        [PSCustomObject]@{
            ServerName = $env:COMPUTERNAME
            Days = $uptime.Days
            Hours = $uptime.Hours
            Minutes = $uptime.Minutes
        }
    }

    try {
        $result = Invoke-Command -Session $Session -ScriptBlock $scriptBlock
        return $result
    } catch {
        Write-Log "Error getting uptime for $ServerName : $_"
        throw
    }
}

    # --- Module: Get-TopCPUProcesses.psm1 ---
function Get-TopCPUProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$PerformanceData,
        [int]$TopCount = 5
    )
    $PerformanceData.ProcessMetrics | 
        Sort-Object AvgCPU -Descending | 
        Select-Object -First $TopCount |
        Select-Object ProcessName, PID, User, AvgCPU, AvgMemoryBytes
}

    # --- Module: Get-TopItems.psm1 ---
function Get-TopItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$path,
        [string[]]$exclude = @(),
        [int]$topN = 10
    )

    try {
        $scriptBlock = {
            param($path, $exclude, $topN)
            
            try {
                # Convert exclude list to HashSet for O(1) lookups
                $excludeSet = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
                foreach ($item in $exclude) { [void]$excludeSet.Add($item) }

                # Cache for folder sizes
                $folderSizeCache = @{}
                
                # Recursive function to calculate folder sizes with caching
                function Get-FolderSize {
                    param($folderPath)
                    
                    # Return cached value if available
                    if ($folderSizeCache.ContainsKey($folderPath)) {
                        return $folderSizeCache[$folderPath]
                    }
                    
                    $size = 0
                    $childItems = $null
                    try {
                        $childItems = Get-ChildItem -LiteralPath $folderPath -ErrorAction Stop
                    } catch {
                        Write-Host "Access error in $folderPath': $_"
                        $folderSizeCache[$folderPath] = 0
                        return 0
                    }
                    
                    foreach ($item in $childItems) {
                        # Skip excluded items
                        if ($excludeSet.Contains($item.Name)) { continue }
                        
                        if ($item.PSIsContainer) {
                            $size += Get-FolderSize $item.FullName
                        } else {
                            $size += $item.Length
                        }
                    }
                    
                    # Update cache and return
                    $folderSizeCache[$folderPath] = $size
                    return $size
                }

                # Process root items
                $rootItems = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                             Where-Object { -not $excludeSet.Contains($_.Name) }
                
                if (-not $rootItems) {
                    Write-Host "No items found in $path after exclusions."
                    return @()
                }

                $results = foreach ($item in $rootItems) {
                    $sizeBytes = if ($item.PSIsContainer) {
                        Get-FolderSize $item.FullName
                    } else {
                        $item.Length
                    }
                    
                    [PSCustomObject]@{
                        Name     = $item.Name
                        FullPath = $item.FullName
                        SizeGB   = [math]::Round($sizeBytes / 1GB, 2)
                        IsFolder = $item.PSIsContainer
                    }
                }

                # Get top N items
                $topItems = $results | Sort-Object SizeGB -Descending | Select-Object -First $topN

                # Process top items
                $detailedOutput = foreach ($item in $topItems) {
                    $output = [PSCustomObject]@{
                        Name     = $item.Name
                        SizeGB   = $item.SizeGB
                        Type     = if ($item.IsFolder) { "Folder" } else { "File" }
                        SubItems = @()
                    }

                    if ($item.IsFolder) {
                        $childItems = Get-ChildItem -LiteralPath $item.FullPath -ErrorAction SilentlyContinue |
                                      Where-Object { -not $excludeSet.Contains($_.Name) }
                        
                        $childObjects = foreach ($child in $childItems) {
                            $childSizeBytes = if ($child.PSIsContainer) {
                                $folderSizeCache[$child.FullName]
                            } else {
                                $child.Length
                            }
                            
                            [PSCustomObject]@{
                                Name   = $child.Name
                                SizeMB = [math]::Round($childSizeBytes / 1MB, 2)
                                Type   = if ($child.PSIsContainer) { "Folder" } else { "File" }
                            }
                        }
                        
                        $output.SubItems = $childObjects | Sort-Object SizeMB -Descending | Select-Object -First 10
                    }
                    $output
                }

                return $detailedOutput
            } catch {
                Write-Host "Error in Get-TopItems script block: $_"
                return @()
            }
        }

        # Execute the script block on the remote session
        $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
        Write-Host "Retrieved top $topN items in '$path'"
        return $result
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Host "Error executing Get-TopItems: $errorDetails"
        return @()
    }
}

    # --- Module: Get-TopMemoryProcesses.psm1 ---
function Get-TopMemoryProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$PerformanceData,
        [int]$TopCount = 5
    )
    $PerformanceData.ProcessMetrics | 
        Sort-Object AvgMemoryBytes -Descending | 
        Select-Object -First $TopCount |
        Select-Object ProcessName, PID, User, AvgCPU, AvgMemoryBytes
}

    # --- Module: Show-PerformanceDashboard.psm1 ---
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

    # --- Module: Test-DiskAvailability.psm1 ---
function Test-DiskAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z]$')]
        [string]$DiskName
    )

    try {       
        # Optimized remote check using direct WMI access
        $diskExists = Invoke-Command -Session $Session -ScriptBlock {
            $driveLetter = $args[0] + ':'
            try {
                $drive = Get-CimInstance -ClassName Win32_LogicalDisk `
                         -Filter "DeviceID = '$driveLetter'" `
                         -ErrorAction Stop
                return [bool]$drive
            }
            catch {
                return $false
            }
        } -ArgumentList $DiskName -ErrorAction Stop

        if ($diskExists) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}

    # --- Module: Test-ReportFileCreation.psm1 ---
function Test-ReportFileCreation {
    [CmdletBinding()]
    param(
        [string]$LogPath = "C:\Temp",
        [string]$TestFile = "test_$(Get-Date -Format 'ddMMyyyy_HHmmss').html"
    )
    
    try {        
        # Use Join-Path for combining paths
        $testFilePath = Join-Path -Path $LogPath -ChildPath $TestFile

        # Create directory structure if needed
        if (-not (Test-Path -Path $LogPath -PathType Container)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }

        # Generate content with UTC timestamp for consistency
        $utcTimestamp = (Get-Date).ToUniversalTime().ToString("o")
        $testContent = "Log creation test: $utcTimestamp"

        # Write content to file
        Set-Content -Path $testFilePath -Value $testContent -Force

        # Verify file creation
        if (Test-Path -Path $testFilePath -PathType Leaf) {
            Remove-Item -Path $testFilePath -Force
            return $true
        }

        throw "File verification failed after write operation"
    }
    catch {
        return $false
    }
}

    # --- Module: Test-ServerAvailability.psm1 ---
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

    # --- Module: Write-Log.psm1 ---
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp",
        [string]$LogFile
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    #$LogPath = Join-Path $LogDirectory "LowFreeSpace-log-$datePart.log"
    $LogPath = Join-Path $LogDirectory "$LogFile-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

    # --- Module: Write-WindowsEventLog.psm1 ---
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

}

# --- Main Script ---
# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:ModuleContents = $Content

# Import the Get-BitwardenAuthentication module
Import-Module "$PSScriptRoot\Get-BitwardenAuthentication.psm1" -Force

$script:ADM_Credential = $null
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

function Unprotect-BitwardenConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    # Unprotect the encrypted file and convert from JSON
    try {
        $decryptedContent = Unprotect-CmsMessage -Path $ConfigPath | ConvertFrom-Json
        return $decryptedContent
    }
    catch {
        $ErrorMessage = $_.Exception.Message

        # Pop up an error message box
        [System.Windows.Forms.MessageBox]::Show(
            "Error: $ErrorMessage",
            "Decryption Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        throw
    }
}

# Decrypt the Bitwarden configuration
$DecryptedContent = Unprotect-BitwardenConfig -ConfigPath "$PSScriptRoot/EncryptedBitwarden.json"
# Extract values
$clientId = $DecryptedContent.bitwarden.clientId
$clientSecret = $DecryptedContent.bitwarden.clientSecret
$masterPassword = $DecryptedContent.bitwarden.masterPassword
$credentialName = $DecryptedContent.bitwarden.credentialName

# Check if any required value is missing
if (-not $clientId -or -not $clientSecret -or -not $masterPassword -or -not $credentialName) {
    throw "One or more Bitwarden configuration values are missing."
}

function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($bitwarden_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp"
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "ScriptManager-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

# Get all video controller objects
$screens = Get-WmiObject -Class Win32_VideoController

# Initialize scale factors
$scaleX = 1
$scaleY = 1

# Set design resolution
$designWidth = 1920
$designHeight = 1080

<#
# Loop through all video controllers
foreach ($screen in $screens) {
    $screenWidth = $screen.CurrentHorizontalResolution
    $screenHeight = $screen.CurrentVerticalResolution
    if ($screenWidth -and $screenHeight) {
        $scaleX = $screenWidth / $designWidth
        $scaleY = $screenHeight / $designHeight
    }
}#>

# Bitwarden form
$bitwarden_form = New-Object System.Windows.Forms.Form
$bitwarden_form.Text = "Script Manager - Checking"
$bitwarden_form.Size = New-Object System.Drawing.Size([Math]::Round(410 * $scaleX) , [Math]::Round(120 * $scaleY))  # Adjust size based on screen resolution
$bitwarden_form.StartPosition = "CenterScreen"
$bitwarden_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$bitwarden_form.MaximizeBox = $false

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel.Font = New-Object System.Drawing.Font($statusLabel.Font.FontFamily, [Math]::Round(11* $scaleY))  # Adjust font size based on screen resolution
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$statusLabel.Location = New-Object System.Drawing.Point([Math]::Round(([Math]::Round($bitwarden_form.Size.Width / 2) - $statusLabel_width) * $scaleX), [Math]::Round(([Math]::Round(($bitwarden_form.Size.Height / 2) - $statusLabel.PreferredHeight)) * $scaleY))

  # Initially hidden until the check is done
$bitwarden_form.Controls.Add($statusLabel)
$bitwarden_form.Add_Shown({
    try {
        # Retrieve the ADM_Credential
        Update-StatusLabel -text "Authenticating with Bitwarden..."
        $script:ADM_Credential = Get-BitwardenAuthentication -ClientId $clientId -ClientSecret $clientSecret -MasterPassword $masterPassword -CredentialName $credentialName
        if ($script:ADM_Credential) {       
            # Get all jump host names from the jumphost.json file
            # Test if the file exists
            $jumpHostsFileContent = Get-Content -Path $PSScriptRoot\"jumphost.json" | ConvertFrom-Json
            $jumpHosts = $jumpHostsFileContent.DCS.PSObject.Properties.Value
            if ( -not $jumpHosts -or $jumpHosts.Count -eq 0 ) {
                Write-Log "No jump hosts found in jumphost.json" -Level "Error"
                [System.Windows.Forms.MessageBox]::Show(
                    "No jump hosts found in jumphost.json",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                exit
            } else {
                # Remote session for each jump host on DCS environment and choose the first one
                $script:JumpHost = $null
                foreach ($jumpHost in $jumpHosts) {
                    try {
                        #Import-Module "$PSScriptRoot\..\Modules\Get-Session.psm1" -Force
                        $session = Get-Session -serverName $jumpHost -Credential $script:ADM_Credential
                        if ($session) {
                            Write-Log "Successfully created session to $jumpHost" -Level "Info"
                            $script:JumpHost = $jumpHost

                            # 1. Define the correct path to modules
                            $scriptDir = if ($MyInvocation.MyCommand.Path) { 
                                Split-Path $MyInvocation.MyCommand.Path -Parent 
                            } else { 
                                $PSScriptRoot 
                            }
                            $localModulesPath = Join-Path $scriptDir "..\Modules"

                            # Check if the path actually exists before trying to copy
                            if (-not (Test-Path $localModulesPath)) {
                                Write-Log "Local modules path '$localModulesPath' does not exist." -Level "Error"
                                [system.windows.forms.messagebox]::Show(
                                    "Local modules path '$localModulesPath' does not exist.",
                                    "Error",
                                    [System.Windows.Forms.MessageBoxButtons]::OK,
                                    [System.Windows.Forms.MessageBoxIcon]::Error
                                )
                                return
                            }

                            # 2. Get all .psm1 files
                            $moduleFiles = Get-ChildItem -Path $localModulesPath -Filter *.psm1

                            foreach ($file in $moduleFiles) {
                                $moduleName = $file.BaseName
                                # Define the destination path on the remote server
                                $remoteBaseDir = "C:\Program Files\WindowsPowerShell\Modules"
                                $remoteModuleDir = "$remoteBaseDir\$moduleName"
                                
                                Write-Log "Copying module '$moduleName' to $jumpHost`:$remoteModuleDir"

                                # 3. Create the directory on the remote host if it doesn't exist
                                # We use Invoke-Command because Copy-Item fails if the destination folder isn't there.
                                Invoke-Command -Session $session -ArgumentList $remoteModuleDir -ScriptBlock {
                                    param($targetDir)
                                    if (-not (Test-Path -Path $targetDir)) {
                                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                                        Write-Log "Created directory $targetDir on remote host." -Level "Info"
                                    }
                                }

                                # 4. Copy the file to the session
                                # Destination must include the filename because we are copying a file to a folder
                                try {
                                    Copy-Item -Path $file.FullName -Destination "$remoteModuleDir\$($file.Name)" -ToSession $session -Force -ErrorAction Stop
                                    Write-Log "Successfully copied $($file.Name) to $jumpHost`:$remoteModuleDir" -Level "Info"
                                }
                                catch {
                                    Write-Log "Failed to copy $($file.Name) to $jumpHost`:$remoteModuleDir. Error: $_" -Level "Error"
                                    [System.Windows.Forms.MessageBox]::Show(
                                        "Error, check logs for details.",
                                        "Error",
                                        [System.Windows.Forms.MessageBoxButtons]::OK,
                                        [System.Windows.Forms.MessageBoxIcon]::Error
                                    )

                                }
                            }
                            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                            break  # Exit the loop if a session is successfully created
                        }
                    }
                    catch {
                        Write-Log "Failed to create session to `$jumpHost: $_" -Level "Warning"
                    }
                }
        
                if (-not $script:JumpHost) {
                    Write-Log "Could not connect to any jump host." -Level "Error"
                    [System.Windows.Forms.MessageBox]::Show(
                        "Could not connect to any jump host.",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                    $bitwarden_form.Close()
                    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
                }
            }
        }
        $bitwarden_form.Close()  # Close the Bitwarden form after successful authentication
        $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    }
    catch {
        Write-Log "An error occurred during Bitwarden authentication: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred during Bitwarden authentication: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
    }
    
})

#########################################
# Create the main form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Script Manager - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size([Math]::Round(400 * $scaleX), [Math]::Round(190*$scaleY))  # Adjust size based on screen resolution
$main_form.StartPosition = "CenterScreen"
# Prevent resizing
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false

# Label
$label = New-Object System.Windows.Forms.Label
$label.Text = "Choose a script to execute"
$label.AutoSize = $true
$label.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY), [System.Drawing.FontStyle]::Bold)

# Calculate centered position (after text & font set)
$label_width  = $label.PreferredWidth
$label_height = $label.PreferredHeight
$label_x = [Math]::Round( ($main_form.ClientSize.Width  - $label_width) / 2 )
$label_y = [Math]::Round( 25 * $scaleY )
$label.Location = New-Object System.Drawing.Point($label_x, $label_y)
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
#$comboBox.Location = New-Object System.Drawing.Point(110, 50)  # Centered horizontally - REMOVE THIS LINE
$comboBox.Size = New-Object System.Drawing.Size ([Math]::Round(200 * $scaleX), [Math]::Round(25 * $scaleY)) # set the size of combobox
$comboBox.Items.AddRange(@('Low Free Space','Windows Performance'))  # Add items to the dropdown
$comboBox.DropDownStyle = 'DropDown' # Allow text editing in the ComboBox
# Calculate the horizontal center for the ComboBox
$combobox_width = $comboBox.Size.Width
$combobox_x = [Math]::Round(($main_form.ClientSize.Width - $combobox_width) / 2)
$combobox_y = [Math]::Round( 50 * $scaleY ) # set padding from top
$comboBox.Location = New-Object System.Drawing.Point($combobox_x, $combobox_y)
# Set the font size (keep the default font family)
$defaultFont = $comboBox.Font  # Get the default font
$comboBox.Font = New-Object System.Drawing.Font($defaultFont.FontFamily, [Math]::Round(11 * $scaleY))  # Change only the size to 12
$comboBox.Text = "------------------------------"
# Enable AutoComplete functionality
$comboBox.AutoCompleteMode = 'SuggestAppend'  # Suggest matching items and append the rest
$comboBox.AutoCompleteSource = 'ListItems'    # Use items from the ComboBox's list for suggestions
# Add key event handler for Ctrl+A and Ctrl+C
$comboBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $comboBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $okButton.PerformClick()
        $e.SuppressKeyPress = $true  # Prevents the "ding" sound
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($comboBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($comboBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($comboBox.Text)
        }
        $e.SuppressKeyPress = $true
    }
})
 
# Create OK Button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = 'OK'
#$okButton.Location = New-Object System.Drawing.Point(120, 100) # Positioning below the dropdown
$okButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size for consistency


# Add Click event  to execute the selected script using a switch statement
$okButton.Add_Click({
    $selectedValue = $comboBox.Text
    switch ($selectedValue) {        "------------------------------" {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a script from the dropdown.",
                "Information",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        "Low Free Space" {
            . (Join-Path $PSScriptRoot "..\Scripts\LowFreeSpace\LowFreeSpace.ps1") -ADM_Credential $script:ADM_Credential -JumpHost $script:JumpHost -ModuleContents $script:ModuleContents
        }
        "Windows Performance" {
            . (Join-Path $PSScriptRoot "..\Scripts\WindowsPerformance\WindowsPerformance.ps1") -ADM_Credential $script:ADM_Credential -JumpHost $script:JumpHost -ModuleContents $script:ModuleContents
        }
        default {
            [System.Windows.Forms.MessageBox]::Show(
                "No script is associated with the selection '$selectedValue'.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return}
    }
})

# Create Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
#$cancelButton.Location = New-Object System.Drawing.Point(220, 100) # Positioning next to the OK button
$cancelButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size matching OK button
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({ $main_form.Dispose() })  # Close the form when Cancel is clicked

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25 * $scaleX  # Space between buttons
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, [Math]::Round(100 * $scaleY))
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), [Math]::Round(100 * $scaleY))

# Add controls to the form
$main_form.Controls.Add($comboBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show the form as a dialog
$bitwarden_form.ShowDialog()


if ($script:ADM_Credential -and $script:JumpHost) {
    # Close the Bitwarden form after authentication
    $bitwarden_form.Close()
    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    
    # Show the main form after Bitwarden authentication
    $main_form.ShowDialog()
}































