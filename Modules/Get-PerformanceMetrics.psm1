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