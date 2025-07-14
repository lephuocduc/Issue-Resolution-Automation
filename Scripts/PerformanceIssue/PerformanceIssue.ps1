# NOTES
# Name:        PerformanceIssue.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        June 24, 2025

# DESCRIPTION
# This script creates a Windows Forms application that allows users to enter a server name, the script will then:

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp"
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "PerformanceIssue-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    $retryCount = 0
    $maxRetries = 3
    try {
        if (Get-PSProvider -PSProvider WSMan -ErrorAction SilentlyContinue) {
            $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            # Skip update if wildcard exists
            if ($currentTrustedHosts -ne "*") {
                Write-Log "Updating TrustedHosts for $serverName"
                # Get current list as array
                $hostList = if (-not [string]::IsNullOrEmpty($currentTrustedHosts)) {
                    $currentTrustedHosts -split ',' | ForEach-Object { $_.Trim() }
                } else {
                    @()
                }
                
                # Add server if not already present
                if ($serverName -notin $hostList) {
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $serverName -Concatenate -Force
                    Write-Log "Updated TrustedHosts to include $serverName"
                }
            } else {
                Write-Log "TrustedHosts already set to wildcard '*', skipping update for $serverName"
            }
        }
        do {
            Write-Log "Attempting to create session for $serverName (Attempt $($retryCount + 1) of $maxRetries)"
            $retryCount++
            $Credential = Get-Credential -Message "Enter credentials for $ServerName (Attempt $($retryCount) of $MaxRetries)"
            if ($null -eq $Credential -or $retryCount -ge $maxRetries) {
                Write-Log "Session creation canceled or retry limit reached for $serverName" "Error"
                Update-StatusLabel -text "Session creation canceled or retry limit reached for $serverName"
                return $null
            }
            try {
                
                $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
                Write-Log "Session created successfully for $serverName"
                Update-StatusLabel -text "Session created successfully for $serverName"
                return $session
            } catch {
                if ($retryCount -ge $maxRetries) {
                    Write-Log "Failed to create session for $serverName after $maxRetries attempts: $_" "Error"
                    Update-StatusLabel -text "Failed to create session for $serverName after $maxRetries attempts."
                    return $null
                }else {
                    $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
                    Write-Log "Failed to create session for $ServerName on attempt $retryCount. Error: $errorDetails" "Error"
                    Update-StatusLabel -text "Failed to create session for $serverName."
                }
            }
        } while ($true)
    }
    catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error creating session for $serverName': $errorDetails" "Error"
        Update-StatusLabel -text "Error creating session for $serverName"
        return $null
    }
}

function Test-ServerAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z0-9\.\-]+$')]
        [string]$ServerName
    )

    $result = [PSCustomObject]@{
        RemotingAvailable = $false
        PingReachable    = $false
        ErrorDetails     = $null
    }

    
    try {
        # Test WinRM availability first
        Update-StatusLabel -text "Testing WinRM service on $ServerName."
        Write-Log "Testing WinRM service on $ServerName."
        $null = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        $result.RemotingAvailable = $true
        Update-StatusLabel -text "WinRM service is available on $ServerName."
        Write-Log "WinRM service is available on $ServerName."
        return $result  # Exit early if successful
    }
    catch {
        $result.ErrorDetails = "WinRM test failed: $($_.Exception.Message)"
        Update-StatusLabel -text "WinRM service is unavailable on $ServerName."
        Write-Log $result.ErrorDetails "Warning"
    }

    # If WinRM fails, test ping connectivity
    try {
        Update-StatusLabel -text "Testing ping for $ServerName"
        Write-Log "Testing ping for $ServerName"
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($ServerName, 1000)  # 1 second timeout
        
        if ($reply.Status -eq 'Success') {
            $result.PingReachable = $true
            Update-StatusLabel -text "Server $ServerName is ping reachable but WinRM is unavailable. Please check WinRM service on the server and the server may be hung."
            Write-Log "Server $ServerName is ping reachable but WinRM is unavailable. Please check WinRM service on the server and the server may be hung." "Warning"
        }
        else {
            $result.ErrorDetails += "; Ping failed ($($reply.Status))"
            Update-StatusLabel -text "Server $ServerName is not ping reachable ($($reply.Status)) and WinRM is unavailable. The server may be offline."
            Write-Log "Server $ServerName is not ping reachable ($($reply.Status)) and WinRM is unavailable. The server may be offline." "Warning"
        }
    }
    catch {
        $result.ErrorDetails += "; Ping test failed: $($_.Exception.Message)"
        Update-StatusLabel -text "Ping test failed and WinRM is unavailable. Please check the server name or the server may be offline."
        Write-Log "Ping test failed for $ServerName': $($_.Exception.Message) and WinRM is unavailable. The server may be offline." "Warning"
    }

    return $result
}

function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()
}

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

# Version 1.0 of Get-PerformanceMetrics function
<#
function Get-PerformanceMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Samples = 5, # Number of samples to collect
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Interval = 2 # Interval in seconds between samples
    )

    # Scriptblock to collect static system information (runs once)
    $staticScriptBlock = {
        $totalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
        $numberOfCores = [Environment]::ProcessorCount
        return @{
            TotalMemory = $totalMemory
            NumberOfCores = $numberOfCores
        }
    }

    # Scriptblock to collect performance samples
    $sampleScriptBlock = {
        param($previousCpuTimes, $totalMemory, $numberOfCores, $previousTimestamp)

        # Function to get process owner
        function Get-ProcessOwner {
            param($ProcessId)
            try {
                $cimProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId"
                if ($cimProcess) {
                    $owner = Invoke-CimMethod -InputObject $cimProcess -MethodName GetOwner
                    return $owner.User
                }
                return "Unknown"
            } catch {
                return "Unknown"
            }
        }

        # Get CPU and memory usage
        $cpuSample = (Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples.CookedValue
        $available = (Get-Counter -Counter "\Memory\Available Bytes" -ErrorAction Stop).CounterSamples.CookedValue
        $usedMemory = $totalMemory - $available
        $memorySample = [math]::Round(($usedMemory / $totalMemory) * 100, 2)

        # Process data
        $currentProcesses = Get-Process | Where-Object { $_.Id -ne 0 }
        $currentCpuTimes = @{}
        $processData = @()
        $sampleStartTime = [datetime]::Now

        # Calculate actual interval since last sample
        $actualInterval = if ($previousTimestamp) {
            ($sampleStartTime - $previousTimestamp).TotalSeconds
        } else {
            $null
        }

        foreach ($process in $currentProcesses) {
            $processID = $process.Id
            $currentCpu = $process.TotalProcessorTime.TotalSeconds
            $currentCpuTimes[$processID] = $currentCpu

            # Calculate CPU usage for processes (skip for first sample)
            $cpuUsage = 0
            if ($previousCpuTimes -and $previousCpuTimes.ContainsKey($processID) -and $actualInterval -gt 0) {
                $cpuDelta = $currentCpu - $previousCpuTimes[$processID]
                $cpuUsage = [math]::Round(($cpuDelta / $actualInterval) * 100 / $numberOfCores, 2)
            }

            $user = Get-ProcessOwner -ProcessId $processID
            $processData += [PSCustomObject]@{
                SampleTime = $sampleStartTime
                PID = $processID
                ProcessName = $process.ProcessName
                CPU = $cpuUsage
                MemoryBytes = $process.WorkingSet64
                User = $user
            }
        }

        return @{
            CurrentCpuTimes = $currentCpuTimes
            CpuSample = $cpuSample
            MemorySample = $memorySample
            ProcessData = $processData
            SampleStartTime = $sampleStartTime
        }
    }

    try {
        # Get static system information
        $staticResult = Invoke-Command -Session $Session -ScriptBlock $staticScriptBlock
        $totalMemory = $staticResult.TotalMemory
        $numberOfCores = $staticResult.NumberOfCores

        # Initialize collections
        $cpuSamples = @()
        $memorySamples = @()
        $allProcessData = @()
        $previousCpuTimes = $null
        $previousTimestamp = $null

        # Collect performance samples
        for ($i = 1; $i -le $Samples; $i++) {
            Update-StatusLabel -text "Collecting sample $i of $Samples."

            $sampleParams = @{
                ScriptBlock = $sampleScriptBlock
                ArgumentList = $previousCpuTimes, $totalMemory, $numberOfCores, $previousTimestamp
            }

            $sampleResult = Invoke-Command -Session $Session @sampleParams

            # Store all samples, including first one for memory and CPU
            $cpuSamples += $sampleResult.CpuSample
            $memorySamples += $sampleResult.MemorySample
            if ($null -ne $previousTimestamp) {
                $allProcessData += $sampleResult.ProcessData
            }

            # Update for next iteration
            $previousCpuTimes = $sampleResult.CurrentCpuTimes
            $previousTimestamp = $sampleResult.SampleStartTime

            if ($i -lt $Samples) { Start-Sleep -Seconds $Interval }
        }

        # Calculate system averages
        $avgCPU = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 2)
        $avgMemoryPercent = [math]::Round(($memorySamples | Measure-Object -Average).Average, 2)
        $avgMemoryBytes = [math]::Round(($memorySamples | ForEach-Object { ($_ / 100) * $totalMemory } | Measure-Object -Average).Average, 0)

        # Aggregate process data
        $processSummary = if ($allProcessData) {
            $allProcessData | Group-Object PID | ForEach-Object {
                $first = $_.Group[0]
                [PSCustomObject]@{
                    PID = $first.PID
                    ProcessName = $first.ProcessName
                    User = $first.User
                    AvgCPU = [math]::Round(($_.Group.CPU | Measure-Object -Average).Average, 2)
                    AvgMemoryBytes = [math]::Round(($_.Group.MemoryBytes | Measure-Object -Average).Average, 0)
                }
            }
        } else {
            @()
        }

        return [PSCustomObject]@{
            SystemMetrics = [PSCustomObject]@{
                AvgCPU = $avgCPU
                AvgMemoryPercent = $avgMemoryPercent
                AvgMemoryBytes = $avgMemoryBytes
                TotalMemoryBytes = $totalMemory
            }
            ProcessMetrics = $processSummary
        }

    } catch {
        Write-Log "Error collecting performance metrics: $_" "Error"
        throw
    }
}
#>

# Version 2.0 of Get-PerformanceMetrics function
function Get-PerformanceMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $false)]
        [int]$Samples = 3,
        [Parameter(Mandatory = $false)]
        [int]$Interval = 5
    )

    # Scriptblock to collect static system information
    $staticScriptBlock = {
        $totalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
        $numberOfCores = [Environment]::ProcessorCount
        return @{
            TotalMemory = $totalMemory
            NumberOfCores = $numberOfCores
        }
    }

    # Scriptblock to collect performance samples
    $sampleScriptBlock = {
        param(
            $previousCpuTimes,
            $totalMemory,
            $numberOfCores,
            $previousTimestamp,
            $ownerCache
        )

        # Function to get process owner (cached)
        function Get-ProcessOwner {
            param($ProcessId)
            try {
                $cimProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId"
                return ($cimProcess | Invoke-CimMethod -MethodName GetOwner).User
            } catch {
                return "Unknown"
            }
        }

        # Get system metrics
        $cpuSample = (Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction Stop).CounterSamples.CookedValue
        $available = (Get-Counter -Counter "\Memory\Available Bytes" -ErrorAction Stop).CounterSamples.CookedValue
        $usedMemory = $totalMemory - $available
        $memorySample = [math]::Round(($usedMemory / $totalMemory) * 100, 2)

        # Get processes >1MB working set
        $currentProcesses = Get-Process | Where-Object { $_.Id -ne 0 -and $_.WorkingSet64 -gt 10MB }
        $currentCpuTimes = @{}
        $processData = @()
        $sampleStartTime = [datetime]::Now

        # Calculate actual interval since last sample
        $actualInterval = if ($previousTimestamp) {
            ($sampleStartTime - $previousTimestamp).TotalSeconds
        } else {
            $null
        }

        foreach ($process in $currentProcesses) {
            $processID = $process.Id
            $currentCpu = $process.TotalProcessorTime.TotalSeconds
            $currentCpuTimes[$processID] = $currentCpu

            # CPU usage calculation (requires previous sample)
            $cpuUsage = 0
            if ($previousCpuTimes -and $previousCpuTimes.ContainsKey($processID) -and $actualInterval -gt 0) {
                $cpuDelta = $currentCpu - $previousCpuTimes[$processID]
                $cpuUsage = [math]::Round(($cpuDelta / $actualInterval) * 100 / $numberOfCores, 2)
            }

            # Owner lookup (cached and conditional)
            if (-not $ownerCache.ContainsKey($processID)) {
                if ($process.WorkingSet64 -gt 10MB) {
                    $ownerCache[$processID] = Get-ProcessOwner -ProcessId $processID
                } else {
                    $ownerCache[$processID] = "Unknown"
                }
            }
            $user = $ownerCache[$processID]

            $processData += [PSCustomObject]@{
                SampleTime = $sampleStartTime
                PID = $processID
                ProcessName = $process.ProcessName
                CPU = $cpuUsage
                MemoryBytes = $process.WorkingSet64
                User = $user
            }
        }

        return @{
            CurrentCpuTimes = $currentCpuTimes
            CpuSample = $cpuSample
            MemorySample = $memorySample
            ProcessData = $processData
            SampleStartTime = $sampleStartTime
            OwnerCache = $ownerCache
        }
    }

    try {
        # Get static system information
        $staticResult = Invoke-Command -Session $Session -ScriptBlock $staticScriptBlock
        $totalMemory = $staticResult.TotalMemory
        $numberOfCores = $staticResult.NumberOfCores

        # Initialize collections
        $cpuSamples = @()
        $memorySamples = @()
        $processAggregates = @{}
        $previousCpuTimes = $null
        $previousTimestamp = $null
        $ownerCache = @{}

        # Collect performance samples
        for ($i = 1; $i -le $Samples; $i++) {
            Update-StatusLabel "Collecting sample $i of $Samples with interval $Interval seconds..."

            $sampleResult = Invoke-Command -Session $Session -ScriptBlock $sampleScriptBlock -ArgumentList @(
                $previousCpuTimes,
                $totalMemory,
                $numberOfCores,
                $previousTimestamp,
                $ownerCache
            )

            # Store system metrics
            $cpuSamples += $sampleResult.CpuSample
            $memorySamples += $sampleResult.MemorySample

            # Aggregate process data (skip first sample)
            if ($null -ne $previousTimestamp) {
                foreach ($p in $sampleResult.ProcessData) {
                    $pidKey = $p.PID
                    if (-not $processAggregates.ContainsKey($pidKey)) {
                        $processAggregates[$pidKey] = [PSCustomObject]@{
                            PID = $p.PID
                            ProcessName = $p.ProcessName
                            User = $p.User
                            TotalCPU = 0
                            TotalMemoryBytes = 0
                            SampleCount = 0
                        }
                    }
                    $agg = $processAggregates[$pidKey]
                    $agg.TotalCPU += $p.CPU
                    $agg.TotalMemoryBytes += $p.MemoryBytes
                    $agg.SampleCount++
                }
            }

            # Update for next iteration
            $previousCpuTimes = $sampleResult.CurrentCpuTimes
            $previousTimestamp = $sampleResult.SampleStartTime
            $ownerCache = $sampleResult.OwnerCache

            if ($i -lt $Samples) { Start-Sleep -Seconds $Interval }
        }

        # Calculate system averages
        $avgCPU = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 2)
        $avgMemoryPercent = [math]::Round(($memorySamples | Measure-Object -Average).Average, 2)
        $avgMemoryBytes = [math]::Round(($memorySamples | ForEach-Object { ($_ / 100) * $totalMemory } | Measure-Object -Average).Average, 0)

        # Generate process summary (filter negligible processes)
        $processSummary = $processAggregates.Values | ForEach-Object {
            [PSCustomObject]@{
                PID = $_.PID
                ProcessName = $_.ProcessName
                User = $_.User
                AvgCPU = [math]::Round($_.TotalCPU / $_.SampleCount, 2)
                AvgMemoryBytes = [math]::Round($_.TotalMemoryBytes / $_.SampleCount, 0)
            }
        } | Where-Object { $_.AvgCPU -ge 1 -or $_.AvgMemoryBytes -ge 10MB }

        return [PSCustomObject]@{
            SystemMetrics = [PSCustomObject]@{
                AvgCPU = $avgCPU
                AvgMemoryPercent = $avgMemoryPercent
                AvgMemoryBytes = $avgMemoryBytes
                TotalMemoryBytes = $totalMemory
            }
            ProcessMetrics = $processSummary
        }

    } catch {
        Write-Log "Error collecting performance metrics: $_" "Error"
        Update-StatusLabel -text "Error collecting performance metrics: $_"
        throw
    }
}

# Top CPU Processes Function
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

# Top Memory Processes Function
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
        [object]$SystemMetrics
    )
    
    # Create temp directory if it doesn't exist
    $tempDir = "C:\temp"
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Write-Log "Created temporary directory: $tempDir" "Info"
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
            $output += ("{0}. {1} ({2})`t- {3}%`t- {4}GB ({5}%)`t- {6}" -f $i++,
                ($p.ProcessName).PadRight(15),
                $p.PID,
                ($p.AvgCPU).ToString().PadLeft(5),
                $pMemGB.ToString("0.0"),
                $pMemPercent,
                $p.User)
        }
        
        $output += ("=" * 60)
        $output += "TOP PROCESSES (MEM):"
        $output += ("{0,-30} {1,-15} {2,-15} {3}" -f "Process name (PID)", "CPU", "RAM", "Run as")
        
        $i = 1
        foreach ($p in $TopMemory) {
            $pMemGB = [math]::Round($p.AvgMemoryBytes / 1GB, 1)
            $pMemPercent = [math]::Round(($p.AvgMemoryBytes / $SystemMetrics.TotalMemoryBytes) * 100, 1)
            $output += ("{0}. {1} ({2})`t- {3}%`t- {4}GB ({5}%)`t- {6}" -f $i++,
                ($p.ProcessName).PadRight(15),
                $p.PID,
                ($p.AvgCPU).ToString().PadLeft(5),
                $pMemGB.ToString("0.0"),
                $pMemPercent,
                $p.User)
        }
        
        $output += ("=" * 60)
        
        # Display dashboard to console
        $output | Out-Host
        
        # Export to file
        $timestamp = Get-Date -Format "ddMMyyyy_HHmmss"
        $fileName = "PerformanceDashboard_$($Uptime.ServerName)_${timestamp}.txt"
        $filePath = Join-Path $tempDir $fileName
        
        $output | Out-File -FilePath $filePath -Force
        Write-Log "Performance dashboard exported to $filePath" "Info"
        
        return $filePath
    }
    catch {
        Write-Log "Error generating performance dashboard: $_" "Error"
        throw
    }
}

function Remove-Session {
    try {
        # Check if session exists and is still open before removing it
        if ($session -and $session.State -eq "Open") {
            Remove-PSSession -Session $session
            Write-Log "Session closed successfully"
        }
        else {
            Write-Log "No session to close or session already closed" "Info"
        }
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error closing session: $errorDetails" "Error"
    }

    # Optionally, clean up form resources to free memory
    if ($main_form) {
        $main_form.Dispose()
        Write-Log "Form disposed and cleaned up"
    }
}

function Test-ReportFileCreation {
    [CmdletBinding()]
    param(
        [string]$LogPath = "C:\Temp",
        [string]$TestFile = "test_$(Get-Date -Format 'ddMMyyyy_HHmmss').html"
    )
    
    try {
        Write-Log "Testing log file creation in: $LogPath"
        
        # Resolve full path using .NET methods
        $resolvedPath = [System.IO.Path]::GetFullPath($LogPath)
        $testFilePath = [System.IO.Path]::Combine($resolvedPath, $TestFile)

        # Create directory structure using .NET (faster and more reliable)
        $testDir = [System.IO.Path]::GetDirectoryName($testFilePath)
        if (-not [System.IO.Directory]::Exists($testDir)) {
            [System.IO.Directory]::CreateDirectory($testDir) | Out-Null
        }

        # Generate content with UTC timestamp for consistency
        $utcTimestamp = [System.DateTime]::UtcNow.ToString("o")
        $testContent = "Log creation test: $utcTimestamp"

        # Use FileStream for atomic write operation
        try {
            $stream = [System.IO.File]::OpenWrite($testFilePath)
            $writer = [System.IO.StreamWriter]::new($stream)
            $writer.Write($testContent)
            $writer.Close()
        }
        finally {
            if ($writer) { $writer.Dispose() }
            if ($stream) { $stream.Dispose() }
        }

        # Verify file creation using file attributes (faster than Test-Path)
        $fileInfo = [System.IO.File]::GetAttributes($testFilePath)
        if (($fileInfo -band [System.IO.FileAttributes]::Archive) -eq [System.IO.FileAttributes]::Archive) {
            [System.IO.File]::Delete($testFilePath)
            Write-Log "Log file created and verified successfully: $TestFile"
            return $true
        }

        throw "File verification failed after write operation"
    }
    catch {
        $errorMsg = "Error creating test file: $($_.Exception.Message)"
        Write-Log $errorMsg "Error"
        return $false
    }
}



$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Windows Performance Issue"
$main_form.Size = New-Object System.Drawing.Size(410, 200)
$main_form.StartPosition = "CenterScreen"
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false
$main_form.TopMost = $false  # Keep form on top
$main_form.KeyPreview = $true  # Important: This allows the form to receive key events before controls
$main_form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        $cancelButton.PerformClick()
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $okButton.PerformClick()
    }
})

# Create ToolTip object
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 5000  # Time the tooltip remains visible (in milliseconds)
$toolTip.InitialDelay = 500   # Time before the tooltip appears (in milliseconds)
$toolTip.ReshowDelay = 500    # Time before tooltip reappears if mouse moves away and back
$toolTip.ShowAlways = $true   # Show tooltip even if the form is not active

# Server Name Label 
$labelServerName = New-Object System.Windows.Forms.Label
$labelServerName.Location = New-Object System.Drawing.Point(20, 30)
$labelServerName.Size = New-Object System.Drawing.Size(100, 30)
$labelServerName.Text = "Server Name:"
$labelServerName.Font = New-Object System.Drawing.Font("Arial", 11)
$toolTip.SetToolTip($labelServerName, "Enter the hostname or IP address of the remote server.")

# Server Name TextBox
$textBoxServerName = New-Object System.Windows.Forms.TextBox
$textBoxServerName.Location = New-Object System.Drawing.Point(120, 30)
$textBoxServerName.Size = New-Object System.Drawing.Size(250, 30)
$textBoxServerName.Font = New-Object System.Drawing.Font("Arial", 11)
$textBoxServerName.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $textBoxServerName.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($textBoxServerName.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($textBoxServerName.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($textBoxServerName.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

# OK Button
$okButton = New-Object System.Windows.Forms.Button
#$okButton.Location = New-Object System.Drawing.Point(110, 100)
$okButton.Size = New-Object System.Drawing.Size(80, 30)
$okButton.Text = "OK"
$okButton.Add_Click({
    try {
        $serverName = $textBoxServerName.Text.Trim()

        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter server name.", 
                "Warning", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # Test server availability
        Update-StatusLabel -text "Testing server availability for $serverName..."
        $result = Test-ServerAvailability -serverName $serverName
        if (-not $result.RemotingAvailable) {
            [System.Windows.Forms.MessageBox]::Show(
                "Server '$serverName' is not available for remoting. Details: $($result.ErrorDetails)",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        # Create remote session
        Update-StatusLabel -text "Creating session for $serverName..."
        $session = Get-Session -serverName $serverName
        if ($null -eq $session) {
            [System.Windows.Forms.MessageBox]::Show(
                "Session creation canceled or retry limit reached.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        if (-not (Test-ReportFileCreation)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Cannot proceed - local log file creation failed", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        try {
            # Load the main script for performance issue analysis
            # Collect data using separate functions
            Update-StatusLabel -text "Collecting system uptime for $serverName..."
            $uptime = Get-SystemUptime -ServerName $serverName -Session $session

            Update-StatusLabel -text "Collecting performance metrics for $serverName..."
            $metrics = Get-PerformanceMetrics -Session $session -Samples 3 -Interval 5

            Update-StatusLabel -text "Processing performance data for $serverName..."
            $topCPU = Get-TopCPUProcesses -PerformanceData $metrics -TopCount 5
            $topMemory = Get-TopMemoryProcesses -PerformanceData $metrics -TopCount 5

            # Show performance dashboard
            $dashboardFile = Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $metrics.SystemMetrics
            if ($dashboardFile) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Performance dashboard generated successfully: $dashboardFile",
                    "Success",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to generate performance dashboard.",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }

            $main_form.Close()
            Remove-Session
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
            Write-Log "Error in OK button click event: $_" "Error"
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
        Write-Log "Error in OK button click event: $_" "Error"
        Remove-Session
    }
})

# Exit Button
$cancelButton = New-Object System.Windows.Forms.Button
#$cancelButton.Location = New-Object System.Drawing.Point(210, 100)
$cancelButton.Size = New-Object System.Drawing.Size(80, 30)
$cancelButton.Text = "Cancel"
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({
    $main_form.Close()
    Remove-Session}
)

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, 80)
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), 80)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $false  # Set to false to enable manual sizing
$statusLabel.Size = New-Object System.Drawing.Size(370, 50)  # Width, Height
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$statusLabel.Location = New-Object System.Drawing.Point(20, 110)
$statusLabel.MaximumSize = New-Object System.Drawing.Size(370, 0)  # Set maximum width, 0 height for auto-height
$statusLabel.MinimumSize = New-Object System.Drawing.Size(370, 50)  # Set minimum size
$main_form.Controls.Add($statusLabel)


# Add components to form
$main_form.Controls.Add($labelServerName)
$main_form.Controls.Add($textBoxServerName)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show form
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}