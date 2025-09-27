# NOTES
# Name:        PerformanceIssue.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        August 10, 2025

# Release History:
# 1.0 - Author: Duc Le - Initial release with basic functionality to check server availability, collect performance metrics, and display a dashboard.

# DESCRIPTION
# This script creates a Windows Forms application that allows users to enter a server name, the script will then:
# 1. Check if the server is reachable via WinRM, ping, and DNS resolution.
# 2. If reachable, it will create a PowerShell session to the server.
# 3. Collect system uptime and performance metrics (CPU, memory, processes).
# 4. Display the results in a dashboard format.
# 5. Log all actions and errors to a log file.

# REQUIREMENTS
# - PowerShell 5.1 or later
# - Admin privileges to create PowerShell sessions on remote servers
# - Local write permissions to the log directory (default: C:\temp)

# PARAMETERS
# - ADM_Credential: Optional PSCredential object for admin credentials. If not provided, a default user and password will be used for testing.
# - ServerName: Mandatory string parameter for the server name to connect to.

# FUNCTIONS:
# - Write-Log: Logs messages to a specified log file.
# - Get-Session: Creates a PowerShell session to the specified server.
# - Test-ServerAvailability: Tests the availability of the server via WinRM, ping, and DNS resolution.
# - Update-StatusLabel: Updates the status label in the Windows Form.
# - Get-SystemUptime: Retrieves the system uptime from the remote server.
# - Get-PerformanceMetrics: Collects performance metrics from the remote server.
# - Get-TopCPUProcesses: Returns the top CPU-consuming processes.
# - Get-TopMemoryProcesses: Returns the top memory-consuming processes.
# - Show-PerformanceDashboard: Displays the performance dashboard in a Windows Form.
# - Remove-Session: Closes the PowerShell session and cleans up resources.
# - Test-ReportFileCreation: Tests the creation of a report file in the specified log directory.
# - Write-WindowsEventLog: Writes an event log entry to the Windows Event Log.
# - Get-VideoControllers: Retrieves video controller information to determine screen resolution and scaling factors.
# - Get-ProcessOwner: Retrieves the owner of a process by its ID, with caching for performance.

# OUTPUT
# - A Windows Form application that displays the server's uptime, performance metrics, and top processes.
# - A log file in C:\temp directory with all actions and errors.
# - A report file in the same directory with performance metrics and process information.

# EXAMPLE USAGE
# 1. Open PowerShell as Administrator.
# 2. Run the script: .\PerformanceIssue.ps1
# 3. Enter the server name when prompted.
# 4. The script will check server availability, create a session, collect metrics, and display the dashboard.
# 5. The log file will be created in C:\temp with all actions and errors.

Param(
    [Parameter(Mandatory= $false)]
    [System.Management.Automation.PSCredential]$ADM_Credential
)
<#
# Temporary workaround for testing
if (-not $ADM_Credential) {
    $userName = "user1"
    $password = ConvertTo-SecureString "Leduc123" -AsPlainText -Force
    $ADM_Credential = New-Object System.Management.Automation.PSCredential($userName, $password)
}#>

# Get current user
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

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
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "PerformanceIssue-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

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
                    Write-Log "Updating TrustedHosts for $serverName"
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
        $Credential = $ADM_Credential
        try {
            
            $session = New-PSSession -ComputerName $serverName -Credential $Credential -ErrorAction SilentlyContinue
            if ($null -eq $session) {
                Write-Log "Failed to create session for $serverName. Retrying..." "Warning"
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to create session for $serverName. Please check the credentials.",
                    "Warning",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            Update-StatusLabel -text "Session created successfully for $serverName"
            return $session
        } catch {
                $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
                Write-Log "Failed to create session for $ServerName on attempt $retryCount. Error: $errorDetails" "Error"
                Update-StatusLabel -text "Failed to create session for $serverName."
            }
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
        DNSResolvable   = $false
        ErrorDetails     = $null
    }

    try {
        # Test WinRM availability first
        Update-StatusLabel -text "Testing WinRM service on $ServerName."
        Write-Log "Testing WinRM service on $ServerName."
        $null = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        $result.RemotingAvailable = $true
        Update-StatusLabel -text "Server $ServerName is running normally."
        Write-Log "Server $ServerName is running normally."
        return $result
    }
    catch {
        $result.ErrorDetails = "WinRM test failed: $($_.Exception.Message)"
        Update-StatusLabel -text "WinRM service is unavailable on $ServerName."
        Write-Log $result.ErrorDetails "Warning"
    }

    # If WinRM fails, test ping connectivity
    $pingFailed = $true
    try {
        Update-StatusLabel -text "Testing ping for $ServerName"
        Write-Log "Testing ping for $ServerName"
        $reply = Test-Connection -ComputerName $ServerName -Count 1 -ErrorAction Stop

        if ($reply.StatusCode -eq 0) {
            $pingFailed = $false
            $result.PingReachable = $true
            Update-StatusLabel -text "Server $ServerName is ping reachable but WinRM is unavailable. Please check WinRM service on the server and the server may be hung."
            Write-Log "Server $ServerName is ping reachable but WinRM is unavailable. Please check WinRM service on the server and the server may be hung." "Warning"
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
            Update-StatusLabel -text "Trying to resolve DNS name"
            Write-Log "Trying to resolve DNS name"
            $dnsResult = Resolve-DnsName -Name $ServerName -ErrorAction Stop
            if ($dnsResult) {
                $result.DNSResolvable = $true
                $result.ErrorDetails += "; DNS resolution succeeded but ping failed"
                Update-StatusLabel -text "Server $ServerName is offline."
                Write-Log "Server $ServerName is offline." "Warning"
            }
        }
        catch {
            $result.DNSResolvable = $false
            $result.ErrorDetails += "; DNS resolution failed: $($_.Exception.Message)"
            Update-StatusLabel -text "Server name $ServerName cannot be resolved. Please check the server name."
            Write-Log "Server name $ServerName cannot be resolved. Please check the server name." "Warning"
        }
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
        Write-Log "Error writing event log entry: $($result.Error)" "Error"
    }
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

# Vertical padding between objects
$verticalPadding = 7 * $scaleY

# Create ToolTip object
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 5000  # Time the tooltip remains visible (in milliseconds)
$toolTip.InitialDelay = 500   # Time before the tooltip appears (in milliseconds)
$toolTip.ReshowDelay = 500    # Time before tooltip reappears if mouse moves away and back
$toolTip.ShowAlways = $true   # Show tooltip even if the form is not active

# Server Name Label
$labelServerName = New-Object System.Windows.Forms.Label
$labelServerName.Location = New-Object System.Drawing.Point([Math]::Round(20 * $scaleX), [Math]::Round(20 * $scaleY))
$labelServerName.Size = New-Object System.Drawing.Size([Math]::Round(120 * $scaleX), [Math]::Round(30 * $scaleY))
$labelServerName.Text = "Server Name:"
$labelServerName.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY))
$toolTip.SetToolTip($labelServerName, "Enter the hostname or IP address of the remote server to analyze or clean.")

# Disk Name TextBox
$textBoxServerName = New-Object System.Windows.Forms.TextBox
$textBoxServerName.Location = New-Object System.Drawing.Point(($labelServerName.Location.X + $labelServerName.Width), $labelServerName.Location.Y)
$textBoxServerName.Size = New-Object System.Drawing.Size([Math]::Round(250 * $scaleX), $labelServerName.Height)
$textBoxServerName.Font = $labelServerName.Font
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

# Main Form Width Calculation
$mainFormWidth = [Math]::Round(($textBoxServerName.Location.X + $textBoxServerName.Width + 40 * $scaleX))


# Ticket number Label
$ticketNumberLabel = New-Object System.Windows.Forms.Label
$ticketNumberLabel.Location = New-Object System.Drawing.Point($labelServerName.Location.X, ($labelServerName.Location.Y + $labelServerName.Height + $verticalPadding))
$ticketNumberLabel.Size = $labelServerName.Size
$ticketNumberLabel.Text = "Ticket Number:"
$ticketNumberLabel.Font = $labelServerName.Font
$toolTip.SetToolTip($ticketNumberLabel, "Enter the ticket number associated with this operation.")

# Ticket number TextBox
$ticketNumberTextBox = New-Object System.Windows.Forms.TextBox
$ticketNumberTextBox.Location = New-Object System.Drawing.Point($textBoxServerName.Location.X, $ticketNumberLabel.Location.Y)
$ticketNumberTextBox.Size = $textBoxServerName.Size
$ticketNumberTextBox.Font = $textBoxServerName.Font
$ticketNumberTextBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $ticketNumberTextBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($ticketNumberTextBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($ticketNumberTextBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($ticketNumberTextBox.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

# OK Button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))
$okButton.Text = "OK"
$okButton.Add_Click({
    try {
        $serverName = $textBoxServerName.Text.Trim()
        $ticketNumber = $ticketNumberTextBox.Text

        if ([string]::IsNullOrEmpty($serverName) -or [string]::IsNullOrEmpty($ticketNumber)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter server name and ticket number.", 
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
                "Server '$serverName' is not available for remoting.",
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
                "Session creation failed.", 
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
            $metrics = Get-PerformanceMetrics -Session $session -Samples 3 -Interval 2

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
                Update-StatusLabel -text "Completed performance analysis for $serverName."
                Start-Process -FilePath $dashboardFile -ErrorAction SilentlyContinue
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to generate performance dashboard.",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }

            # Write event log entry
            $eventMessage = "User: $CurrentUser`n" + "Ticket Number: $ticketNumber`n" + "Message: Performance analysis completed for $serverName. CPU usage: $($metrics.SystemMetrics.AvgCPU)%. Memory usage: $($metrics.SystemMetrics.AvgMemoryPercent)% ($([math]::Round($metrics.SystemMetrics.AvgMemoryBytes / 1GB, 2)) GB)`n" + "`nTop CPU Processes:`n$($topCPU | Out-String)`nTop Memory Processes:`n$($topMemory | Out-String)"
            Write-WindowsEventLog -LogName "Application" `
                                -Source "PerformanceAnalysisScript" `
                                -EventID 1000 `
                                -EntryType "Information" `
                                -Message $eventMessage `
                                -Session $session

            $main_form.Close()
            Remove-Session
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
            Write-Log "Error during performance analysis: $_" "Error"
            Remove-Session
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
        Write-Log "Error in OK button click event: $_" "Error"
        Remove-Session
    }
})

# Exit Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Size = $okButton.Size
$cancelButton.Text = "Cancel"
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({
    $main_form.Close()
    Remove-Session
}
)

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($mainFormWidth - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, ($ticketNumberLabel.Location.Y + $ticketNumberLabel.Height + $verticalPadding))
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), $okButton.Location.Y)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2  # Center horizontally
$label_y = $cancelButton.Location.Y + $cancelButton.Height + $verticalPadding
$statusLabel.Location = New-Object System.Drawing.Point($label_x, ($label_y + 10))  # Add some vertical padding

# Main Form Length Calculation
$mainFormLength = [Math]::Round($statusLabel.Location.Y + $statusLabel.Height + $verticalPadding + 50*$scaleY)

# Main Form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Windows Performance Issue - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size($mainFormWidth, $mainFormLength)
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

# Add components to form
$main_form.Controls.Add($labelServerName)
$main_form.Controls.Add($textBoxServerName)
$main_form.Controls.Add($ticketNumberLabel)
$main_form.Controls.Add($ticketNumberTextBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)
$main_form.Controls.Add($statusLabel)


# Show form
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}