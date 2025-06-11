# NOTES
# Name:        LowFreeSpace.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        April 15, 2025
# Release History:
#   1.0 - Initial release with disk cleanup, IIS log compression, and detailed reporting

# DESCRIPTION
# A PowerShell script with a graphical user interface (GUI) designed to manage low disk space on remote Windows servers. It automates disk cleanup and analysis tasks, targeting both system and data drives. Key features include:
# - System cache cleanup: Removes temporary files, Windows Update caches, SCCM caches, Windows Installer patches, and Recycle Bin contents older than 5 days
# - IIS log management: Compresses and archives IIS log files older than 6 months to save space
# - Disk usage analysis: Generates detailed reports on disk space, including free space, used space, and total capacity
# - Large item identification: Detects the top space-consuming folders and files when disk space remains low (<10% free)
# - Remote execution: Supports running cleanup and analysis on remote servers via PowerShell sessions
# - Reporting: Produces HTML reports with before/after cleanup metrics and folder/file size breakdowns

# REQUIREMENTS
# - PowerShell 5.1 or later (compatible with Windows PowerShell; PowerShell Core untested)
# - Administrative credentials for target servers to perform cleanup and access protected areas
# - System.Windows.Forms and System.Drawing assemblies for GUI functionality
# - Network connectivity to target servers (ping and PowerShell remoting enabled)
# - TrustedHosts configuration for non-domain environments (handled automatically by script)
# - Local write permissions for report generation (C:\temp directory)

# PARAMETERS
# - ServerName: The hostname or IP address of the remote server to analyze or clean
# - DiskName: The drive letter to process (e.g., "C" for system drive cleanup, "D" for data drive analysis)

# FUNCTIONS
# - Test-ServerAvailability: Pings the target server to confirm network reachability
# - Get-Session: Creates a PowerShell remoting session with retry logic for credential failures
# - Test-DiskAvailability: Verifies the specified disk exists on the remote server
# - Test-ReportFileCreation: Ensures the local system can create report files in C:\temp
# - Clear-SystemCache: Deletes cached files from Windows Update, SCCM, Installer, Temp, and Recycle Bin
# - Compress-IISLogs: Compresses IIS logs older than 6 months into ZIP archives and removes originals
# - Get-DiskSpaceDetails: Collects disk metrics (free space, used space, total size, free percentage)
# - Get-TopItems: Identifies the top 10 largest folders/files, including subfolder breakdowns
# - Export-DiskReport: Generates an HTML report with disk stats, cleanup logs, and large item details
# - Update-StatusLabel: Dynamically updates the GUI with progress messages
# - Remove-Session: Closes remote sessions and disposes of GUI resources

# OUTPUTS
# - HTML Reports: Saved to C:\temp with filenames like LowFreeSpace-<DiskName>-<ServerName>-<Timestamp>.html
#   - For C: drive: Includes before/after cleanup stats, cleanup logs, and top folder/user details
#   - For other drives: Includes disk usage and top folder/file analysis
# - GUI Updates: Real-time status messages during execution (e.g., "Cleaning system cache...")
# - MessageBox Notifications: Alerts for success, errors, or warnings (e.g., disk not found, session failures)
# - Log File: Execution details logged to C:\temp\LowFreeSpace-log.log for troubleshooting

# EXAMPLES
# 1. System Drive Cleanup:
#    - Input: Server name (e.g., "Server01") and DiskName "C"
#    - Actions: Cleans system caches, compresses IIS logs, generates a report comparing before/after stats
#    - Output: Report with cleanup details and top folders/users if free space remains below 10%
#    - Use Case: Free up space on a system drive with low disk space warnings
#
# 2. Data Drive Analysis:
#    - Input: Server name (e.g., "Server02") and DiskName "D"
#    - Actions: Analyzes disk usage and identifies the top 10 largest folders/files
#    - Output: Report with disk metrics and detailed folder/file size breakdown
#    - Use Case: Investigate space usage on a data drive to plan storage management
#
# 3. Error Handling:
#    - Scenario: Invalid server name or unreachable server
#    - Output: MessageBox with error details (e.g., "Server not reachable") and log entry
#    - Scenario: Non-existent disk
#    - Output: MessageBox indicating disk not found

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing


function Write-Log {
    <#
    .SYNOPSIS
    Write a log message to a specified log file with a timestamp and log level.
    .DESCRIPTION
        This function writes a log message to a dynamically named log file (including date),
        creating the directory if it does not exist. It includes a timestamp and allows specifying the log level.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        The log level (default is "Info"). Other levels include "Warning" and "Error".
    .PARAMETER LogDirectory
        The directory where the log file will be saved. Default is "C:\temp".
    .EXAMPLE
        Write-Log -Message "Disk space check completed."
    #>
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp"
    )

    # Ensure log directory exists
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    # Construct log file path with current date
    $datePart = Get-Date -Format "dd-MM-yyyy"
    $LogPath = Join-Path -Path $LogDirectory -ChildPath ("LowFreeSpace-log-$datePart.log")

    # Create timestamp for log entry
    $timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}


function Test-ServerAvailability {
    <#
    .SYNOPSIS
        Tests the availability of a server for PowerShell remoting and network reachability.
    .DESCRIPTION
        This function checks if a server is reachable via PowerShell remoting (WinRM) and optionally via ICMP ping.
        It returns a PSObject with remoting and ping results, plus error details if applicable.
    .PARAMETER serverName
        The name or IP address of the server to test.
    .EXAMPLE
        $result = Test-ServerAvailability -serverName "Server01"
        if ($result.RemotingAvailable) {
            Write-Log "Server01 is ready for remoting"
        } else {
            Write-Log "Server01 unavailable: $($result.ErrorDetails)"
        }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$serverName
    )

    $result = [PSCustomObject]@{
        RemotingAvailable = $false
        PingReachable = $false
        ErrorDetails = $null
    }

    # Validate server name (basic check for non-empty and valid format)
    if ([string]::IsNullOrWhiteSpace($serverName) -or $serverName -notmatch '^[a-zA-Z0-9\.\-]+$') {
        $result.ErrorDetails = "Invalid server name: '$serverName'"
        Write-Log $result.ErrorDetails "Error"
        return $result
    }

    try {
        Write-Log "Testing WinRM availability for $serverName"
        $wsmanResult = Test-WSMan -ComputerName $serverName -ErrorAction Stop
        if ($wsmanResult) {
            $result.RemotingAvailable = $true
            Write-Log "WinRM service is available on $serverName"
        }
    } catch {
        $result.ErrorDetails = "WinRM test failed: $_"
        Write-Log $result.ErrorDetails "Warning"
    }

    # Fallback to ping if WinRM fails
    if (-not $result.RemotingAvailable) {
        try {
            Write-Log "Testing ping for $serverName"
            $pingResult = Test-Connection -ComputerName $serverName -Count 2 -Quiet -ErrorAction Stop
            $result.PingReachable = $pingResult
            if ($pingResult) {
                Write-Log "Server $serverName is ping reachable but WinRM is unavailable"
            } else {
                Write-Log "Server $serverName is not ping reachable" "Warning"
            }
        } catch {
            $result.ErrorDetails += "; Ping test failed: $_"
            Write-Log "Ping test failed for $serverName': $_" "Warning"
        }
    }

    return $result
}

function Get-Session {
    <#
    .SYNOPSIS
        Creates a PowerShell session to a remote server with retry logic for credential failures.
    .DESCRIPTION
        This function attempts to create a PowerShell session to a specified server.
        It prompts for credentials and retries up to a maximum number of attempts if the session creation fails.
    .PARAMETER serverName
        The name or IP address of the server to connect to.
    .PARAMETER Credential
        The credentials to use for the session. If not provided, it will prompt for credentials.
    .EXAMPLE
        $session = Get-Session -serverName "Server01"
        This will create a session to "Server01", prompting for credentials if necessary.
        If the session creation fails, it will retry up to 3 times before giving up.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    $retryCount = 0
    $maxRetries = 3
    try {
        do {
            Write-Log "Attempting to create session for $serverName (Attempt $($retryCount + 1) of $maxRetries)"
            $retryCount++
            $Credential = Get-Credential -Message "Enter credentials for $ServerName (Attempt $($retryCount) of $MaxRetries)"
            if ($null -eq $Credential -or $retryCount -ge $maxRetries) {
                Write-Log "Session creation canceled or retry limit reached for $serverName" "Error"
                Update-StatusLabel -text "Session creation canceled or retry limit reached for $serverName" -percentComplete 0
                return $null
            }
            try {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force #In a non-domain (workgroup) environment, the remote computer’s name or IP must be added to the local computer’s TrustedHosts list
                $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
                Write-Log "Session created successfully for $serverName"
                Update-StatusLabel -text "Session created successfully for $serverName" -percentComplete 100
                return $session
            } catch {
                if ($retryCount -ge $maxRetries) {
                    Write-Log "Failed to create session for $serverName after $maxRetries attempts: $_" "Error"
                    Update-StatusLabel -text "Failed to create session for $serverName after $maxRetries attempts." -percentComplete 0
                    return $null
                }else {
                    $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
                    Write-Log "Failed to create session for $ServerName on attempt $retryCount. Error: $errorDetails" "Error"
                    Update-StatusLabel -text "Failed to create session for $serverName." -percentComplete 0
                }
            }
        } while ($true)
    }
    catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error creating session for $serverName': $errorDetails" "Error"
        Update-StatusLabel -text "Error creating session for $serverName" -percentComplete 0
        return $null
    }
}


function Test-DiskAvailability {
    <#
    .SYNOPSIS
        Tests the availability of a specified disk on a remote server.
    .DESCRIPTION
        This function checks if a specified disk exists on a remote server by querying the PowerShell drives.
        It returns true if the disk is available, otherwise false.
    .PARAMETER session
        The PowerShell session to the remote server.
    .PARAMETER diskName
        The name of the disk to check (e.g., "C", "D").
    .EXAMPLE
        $session = Get-Session -serverName "Server01"
        $diskAvailable = Test-DiskAvailability -session $session -diskName "C"
        if ($diskAvailable) {
            Write-Log "Disk C is available on Server01"
        } else {
            Write-Log "Disk C is not available on Server01" "Error"
        }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )
    try {
        Write-Log "Checking disk availability for disk $diskName"
        $diskExists = Invoke-Command -Session $session -ScriptBlock {
            param($diskName)
            
            $disk = Get-PSDrive -Name $diskName -ErrorAction SilentlyContinue
            if ($null -eq $disk) {
                return $false
            }
            else {
                return $true
            }
        } -ArgumentList $diskName -ErrorAction SilentlyContinue
        if ($diskExists) {
            Write-Log "Disk $diskName is available"
        } else {
            Write-Log "Disk $diskName is not available" "Error"
        }
        return $diskExists
    }
    catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error checking disk availability for $diskName': $errorDetails" "Error"
        Update-StatusLabel -text "Error checking disk availability for $diskName" -percentComplete 0
        return $false
    }
}



function Test-ReportFileCreation {
    <#
    .SYNOPSIS
        Tests the creation of a log file in a specified directory.
    .DESCRIPTION
        This function attempts to create a log file in a specified directory and verifies its creation.
        It returns true if the file is created successfully, otherwise false.
    .PARAMETER logPath
        The path where the log file will be created. Default is "C:\Temp".
    .PARAMETER testFile
        The name of the test log file to create. Default is "test_<timestamp>.html".
    .EXAMPLE
        $logCreated = Test-ReportFileCreation -logPath "C:\Temp"
        if ($logCreated) {
            Write-Log "Log file created successfully."
        } else {
            Write-Log "Log file creation failed." "Error"
        }
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing log file creation"
        # Define paths
        $logPath = "C:\Temp"
        $testFile = Join-Path $logPath "test_$(Get-Date -Format 'ddMMyyyy_HHmmss').html"

        # Create directory if needed
        if (-not (Test-Path $logPath)) {
            New-Item -Path $logPath -ItemType Directory -Force | Out-Null
        }

        # Test file creation
        $testContent = "Log creation test: $(Get-Date)"
        Set-Content -Path $testFile -Value $testContent -ErrorAction Stop

        # Verify and cleanup
        if (Test-Path $testFile) {
            Remove-Item -Path $testFile -Force
            Write-Log "Log file created and verified successfully: $testFile"
            return $true
        }
    }
    catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error creating test log file: $errorDetails" "Error"
        return $false
    }
}

function Clear-SystemCache {
    <#
    .SYNOPSIS
        Clears system cache on a remote server.
    .DESCRIPTION
        This function removes cached files from various system locations on a remote server.
        It targets Windows Update cache, Windows Installer patch cache, SCCM cache, Windows Temp files, and Recycle Bin.
        Files older than 5 days are deleted to free up space. Status updates are throttled to every 1% progress to reduce CPU usage.
    .PARAMETER session
        The PowerShell session to the remote server where the cache will be cleared.
    .EXAMPLE
        $session = Get-Session -serverName "Server01"
        Clear-SystemCache -session $session
        This will clear the system cache on Server01, removing old cached files and cleaning up temporary directories.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    try {
        Write-Log "Starting to clear system cache"
        Update-StatusLabel -text "Starting system cache cleanup..." -percentComplete 0
        $ScriptBlock = {
            param($ProgressPreference)
            $ProgressPreference = 'SilentlyContinue'

            $cachePaths = @(
                @{ Path = "C:\Windows\SoftwareDistribution\Download"; Name = "Windows Update cache" },
                @{ Path = "C:\Windows\Installer\$PatchCache$"; Name = "Windows Installer patch cache" },
                @{ Path = "C:\Windows\ccmcache"; Name = "SCCM cache" },
                @{ Path = "C:\Windows\Temp"; Name = "Windows Temp files" }
            )

            $results = @()
            $totalCaches = $cachePaths.Count + 1 # +1 for Recycle Bin
            $processedCaches = 0

            foreach ($cache in $cachePaths) {
                $processedCaches++
                $percentComplete = [math]::Round(($processedCaches / $totalCaches) * 100, 2)
                $results += "Starting cleanup of $($cache.Name) ($percentComplete% complete)"

                try {
                    if (Test-Path -Path "$($cache.Path)\*") {
                        $filesToDelete = Get-ChildItem -Path "$($cache.Path)\*" -Recurse -Force |
                            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                        $totalFiles = $filesToDelete.Count
                        $processedFiles = 0

                        if ($totalFiles -gt 0) {
                            foreach ($file in $filesToDelete) {
                                $processedFiles++
                                $filePercent = [math]::Round(($processedFiles / $totalFiles) * 100, 2)
                                $overallPercent = [math]::Round(($processedCaches - 1) / $totalCaches * 100 + ($filePercent / $totalCaches), 2)
                                try {
                                    Remove-Item -Path $file.FullName -Force -Recurse -ErrorAction SilentlyContinue
                                    if (-not (Test-Path -Path $file.FullName)) {
                                        $results += "Deleted: $($file.FullName). Overall progress: $overallPercent% complete"
                                    } else {
                                        $results += "Error deleting $($file.FullName): File may be in use"
                                    }
                                } catch {
                                    $results += "Error deleting $($file.FullName): $_"
                                }
                            }
                        } else {
                            $results += "$($cache.Name) not found or no files older than 5 days"
                        }
                    } else {
                        $results += "$($cache.Name) path not found: $($cache.Path)"
                    }
                } catch {
                    $results += "Error cleaning $($cache.Name): $_"
                }
            }

            # Recycle Bin
            try {
                $processedCaches++
                $percentComplete = [math]::Round(($processedCaches / $totalCaches) * 100, 2)
                $results += "Cleaning Recycle Bin ($percentComplete% complete)"
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                $results += "Recycle Bin cleaned"
            } catch {
                $results += "Error cleaning Recycle Bin: $_"
            }

            return $results
        }

        $lastPercentComplete = -1  # Initialize to -1 to ensure first update
        $lastStatusText = ""

        $clearSystemCache = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ProgressPreference
        foreach ($line in $clearSystemCache) {
            $currentPercentComplete = $lastPercentComplete
            if ($line -match "\((\d+\.\d+)% complete\)") {
                $currentPercentComplete = [math]::Round($Matches[1], 2)
                $lastStatusText = $line
            } else {
                $lastStatusText = $line
            }

            # Update status label only if percent complete has increased by at least 1%
            if ($currentPercentComplete -ge $lastPercentComplete + 1 -or $lastPercentComplete -eq -1) {
                Update-StatusLabel -text $lastStatusText -percentComplete $currentPercentComplete
                $lastPercentComplete = $currentPercentComplete
            }
            Write-Log $line "Info"
        }
        Update-StatusLabel -text "System cache cleanup completed" -percentComplete 100
        Write-Log "System cache cleanup completed successfully"
        return $clearSystemCache | Out-String
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error clearing system cache: $errorDetails" "Error"
        Update-StatusLabel -text "Error during system cache cleanup" -percentComplete 0
        return "Error clearing system cache: $_"
    }
}


function Compress-IISLogs {
    <#
    .SYNOPSIS
        Compresses IIS log files older than 6 months and removes the original files.
    .DESCRIPTION
        This function compresses IIS log files that are older than 6 months into ZIP archives.
        It moves the compressed files to a specified archive directory and removes the original log files.
    .PARAMETER session
        The PowerShell session to the remote server where IIS logs will be compressed.
    .PARAMETER IISLogPath
        The path to the IIS log files. Default is "C:\inetpub\logs\LogFiles".
    .PARAMETER ArchivePath
        The path where the compressed log files will be stored. Default is "C:\inetpub\logs\Archive".
    .EXAMPLE
        $session = Get-Session -serverName "Server01"
        Compress-IISLogs -session $session
        This will compress IIS log files older than 6 months on Server01 and move them to the archive directory.
    #>
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
                Write-Host "Error processing IIS logs: $_"
            }
        }
        
        Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $IISLogPath, $ArchivePath
    }
    catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error compressing IIS logs: $errorDetails" "Error"
        Update-StatusLabel -text "Error compressing IIS logs" -percentComplete 0}
}



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
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error getting disk space details for $diskName': $errorDetails" "Error"
        Update-StatusLabel -text "Error getting disk space details for $diskName" -percentComplete 0
        return $null
    }
}

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
        Write-Log "Starting top $topN items analysis for $path"
        Update-StatusLabel -text "Analyzing top items in $path..." -percentComplete 0
        $scriptBlock = {
            param($path, $exclude, $topN)
            $ProgressPreference = 'SilentlyContinue'
            $results = @()

            try {
                # Validate path
                if (-not (Test-Path $path)) {
                    $results += "Path $path does not exist."
                    Write-Host "Path $path does not exist."
                    return @{ Results = $results; Output = @() }
                }

                # Cache for folder sizes
                $folderSizeCache = @{}
                $results += "Starting size calculation for items in $path"

                # Get immediate children of the path
                $rootItems = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                             Where-Object { $_.Name -notin $exclude }
                $totalItems = $rootItems.Count
                if ($totalItems -eq 0) {
                    $results += "No items found in $path after applying exclusions: $($exclude -join ', ')"
                    Write-Host "No items found in $path after applying exclusions: $($exclude -join ', ')"
                    return @{ Results = $results; Output = @() }
                }

                $results += "Found $totalItems items in $path"
                $processedItems = 0
                $updateInterval = [math]::Max(1, [math]::Ceiling($totalItems / 10)) # Update every ~10% of items

                # Calculate sizes for root items
                $itemSizes = foreach ($item in $rootItems) {
                    $processedItems++
                    if ($processedItems % $updateInterval -eq 0 -or $processedItems -eq $totalItems) {
                        $percentComplete = [math]::Round(($processedItems / $totalItems) * 100, 2)
                        $results += "Processed $processedItems of $totalItems items in $path ($percentComplete% complete)"
                    }
                    try {
                        $size = if ($item.PSIsContainer) {
                            try {
                                $sizeBytes = (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                                             Where-Object { $_.Name -notin $exclude } |
                                             Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                                $folderSizeCache[$item.FullName] = $sizeBytes
                                $sizeBytes
                            } catch {
                                $results += "Error calculating size for folder $($item.FullName): $_"
                                Write-Host "Error calculating size for folder $($item.FullName): $_"
                                0
                            }
                        } else {
                            $item.Length
                        }
                        [PSCustomObject]@{
                            Name = $item.Name
                            FullPath = $item.FullName
                            SizeGB = [math]::Round($size / 1GB, 2)
                            IsFolder = $item.PSIsContainer
                        }
                    } catch {
                        $results += "Error processing item $($item.FullName): $_"
                        Write-Host "Error processing item $($item.FullName): $_"
                        continue
                    }
                }

                if (-not $itemSizes) {
                    $results += "No valid items found after processing in $path"
                    Write-Host "No valid items found after processing in $path"
                    return @{ Results = $results; Output = @() }
                }

                $topItems = $itemSizes | Sort-Object SizeGB -Descending | Select-Object -First $topN
                $processedFolders = 0
                $totalFolders = ($topItems | Where-Object { $_.IsFolder }).Count
                $results += "Analyzing sub-items for $totalFolders folders"

                $detailedOutput = foreach ($topItem in $topItems) {
                    $output = [PSCustomObject]@{
                        Name = $topItem.Name
                        SizeGB = $topItem.SizeGB
                        Type = if ($topItem.IsFolder) { "Folder" } else { "File" }
                        SubItems = @()
                    }

                    if ($topItem.IsFolder) {
                        $processedFolders++
                        $percentComplete = if ($totalFolders -gt 0) {
                            [math]::Round(($processedFolders / $totalFolders) * 100, 2)
                        } else {
                            100
                        }
                        $results += "Processing folder $processedFolders of $totalFolders in $($topItem.FullName) ($percentComplete% complete)"
                        try {
                            $subItems = Get-ChildItem -Path $topItem.FullPath -ErrorAction SilentlyContinue |
                                       Where-Object { $_.Name -notin $exclude }
                            $subItemSizes = foreach ($subItem in $subItems) {
                                try {
                                    $subSize = if ($subItem.PSIsContainer) {
                                        if ($folderSizeCache.ContainsKey($subItem.FullName)) {
                                            $folderSizeCache[$subItem.FullName]
                                        } else {
                                            (Get-ChildItem -Path $subItem.FullName -Recurse -File -ErrorAction SilentlyContinue |
                                             Where-Object { $_.Name -notin $exclude } |
                                             Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                                        }
                                    } else {
                                        $subItem.Length
                                    }
                                    [PSCustomObject]@{
                                        Name = $subItem.Name
                                        SizeMB = [math]::Round($subSize / 1MB, 2)
                                        Type = if ($subItem.PSIsContainer) { "Folder" } else { "File" }
                                    }
                                } catch {
                                    $results += "Error processing sub-item $($subItem.FullName): $_"
                                    Write-Host "Error processing sub-item $($subItem.FullName): $_"
                                    continue
                                }
                            }
                            $output.SubItems = $subItemSizes | Sort-Object SizeMB -Descending | Select-Object -First 10
                        } catch {
                            $results += "Error processing sub-items for $($topItem.FullName): $_"
                            Write-Host "Error processing sub-items for $($topItem.FullName): $_"
                        }
                    }
                    $output
                }

                return @{ Results = $results; Output = $detailedOutput }
            } catch {
                $results += "Error in Get-TopItems script block: $_"
                Write-Host "Error in Get-TopItems script block: $_"
                return @{ Results = $results; Output = @() }
            }
        }

        $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
        foreach ($line in $result.Results) {
            if ($line -match "\((\d+\.\d+)% complete\)") {
                $percent = [math]::Round($Matches[1], 2)
                Update-StatusLabel -text $line -percentComplete $percent
                Write-Log $line "Info"
            } else {
                Update-StatusLabel -text $line
                Write-Log $line "Info"
            }
        }
        if (-not $result.Output) {
            Write-Log "No output returned from Get-TopItems for $path" "Warning"
            Update-StatusLabel -text "No items found for $path" -percentComplete 0
        } else {
            Update-StatusLabel -text "Top items analysis completed for $path" -percentComplete 100
            Write-Log "Top items analysis completed successfully for $path"
        }
        return $result.Output
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error getting top items for $path': $errorDetails" "Error"
        Update-StatusLabel -text "Error analyzing top items for $path" -percentComplete 0
        return @()
    }
}

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
        Write-Log "Exporting disk report for $diskName on $serverName"
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

        if (Test-Path -Path $reportPath) {
            Write-Log "Disk report exported successfully to $reportPath"
            [System.Windows.Forms.MessageBox]::Show(
                "The report has been exported to $reportPath.", 
                "Information", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } else {
            $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
            Write-Log "Failed to export disk report: $errorDetails" "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export the report. Please check the log file for details.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error exporting disk report for $diskName on $serverName': $errorDetails" "Error"
    }
}



function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text,
        [Parameter(Mandatory=$false)]
        [int]$percentComplete = -1
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    
    if ($percentComplete -ge 0 -and $percentComplete -le 100) {
        $progressBar.Value = $percentComplete
    }
    $main_form.Refresh() # Ensure immediate update
}
function Remove-Session {
    <#
    .SYNOPSIS
        Removes the PowerShell session and cleans up resources.
    .DESCRIPTION
        This function closes the PowerShell session if it exists and is still open.
        It also disposes of the main form to free up resources.
    .PARAMETER session
        The PowerShell session to remove.
    .EXAMPLE
        Remove-Session -session $session
        This will close the PowerShell session and dispose of the main form if it exists.
    #>
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


$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Low Free Space"
$main_form.Size = New-Object System.Drawing.Size(410, 250)
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
$toolTip.SetToolTip($labelServerName, "Enter the hostname or IP address of the remote server to analyze or clean.")

# Disk Name TextBox
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

# Disk Name Label
$diskLabel = New-Object System.Windows.Forms.Label
$diskLabel.Location = New-Object System.Drawing.Point(20, 60)
$diskLabel.Size = New-Object System.Drawing.Size(100, 30)
$diskLabel.Text = "Drive Letter:"
$diskLabel.Font = New-Object System.Drawing.Font("Arial", 11)
$toolTip.SetToolTip($diskLabel, "Enter the drive letter to process (e.g., C or C: or C:\).")

# Disk Name TextBox
$diskTextBox = New-Object System.Windows.Forms.TextBox
$diskTextBox.Location = New-Object System.Drawing.Point(120, 60)
$diskTextBox.Size = New-Object System.Drawing.Size(250, 30)
$diskTextBox.Font = New-Object System.Drawing.Font("Arial", 11)
$diskTextBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $diskTextBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($diskTextBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($diskTextBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($diskTextBox.Text)
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
        # Normalize disk name input
        if ($diskTextBox.Text -eq $diskTextBox.Tag) {
            $diskTextBox.Text = ""
        }
        if ($textBoxServerName.Text -eq $textBoxServerName.Tag) {
            $textBoxServerName.Text = ""
        }
        $rawDiskName = $diskTextBox.Text.Trim()
        $diskName = $rawDiskName -replace '[:\\]', ''
        $diskName = $diskName.ToUpper()
        $serverName = $textBoxServerName.Text.Trim()

        if ([string]::IsNullOrEmpty($diskName) -or [string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter server name and disk name.", 
                "Warning", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

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

        if (-not (Test-DiskAvailability -session $session -diskName $diskName)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Disk '$diskName' is not available on server '$serverName'.", 
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
            if ($diskName -eq "C") {
                Update-StatusLabel -text "Cleaning C disk. Please wait..." -percentComplete 0
                $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

                Update-StatusLabel -text "Cleaning system cache..." -percentComplete 0
                $clearSystemCache = Clear-SystemCache -session $session

                Update-StatusLabel -text "Compressing IIS logs..." -percentComplete 0
                $clearIISLogs = Compress-IISLogs -session $session | Out-String

                $After = Get-DiskSpaceDetails -session $session -diskName $diskName
                $freePercentageDisk = $After.FreePercentage
                $topRoot = $null
                $topUsers = $null

                if ($After.FreePercentage -lt 50) {
                    Update-StatusLabel -text "Free space still low. Identifying top items..." -percentComplete 0
                    $topRoot = Get-TopItems -session $session -path "$($diskName):\" -exclude @("Windows", "Program Files", "Program Files (x86)", "ProgramData","Users") -topN 10
                    $topUsers = Get-TopItems -session $session -path "$($diskName):\Users" -topN 10
                }

                [System.Windows.Forms.MessageBox]::Show(
                    "Drive $($diskName). Free space is $($freePercentageDisk)%.`nPlease check report for details.", 
                    "Information", 
                    [System.Windows.Forms.MessageBoxButtons]::OK, 
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )

                Export-DiskReport -serverName $serverName -diskName $diskName `
                    -diskInfo $After -beforeDiskInfo $Before `
                    -systemCacheLog $clearSystemCache `
                    -iisLogCleanupLog $clearIISLogs `
                    -topUsers $topUsers -topRoot $topRoot
            } else {
                Update-StatusLabel -text "Getting disk information and top items..." -percentComplete 0
                $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName
                $topItems = Get-TopItems -session $session -path "$($diskName):\" -topN 10

                $freePercentageDisk = $diskInfo.FreePercentage

                [System.Windows.Forms.MessageBox]::Show(
                    "Drive $($diskName). Free space is $($freePercentageDisk)%.`nPlease check report for details.", 
                    "Information", 
                    [System.Windows.Forms.MessageBoxButtons]::OK, 
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )

                Export-DiskReport -serverName $serverName -diskName $diskName `
                    -diskInfo $diskInfo -topItems $topItems
            }
            $main_form.Close()
            Remove-Session
        } catch {
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
    Remove-Session
}
)

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, 100)
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), 100)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2  # Center horizontally
$label_y = 135  # Top padding
$statusLabel.Location = New-Object System.Drawing.Point($label_x, $label_y)
$main_form.Controls.Add($statusLabel)

# ProgressBar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 135)
$progressBar.Size = New-Object System.Drawing.Size(350, 20)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0
# Adjust Status Label position to avoid overlap
$statusLabel.Location = New-Object System.Drawing.Point($label_x, 160) # Moved below progress bar

# Add components to form
$main_form.Controls.Add($labelServerName)
$main_form.Controls.Add($textBoxServerName)
$main_form.Controls.Add($diskLabel)
$main_form.Controls.Add($diskTextBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)
$main_form.Controls.Add($progressBar)

# Show form
#$main_form.ShowDialog()
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}
