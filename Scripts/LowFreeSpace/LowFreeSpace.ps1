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
                Update-StatusLabel -text "Session creation canceled or retry limit reached for $serverName"
                return $null
            }
            try {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force #In a non-domain (workgroup) environment, the remote computer’s name or IP must be added to the local computer’s TrustedHosts list
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
        Update-StatusLabel -text "Error checking disk availability for $diskName"
        return $false
    }
}



function Test-ReportFileCreation {
    [CmdletBinding()]
    param(
    [string]$logPath = "C:\Temp",
    [string]$testFile = "test_$(Get-Date -Format 'ddMMyyyy_HHmmss').html"
    )
    
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

# Function to clear system cacheMore actions
function Clear-SystemCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    try {
        Write-Host "Starting to clear system cache"
        $ScriptBlock = {
            # Windows Update cache (older than 5 days)
            try {
                if (Test-Path -Path "C:\Windows\SoftwareDistribution\Download\") {
                    $filesToDelete = Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download" -Recurse -Force |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }

                    if ($filesToDelete.Count -gt 0) {
                        Write-Host "Starting to clean Windows Update cache"
                        foreach ($file in $filesToDelete) {
                            Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                            if ((Test-Path -Path $file.FullName)) {
                                Write-Host "Error deleting Windows Update cache file: $($file.FullName)"
                            }else {
                                Write-Host "Deleted: $($file.FullName)"
                            }
                        }
                    }else {
                        Write-Host "Windows Update cache not found"
                    }   
                }
            } catch {
                Write-Host "Error cleaning Windows Update cache: $_"
            }


            # Windows Installer patch cache (older than 5 days)
            try {
                if (Test-Path -Path "C:\Windows\Installer\$PatchCache$\*") {
                    $filesToDelete = Get-ChildItem -Path "C:\Windows\Installer\$PatchCache$\*" -Recurse -Force |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }

                    if ($filesToDelete.Count -gt 0) {
                        Write-Host "Starting to clean Windows Installer patch cache"
                        foreach ($file in $filesToDelete) {
                            Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                            if ((Test-Path -Path $file.FullName)) {
                                Write-Host "Error deleting Windows Installer patch cache file: $($file.FullName)"
                            }else {
                                Write-Host "Deleted: $($file.FullName)"
                            }
                        }
                    }else {
                        Write-Host "Windows Installer patch cache not found"
                    }                
                }
            } catch {
                Write-Host "Error cleaning Windows Installer patch cache: $_"
            }

            # SCCM cache (older than 5 days)
            try {
                if (Test-Path -Path "C:\Windows\ccmcache\*") {
                    $filesToDelete = Get-ChildItem -Path "C:\Windows\ccmcache\*" -Recurse -Force |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                    if ($filesToDelete.Count -gt 0) {
                        Write-Host "Starting to clean SCCM cache"
                        foreach ($file in $filesToDelete) {
                            Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                            if ((Test-Path -Path $file.FullName)) {
                                Write-Host "Error deleting SCCM cache file: $($file.FullName)"
                            }else {
                                Write-Host "Deleted: $($file.FullName)"
                            }
                        }
                    }else {
                        Write-Host "SCCM cache not found"
                    }
                }
            } catch {
                Write-Host "Error cleaning SCCM cache: $_"
            }

            # Windows Temp files (older than 5 days)
            try {
                if (Test-Path -Path "C:\Windows\Temp\*") {
                    $filesToDelete = Get-ChildItem -Path "C:\Windows\Temp\*" -Recurse -Force |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                    if ($filesToDelete.Count -gt 0) {
                        Write-Host "Starting to clean Windows Temp files"
                        foreach ($file in $filesToDelete) {
                            Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                            if ((Test-Path -Path $file.FullName)) {
                                Write-Host "Error deleting Windows Temp file: $($file.FullName)"
                            }else {
                                Write-Host "Deleted: $($file.FullName)"
                            }
                        }
                    } else {
                        Write-Host "Windows Temp not found"
                    }
                }
            } catch {
                Write-Host "Error cleaning Windows Temp files: $_"
            }

            # Recycle Bin
            try {
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                Write-Host "Recycle Bin cleaned"
            } catch {
                Write-Host "Error cleaning Recycle Bin: $_"
            }
        }
        Invoke-Command -Session $session -ScriptBlock $ScriptBlock
    }
    catch {
        Write-Host "Error clearing system cache: $_" "Error"
    }
}


# Function to compress IIS log files on a remote PC
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

            #Write-Host "Remote execution started for Compress-IISLogs"

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
        Write-Log "Error compressing IIS or removing log files: $_" "Error"
    }
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
        Update-StatusLabel -text "Error getting disk space details for $diskName"
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
        Update-StatusLabel -text "Analyzing top $topN items in $path..."
        $scriptBlock = {
            param($path, $exclude, $topN)
            $ProgressPreference = 'SilentlyContinue'
            $detailedOutput = @()

            try {
                # Cache for folder sizes
                $folderSizeCache = @{}

                # Get immediate children of the path. Example: C:\, D:\, etc.
                $rootItems = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                             Where-Object { $_.Name -notin $exclude }
                
                if (-not $rootItems) {
                    Write-Host "No items found in $path after excluding specified items."
                    return @()
                }

                # Calculate sizes for root items and output to a custom object
                $itemSizes = foreach ($item in $rootItems) {
                    try {
                        # Calculate size for each item
                        $size = if ($item.PSIsContainer) { # If it's a folder, calculate the size of all files within it
                            try {
                                $sizeBytes = (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue |
                                             Where-Object { $_.Name -notin $exclude } |
                                             Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                                $folderSizeCache[$item.FullName] = $sizeBytes
                                $sizeBytes
                            } catch {
                                Write-Host "Error calculating size for folder $($item.FullName): $_"
                                0
                            }
                        } else {
                            $item.Length # If it's a file, just get its length
                        }
                        # Create a custom object with the item name, full path, size in GB, and whether it's a folder
                        [PSCustomObject]@{
                            Name = $item.Name
                            FullPath = $item.FullName
                            SizeGB = [math]::Round($size / 1GB, 2)
                            IsFolder = $item.PSIsContainer
                        }
                    } catch {
                        Write-Host "Error processing item $($item.FullName): $_"
                        continue
                    }
                }

                # Filter out items with size 0 GB
                if (-not $itemSizes) {
                    Write-Host "No valid items found after processing in $path"
                    return @{ Results = $results; Output = @() }
                }

                # Sort and select top items
                $topItems = $itemSizes | Sort-Object SizeGB -Descending | Select-Object -First $topN # Select the top N items based on size
                $processedFolders = 0

                # Prepare the output for each top item
                $detailedOutput = foreach ($topItem in $topItems) {
                    $output = [PSCustomObject]@{
                        Name = $topItem.Name
                        SizeGB = $topItem.SizeGB
                        Type = if ($topItem.IsFolder) { "Folder" } else { "File" }
                        SubItems = @()
                    }

                    if ($topItem.IsFolder) {
                        $processedFolders++
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
                return $detailedOutput
            } catch {
                Write-Host "Error in Get-TopItems script block: $_"
                return @()
            }
        }
        # Execute the script block on the remote session
        $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
        return $result
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Log "Error getting top items for $path': $errorDetails" "Error"
        Update-StatusLabel -text "Error analyzing top items for $path"
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
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()

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
                Update-StatusLabel -text "Cleaning C disk. Please wait..."
                $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

                Update-StatusLabel -text "Cleaning system cache..."
                $clearSystemCache = Clear-SystemCache -session $session -Verbose *>&1 | ForEach-Object {
                    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
                } | Out-String

                Update-StatusLabel -text "Compressing IIS logs..."
                $clearIISLogs = Compress-IISLogs -session $session -Verbose *>&1 | ForEach-Object {
                    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
                } | Out-String

                $After = Get-DiskSpaceDetails -session $session -diskName $diskName
                $freePercentageDisk = $After.FreePercentage
                $topRoot = $null
                $topUsers = $null

                if ($After.FreePercentage -lt 50) {
                    Update-StatusLabel -text "Free space still low. Identifying top items..."
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
                Update-StatusLabel -text "Getting disk information and top items..."
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


# Add components to form
$main_form.Controls.Add($labelServerName)
$main_form.Controls.Add($textBoxServerName)
$main_form.Controls.Add($diskLabel)
$main_form.Controls.Add($diskTextBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show form
#$main_form.ShowDialog()
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}
