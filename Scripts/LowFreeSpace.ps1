#NOTES
# Name:        LowFreeSpace.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        March 2, 2025
# Major Release History:
# 1.0 - Initial release with disk cleanup and reporting features

#DESCRIPTION
# This script provides a GUI tool to manage low disk space on remote servers by:
# - Cleaning system caches (Windows Update, Installer, SCCM)
# - Compressing IIS logs older than 6 months
# - Generating detailed disk usage reports
# - Identifying large folders when space remains low

#REQUIREMENTS
# - PowerShell 5.1 or later
# - Admin access on target servers
# - Windows Forms assemblies
# - Network connectivity to target servers

#PARAMETERS
# Server name: Remote server to analyze/clean
# Disk name:   Drive letter to process (C: for system cleanup, other letters for analysis)

#FUNCTIONS
# Test-DiskAvailability:      Verifies disk exists on remote server
# Clear-SystemCache:          Cleans various system cache locations
# Compress-IISLogs:          Compresses and archives old IIS logs
# Get-DiskSpaceDetails:      Retrieves disk space information
# Get-LargestFolders:        Identifies largest space consumers
# Export-CDisk-Cleanup-Report: Generates cleanup report
# Get-SecondLevelFolderSizes: Analyzes folder hierarchy
# Export-DataDiskReport:      Creates disk analysis report

#OUTPUTS
# - Detailed cleanup/analysis reports in C:\temp
# - GUI status updates during execution
# - Success/failure messages via MessageBox

#EXAMPLES
# 1. System drive cleanup:
#    Enter server name and C for disk name
#    Script will clean caches and compress logs
#
# 2. Data drive analysis:
#    Enter server name and drive letter
#    Script will analyze space usage

# Load module
#. "$PSScriptRoot/../modules/module.ps1"

# Load Windows Forms Assembly
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
} catch {
    Write-Error "Failed to load Windows Forms assemblies: $_"
    exit 1
}

function Test-ServerAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [string]$serverName
    )
    return (Test-Connection -ComputerName $serverName -Count 1 -Quiet)
}


# Function to attempt to create a session and handle credential failures
function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        # Only call Get-Credential if no credential was provided
        #if ($null -eq $Credential) {
            $Credential = Get-Credential -Message "Enter credentials for $ServerName (Attempt $($retryCount) of $MaxRetries)"
        #}
        if ($null -eq $Credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            if ($retryCount -ge $maxRetries) {
                return $null
            }
        }
    } while ($true)
}

# Function to check if disk exists on the server
function Test-DiskAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )
    try {
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
        return $diskExists
    }
    catch {
        return $false
    }
}

#Test-LogFileCreation
function Test-LogFileCreation {
    [CmdletBinding()]
    param()
    
    try {
        # Define paths
        $logPath = "C:\Temp"
        $testFile = Join-Path $logPath "test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
            return $true
        }
    }
    catch {
        Write-Warning "Failed to create log file: $($_.Exception.Message)"
        return $false
    }
}

# Usage (add after disk cleanup operations):
if (-not (Test-LogFileCreation)) {
    Write-Warning "Cannot proceed - local log file creation failed"
    return
}

<#
# Function to clear user cache
function Clear-UserCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [string[]]$ExcludedProfiles = @("Administrator", "Public", "SVC_DailyChecks", "Duc")
    )
    Write-Host "Starting to clear User Cache"

    $ScriptBlock = {
        param($ExcludedProfiles)
        
        Write-Host "Excluded profiles: $($ExcludedProfiles -join ', ')"

        try {
            $ProfileFolders = Get-ChildItem -Directory -Path 'C:\Users' -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notin $ExcludedProfiles } |
                Select-Object -ExpandProperty Name

            Write-Host "Found profiles to process: $($ProfileFolders -join ', ')"

        foreach ($Folder in $ProfileFolders) {
            $PathsToClean = @(
                "C:\Users\$Folder\AppData\Local\Microsoft\Windows\Temporary Internet Files\",
                "C:\Users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data",
                "C:\Users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage",
                "C:\Users\$Folder\AppData\Local\Temp\",
                "C:\Users\$Folder\AppData\Local\Microsoft\Terminal Server Client\Cache",
                "C:\Users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Cache",
                "C:\Users\$Folder\AppData\Local\Microsoft\Teams",
                "C:\Users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache",
                "C:\Users\$Folder\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage",
                "C:\Users\$Folder\AppData\Local\Microsoft\Windows\InetCache\IE",
                "C:\Users\$Folder\AppData\Local\Microsoft\Windows\WebCache",
                "C:\Users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Code Cache",
                "C:\Users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Service Worker\CacheStorage"
            )

            foreach ($Path in $PathsToClean) {
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    try {
                        # First find and display files to be deleted
                        $filesToDelete = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-0) }
                        
                        foreach ($file in $filesToDelete) {
                            Write-Host "Deleting: $($file.FullName)"
                        }
        
                        # Then delete the files
                        $filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                    }
                    catch [System.UnauthorizedAccessException] {
                        Write-Host "Access denied to $Path"
                    }
                    catch {
                        Write-Host "Error cleaning $Path : $_"
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Failed to process profiles: $_"
    }
}

Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList (,$ExcludedProfiles)
}
#>

# Function to clear system cache
function Clear-SystemCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    $ScriptBlock = {
        # Windows Update cache (older than 5 days)
        try {
            if (Test-Path -Path "C:\Windows\SoftwareDistribution\Download\") {
                Write-Host "Starting to clean Windows Update cache"
                $filesToDelete = Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download" -Recurse -Force |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                
                foreach ($file in $filesToDelete) {
                    Write-Host "Deleting: $($file.FullName)"
                    Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                }
                
                #$filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            } else {
                Write-Host "Windows Update cache path not found"
            }
        } catch {
            Write-Host "Error cleaning Windows Update cache: $_"
        }

        # Windows Installer patch cache (older than 5 days)
        try {
            if (Test-Path -Path "C:\Windows\Installer\$PatchCache$\*") {
                Write-Host "Starting to clean Windows Installer patch cache"
                $filesToDelete = Get-ChildItem -Path "C:\Windows\Installer\$PatchCache$\*" -Recurse -Force |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                
                foreach ($file in $filesToDelete) {
                    Write-Host "Deleting: $($file.FullName)"
                    Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
                }
                
                #$filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            } else {
                Write-Host "Windows Installer patch cache path not found"
            }
        } catch {
            Write-Host "Error cleaning Windows Installer patch cache: $_"
        }

        # SCCM cache (older than 5 days)
        try {
            if (Test-Path -Path "C:\Windows\ccmcache\*") {
                Write-Host "Starting to clean SCCM cache"
                $filesToDelete = Get-ChildItem -Path "C:\Windows\ccmcache\*" -Recurse -Force |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
                
                foreach ($file in $filesToDelete) {
                    Write-Host "Deleting: $($file.FullName)"
                }
                
                $filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            } else {
                Write-Host "SCCM cache path not found"
            }
        } catch {
            Write-Host "Error cleaning SCCM cache: $_"
        }

        # Windows Temp files (older than 5 days)
        try {
            if (Test-Path -Path "C:\Windows\Temp\*") {
            Write-Host "Starting to clean Windows Temp files"
            $filesToDelete = Get-ChildItem -Path "C:\Windows\Temp\*" -Recurse -Force |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) }
            
            foreach ($file in $filesToDelete) {
                Write-Host "Deleting: $($file.FullName)"
                Remove-Item -Path $file.FullName -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            }
            
            #$filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            } else {
            Write-Host "Windows Temp path not found"
            }
        } catch {
            Write-Host "Error cleaning Windows Temp files: $_"
        }

        # Recycle Bin
        try {
            Write-Host "Cleaning Recycle Bin"
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Error cleaning Recycle Bin: $_"
        }
    }

    Invoke-Command -Session $session -ScriptBlock $ScriptBlock
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
    Write-Host "Starting Compress-IISLogs with IISLogPath: $IISLogPath and ArchivePath: $ArchivePath"

    $ScriptBlock = {
        param($IISLogPath, $ArchivePath)

        Write-Host "Remote execution started for Compress-IISLogs"

        # Ensure the archive directory exists
        try {
            if (Test-Path -Path $IISLogPath) {
                Write-Host "IIS log path exists: $IISLogPath"
                $OldLogs = Get-ChildItem -Path "$IISLogPath\*" -Recurse -Force |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-6) }

                Write-Host "Found $($OldLogs.Count) old log(s) to process"

                # Then process the files
                foreach ($Log in $OldLogs) {                    
                    try {
                        $ArchiveFileName = "$ArchivePath\$($Log.Name).zip"
                        Write-Host "Compressing log file: $($Log.FullName) to $ArchiveFileName"
                        Compress-Archive -Path $Log.FullName -DestinationPath $ArchiveFileName -Update -ErrorAction SilentlyContinue
                        Write-Host "Compression successful: $ArchiveFileName"
                        Write-Host "Deleting original log file: $($Log.FullName)"
                        Remove-Item -Path $Log.FullName -Force -Verbose -ErrorAction SilentlyContinue
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

<#
function Invoke-CleanupTool {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )
    
    $ScriptBlock = {
        # Pre-configure all Disk Cleanup categories via Registry
        $cleanupCategories = @(
            "Active Setup Temp Folders",
            "BranchCache",
            "Downloaded Program Files",
            "Internet Cache Files",
            "Memory Dump Files",
            "Offline Pages Files",
            "Old ChkDsk Files",
            "Previous Installations",
            "Recycle Bin",
            "Service Pack Cleanup",
            "Setup Log Files",
            "System error memory dump files",
            "System error minidump files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Update Cleanup",
            "Upgrade Discarded Files",
            "User file versions",
            "Windows Defender",
            "Windows Error Reporting Archive Files",
            "Windows Error Reporting Queue Files",
            "Windows Error Reporting System Archive Files",
            "Windows Error Reporting System Queue Files",
            "Windows ESD installation files",
            "Windows Upgrade Log Files"
        )

        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"

        # Enable all cleanup categories
        foreach ($category in $cleanupCategories) {
            $fullPath = $registryPath + $category
            if (Test-Path $fullPath) {
                Set-ItemProperty -Path $fullPath -Name "StateFlags0001" -Value 2 -ErrorAction SilentlyContinue
            }
        }

        # Run Disk Cleanup with timeout
        Write-Output "Starting disk cleanup on $env:COMPUTERNAME..."
        
        # Start the cleanup process
        $process = cleanmgr /sagerun:1
        
        # Wait for process to complete (30 minutes = 1800 seconds)
        try {
            $process | Wait-Process -Timeout 1800 -ErrorAction Stop
            Write-Output "Cleanup completed successfully"
        }
        catch {
            Write-Output "Cleanup timed out after 30 minutes - force stopping..."
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        finally {
            # Clean up any remaining process references
            if ($process -and -not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        
    }

    # Execute with extended session timeout
    Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ThrottleLimit 1
}
#>

# Function to get disk space on a remote PC
function Get-DiskSpaceDetails {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )

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

# Function to get top 10 largest folders and files
function Get-TopItems {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$path,
        [string[]]$exclude = @(),
        [int]$topN = 10
    )

    $scriptBlock = {
        param($path, $exclude, $topN)
        try {
            # Get all items (files and folders) at the root level
            $rootItems = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Name -notin $exclude }

            $itemSizes = foreach ($item in $rootItems) {
                try {
                    $size = 0
                    if ($item.PSIsContainer) {
                        # Calculate total size of folder contents
                        $size = (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    } else {
                        # File size directly
                        $size = $item.Length
                    }
                    [PSCustomObject]@{
                        Name = $item.Name
                        FullPath = $item.FullName
                        SizeGB = [math]::Round($size / 1GB, 2)
                        IsFolder = $item.PSIsContainer
                    }
                } catch {
                    Write-Warning "Error processing item $($item.FullName): $_"
                    continue
                }
            }

            # Sort by size and get top N items
            $topItems = $itemSizes | Sort-Object SizeGB -Descending | Select-Object -First $topN

            # For each folder in the top items, get its largest sub-items
            $detailedOutput = foreach ($topItem in $topItems) {
                $output = [PSCustomObject]@{
                    Name = $topItem.Name
                    SizeGB = $topItem.SizeGB
                    Type = if ($topItem.IsFolder) { "Folder" } else { "File" }
                    SubItems = $null
                }

                if ($topItem.IsFolder) {
                    $subItems = Get-ChildItem -Path $topItem.FullPath -ErrorAction SilentlyContinue
                    $subItemSizes = foreach ($subItem in $subItems) {
                        $subSize = 0
                        if ($subItem.PSIsContainer) {
                            $subSize = (Get-ChildItem -Path $subItem.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                                       Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                        } else {
                            $subSize = $subItem.Length
                        }
                        [PSCustomObject]@{
                            Name = "+ $($subItem.Name)"
                            SizeMB = [math]::Round($subSize / 1MB, 2)
                            Type = if ($subItem.PSIsContainer) { "Folder" } else { "File" }
                        }
                    }
                    $output.SubItems = $subItemSizes | Sort-Object SizeMB -Descending | Select-Object -First 10
                }
                $output
            }

            return $detailedOutput
        } catch {
            Write-Warning "Error in Get-TopItems script block: $_"
            return @()
        }
    }

    $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
    return $result
}

# Function to export disk report (merged C: cleanup and data disk reports)
function Export-DiskReport {
    param (
        [Parameter(Mandatory)]
        [string]$serverName,
        [Parameter(Mandatory)]
        [string]$diskName,
        [Parameter(Mandatory)]
        [PSObject]$diskInfo,
        [Parameter(Mandatory = $false)]
        [PSObject]$beforeDiskInfo,  # Used for C: cleanup
        [Parameter(Mandatory = $false)]
        [string]$userCacheLog,      # Used for C: cleanup
        [Parameter(Mandatory = $false)]
        [string]$systemCacheLog,    # Used for C: cleanup
        [Parameter(Mandatory = $false)]
        [string]$iisLogCleanupLog,  # Used for C: cleanup
        [Parameter(Mandatory = $false)]
        [array]$topUsers,           # Used for C: cleanup if space still low
        [Parameter(Mandatory = $false)]
        [array]$topRoot,            # Used for C: cleanup if space still low
        [Parameter(Mandatory = $false)]
        [string]$folderSizes        # Used for data disk analysis
    )

    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp" | Out-Null
    }

    # Setup report path with timestamp
    $timestamp = Get-Date -Format "ddMMyyyy-HHmm"
    $reportPath = "C:\temp\LowFreeSpace-$diskName-$serverName-$timestamp.txt"

    # Initialize report content
    $reportContent = @"
-------------------------------------------------------------------------
Server name: $serverName | Date: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
"@

    # Add disk usage information
    if ($diskName -eq "C" -and $beforeDiskInfo -and $diskInfo) {
        # C: drive cleanup report
        $spaceSaved = [math]::Round($diskInfo.FreeSpace - $beforeDiskInfo.FreeSpace, 2)
        $reportContent += @"

Disk usage before cleanup:
Drive C: | Used GB: $($beforeDiskInfo.UsedSpace) | Free GB: $($beforeDiskInfo.FreeSpace) | Total GB: $($beforeDiskInfo.TotalSize) | Free Percentage: $($beforeDiskInfo.FreePercentage)%

Disk usage after cleanup:
Drive C: | Used GB: $($diskInfo.UsedSpace) | Free GB: $($diskInfo.FreeSpace) | Total GB: $($diskInfo.TotalSize) | Free Percentage: $($diskInfo.FreePercentage)%

Space saved: $spaceSaved GB
"@
    } else {
        # Data disk report
        $reportContent += @"

Disk usage:
Drive $($diskName): | Used GB: $($diskInfo.UsedSpace) | Free GB: $($diskInfo.FreeSpace) | Total GB: $($diskInfo.TotalSize) | Free Percentage: $($diskInfo.FreePercentage)%
"@
    }

    # Add detailed sections based on disk type
    if ($diskName -eq "C") {
        # C: drive cleanup details
        $reportContent += @"
#######################################################################
$userCacheLog
#######################################################################
$systemCacheLog
#######################################################################
$iisLogCleanupLog
"@

        # Append top folders if available
        if ($topUsers -and $topUsers.Count -gt 0) {
            $reportContent += "`n#######################################################################"
            $reportContent += "`nTop 5 largest folders in C:\Users:`n"
            $reportContent += ($topUsers | ForEach-Object { " - $($_.Folder): $($_.SizeGB)GB" }) -join "`n"
        }

        if ($topRoot -and $topRoot.Count -gt 0) {
            $reportContent += "`n`nTop 5 largest folders in C:\ (excluding system folders):`n"
            $reportContent += ($topRoot | ForEach-Object { " - $($_.Folder): $($_.SizeGB)GB" }) -join "`n"
        }
    } else {
        # Data disk folder sizes
        $reportContent += @"
#######################################################################
$folderSizes
"@
    }

    # Write report to file
    $reportContent | Out-File -FilePath $reportPath -Force

    # Show message box based on success/failure
    if (Test-Path -Path $reportPath) {
        [System.Windows.Forms.MessageBox]::Show(
            "The report has been exported to $reportPath.", 
            "Information", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
}

# Function to update status label text and recenter it
function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
}

# Create Form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Low Free Space"
$main_form.Size = New-Object System.Drawing.Size(400, 200)
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

# Server Name Label
$labelServerName = New-Object System.Windows.Forms.Label
$labelServerName.Location = New-Object System.Drawing.Point(20, 30)
$labelServerName.Size = New-Object System.Drawing.Size(100, 30)
$labelServerName.Text = "Server Name:"
$labelServerName.Font = New-Object System.Drawing.Font("Arial", 11)

# Disk Name TextBox
$textBoxServerName = New-Object System.Windows.Forms.TextBox
$textBoxServerName.Location = New-Object System.Drawing.Point(120, 30)
$textBoxServerName.Size = New-Object System.Drawing.Size(200, 30)
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
$diskLabel.Text = "Disk Name:"
$diskLabel.Font = New-Object System.Drawing.Font("Arial", 11)

# Disk Name TextBox
$diskTextBox = New-Object System.Windows.Forms.TextBox
$diskTextBox.Location = New-Object System.Drawing.Point(120, 60)
$diskTextBox.Size = New-Object System.Drawing.Size(200, 30)
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
    $diskName = $diskTextBox.Text.ToUpper()
    $serverName = $textBoxServerName.Text
    
    # Validate disk name
    if ([string]::IsNullOrEmpty($diskName) -or [string]::IsNullOrEmpty($serverName))  {
        [System.Windows.Forms.MessageBox]::Show(
        "Please enter server name and disk name.", 
        "Warning", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Warning
)
        return
    }
    
    if (-not (Test-ServerAvailability -serverName $serverName)) {
        [System.Windows.Forms.MessageBox]::Show(
                "Server '$serverName' is not reachable.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        return
    }

    # Create session
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

    # Connect to server
    if (-not (Test-DiskAvailability -session $session -diskName $diskName)) {
        [System.Windows.Forms.MessageBox]::Show(
                "Disk '$diskName' is not available on server '$serverName'.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    if (-not (Test-LogFileCreation)) {
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
            # Show status
            Update-StatusLabel -text "Cleaning C disk. Please wait..."

            # Get disk space before cleanup
            $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

            <#
            $statusLabel.Text = "Cleaning user cache..."
            # Clear user cache
            $clearUserCache = Clear-UserCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String
            #>

            Update-StatusLabel -text "Cleaning system cache..."
            # Clear system cache
            $clearSystemCache = Clear-SystemCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            Update-StatusLabel -text "Compressing IIS logs..."
            # Compress IIS logs
            $clearIISLogs = Compress-IISLogs -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            <#
            $statusLabel.Text = "Running Disk Cleanup Tool..."
            Invoke-CleanupTool -session $session
            #>

            # Get disk space after cleanup
            $After = Get-DiskSpaceDetails -session $session -diskName $diskName
            
            $freePercentageDisk = $After.FreePercentage

            # After cleanup, if free space is still low
            if ($After.FreePercentage -lt 10) {
                Update-StatusLabel -text "Free space still low. Identifying top items..."
                $topItems = Get-TopItems -session $session -path "C:\" -exclude @("Windows", "Program Files", "Program Files (x86)", "ProgramData") -topN 10
            }

            

            [System.Windows.Forms.MessageBox]::Show(
                "Drive $($diskName). Free space is $($freePercentageDisk)%.`nPlease check report for details.", 
                "Information", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

            # Export cleanup report
            #Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs       
            <#Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After `
                -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs `
                -topUsers $topUsers -topRoot $topRoot#>
            
            # Format output for the report
            $formattedOutput = "`nTop 10 largest items on $($diskName):`n"
            foreach ($item in $topItems) {
                $formattedOutput += "- $($item.Name) ($($item.Type)): $($item.SizeGB)GB`n"
                if ($item.SubItems) {
                    foreach ($subItem in $item.SubItems) {
                        $formattedOutput += "  $($subItem.Name) ($($subItem.Type)): $($subItem.SizeMB)MB`n"
                    }
                }
            }
            
            Export-DiskReport -serverName $serverName -diskName "C" `
                -diskInfo $After -beforeDiskInfo $Before `
                -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache `
                -iisLogCleanupLog $clearIISLogs -folderSizes $formattedOutput
        }
        else {
            # Show status
            Update-StatusLabel -text "Getting disk information and top items..."
            $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName
            $topItems = Get-TopItems -session $session -path "$($diskName):\" -topN 10

            $formattedOutput = "`nTop 10 largest items on $($diskName):`n"
            foreach ($item in $topItems) {
                $formattedOutput += "- $($item.Name) ($($item.Type)): $($item.SizeGB)GB`n"
                if ($item.SubItems) {
                    foreach ($subItem in $item.SubItems) {
                        $formattedOutput += "  $($subItem.Name) ($($subItem.Type)): $($subItem.SizeMB)MB`n"
                    }
                }
            }

            $freePercentageDisk = $diskInfo.FreePercentage

            [System.Windows.Forms.MessageBox]::Show(
                "Drive $($diskName). Free space is $($freePercentageDisk)%.`nPlease check report for details.", 
                "Information", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
                            
            # Export report
            #Export-DataDiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes
            Export-DiskReport -serverName $serverName -diskName $diskName `
                -diskInfo $diskInfo -folderSizes $formattedOutput

        }
        # Close session
        Remove-PSSession -Session $session
        $main_form.Close()        
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
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
