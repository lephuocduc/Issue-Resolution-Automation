#NOTES
# Name:   LowFreeSpace.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION
# This script is designed to manage low disk space on remote servers. It includes functions to clear user and system caches, compress IIS logs, and generate detailed reports on disk usage.

#REQUIREMENT
# Requires the necessary permissions to access and modify files on the target servers.

#INPUTS
# Server name and disk name to perform cleanup actions on.
# Disk C: - Clear user and system caches, compress IIS logs, and generate a detailed report.
# Data disk - Provide information on disk usage and the sizes of items within each first-level folder.

#OUTPUTS
# Generates a report detailing the disk usage before and after cleanup, including space saved and logs of actions taken.

#EXAMPLE
# Run the script and enter the server name and disk name to start the cleanup process.
# The script will prompt for confirmation before executing the cleanup actions.
# If disk C is selected, it will clear user and system caches, compress IIS logs, and generate a detailed report.
# If a data disk is selected, it will provide information on disk usage and the sizes of items within each first-level folder.
# A report will be exported to the local machine for further analysis. 


# Load module
. "$PSScriptRoot/../modules/module.ps1"

# Load Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

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
                }
                
                $filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
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
                }
                
                $filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
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
            }
            
            $filesToDelete | Remove-Item -Force -Recurse -Verbose -ErrorAction SilentlyContinue
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
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-0) }

                Write-Host "Found $($OldLogs.Count) old log(s) to process"

                # First display all files to be processed
                foreach ($Log in $OldLogs) {
                    Write-Host "Processing: $($Log.FullName)"
                    Write-Host "  - Will compress to: $ArchivePath\$($Log.Name).zip"
                    Write-Host "  - Will delete original after compression"
                }

                # Then process the files
                foreach ($Log in $OldLogs) {
                    $ArchiveFileName = "$ArchivePath\$($Log.Name).zip"
                    Write-Host "Processing $($Log.FullName)"
                    try {
                        Compress-Archive -Path $Log.FullName -DestinationPath $ArchiveFileName -Update -ErrorAction SilentlyContinue
                        Write-Host "Compression successful: $ArchiveFileName"
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
        $usedPercentage = [math]::Round(($drive.Used / ($drive.Free + $drive.Used)) * 100, 2)

        return [PSCustomObject]@{
            UsedSpace = [math]::Round(($drive.Used / 1GB), 2)
            FreeSpace = $freeSpace
            TotalSize = $totalSize
            UsedPercentage = $usedPercentage
        }
    } -ArgumentList $diskName

    return $diskDetails
}

# Function to export cleanup report
function Export-CDisk-Cleanup-Report {
    param (
        [Parameter(Mandatory)]
        [string]$serverName,
        [Parameter(Mandatory)]
        [PSObject]$Before,
        [Parameter(Mandatory)]
        [PSObject]$After,
        [string]$userCacheLog,
        [string]$systemCacheLog,
        [string]$iisLogCleanupLog
    )
    
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp" 
    }

    $timestamp = Get-Date -Format "ddMMyyyy-HHmm"
    $LogFilePath = "C:\temp\LowFreeSpace-C-Disk-$serverName-$timestamp.txt"

    $SpaceSaved = $After.FreeSpace - $Before.FreeSpace
    
    $Report = @"
-------------------------------------------------------------------------
Server name: $serverName | Date: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
-------------------------------------------------------------------------
Disk usage before cleanup:
Drive C: | Used GB: $($Before.UsedSpace) | Free GB: $($Before.FreeSpace) | Total GB: $($Before.TotalSize) | Used Percentage: $($Before.UsedPercentage)%
-------------------------------------------------------------------------
Disk usage after cleanup:
Drive C: | Used GB: $($After.UsedSpace) | Free GB: $($After.FreeSpace) | Total GB: $($After.TotalSize) | Used Percentage: $($After.UsedPercentage)%
-------------------------------------------------------------------------
Space saved: $SpaceSaved GB
#######################################################################
$userCacheLog
#######################################################################
$systemCacheLog
#######################################################################
$iisLogCleanupLog
"@

    $Report | Out-File -FilePath $LogFilePath -Force

    if (Test-Path -Path $LogFilePath) {
        [System.Windows.Forms.MessageBox]::Show(
            "The report has been exported to $LogFilePath.", 
            "Information", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    else {
        [System.Windows.Forms.MessageBox]::Show(
                "Error when exporting.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
    }
}


# Function to list and sort sizes of items (both folders and files) within each first-level folder
function Get-SecondLevelFolderSizes {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )
    $folderStructure = Invoke-Command -Session $session -ScriptBlock {
        param($diskName)
        $firstLevelFolders = Get-ChildItem -Path "$($diskName):\" -Directory -ErrorAction SilentlyContinue
        $result = @()

        foreach ($folder in $firstLevelFolders) {
            $items = Get-ChildItem -Path $folder.FullName -ErrorAction SilentlyContinue
            $folderDetails = @()
            foreach ($item in $items) {
                $size = 0
                if ($item.PSIsContainer) {
                    $size = (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                } else {
                    $size = $item.Length
                }
                $folderDetails += [PSCustomObject]@{
                    Name = "++ $($item.Name)"
                    Size = [math]::Round($size / 1MB, 2)
                }
            }
            $folderDetails = $folderDetails | Sort-Object Size -Descending | Select-Object -First 10
            $result += [PSCustomObject]@{
                FolderName = $folder.Name
                Items = $folderDetails
            }
        }
        return $result
    } -ArgumentList $diskName
    
    $output = "Folder structure for ${diskName}:`n"
    foreach ($folder in $folderStructure) {
        $output += "- $($folder.FolderName)`n"
        foreach ($item in $folder.Items) {
            $output += "  $($item.Name): $($item.Size)MB`n"
        }
    }
    return $output
}

# Function to export data disk report
function Export-DataDiskReport {
    param(
        [Parameter(Mandatory=$true)]
        $serverName,
        [Parameter(Mandatory=$true)]
        $diskName,
        [Parameter(Mandatory=$true)]
        $diskInfo,
        [Parameter(Mandatory=$true)]
        $folderSizes
    )

    # Create temp directory if not exists
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp" 
    }

    # Setup report path with timestamp
    $timestamp = Get-Date -Format "ddMMyyyy-HHmm"
    $reportPath = "C:\temp\LowFreeSpace-$diskName-$serverName-$timestamp.txt"

    # Build report content
    $reportContent = @"
Server name: $serverName | Date: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")
-------------------------------------------------------------------------
Disk usage
Drive '$diskName': | Used GB: $($diskInfo.UsedSpace) | Free GB: $($diskInfo.FreeSpace) | Total GB: $($diskInfo.TotalSize) | Used Percentage: $($diskInfo.UsedPercentage)%
-------------------------------------------------------------------------
$folderSizes
"@

    # Write report to file
    $reportContent | Out-File -FilePath $reportPath -Force

    if (Test-Path -Path $LogFilePath) {
        [System.Windows.Forms.MessageBox]::Show(
            "The report has been exported to $reportPath.", 
            "Information", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    else {
        [System.Windows.Forms.MessageBox]::Show(
                "Error when exporting.", 
                "Error", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
    }
}

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Low Free Space"
$form.Size = New-Object System.Drawing.Size(400, 200)
$form.StartPosition = "CenterScreen"
$form.TopMost = $false  # Keep form on top
$form.KeyPreview = $true  # Important: This allows the form to receive key events before controls
$form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        $buttonExit.PerformClick()
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $buttonOK.PerformClick()
    }
})

# Server Name Label
$labelServerName = New-Object System.Windows.Forms.Label
$labelServerName.Location = New-Object System.Drawing.Point(20, 30)
$labelServerName.Size = New-Object System.Drawing.Size(100, 30)
$labelServerName.Text = "Server Name:"
$form.Controls.Add($labelServerName)

# Disk Name TextBox
$textBoxServerName = New-Object System.Windows.Forms.TextBox
$textBoxServerName.Location = New-Object System.Drawing.Point(120, 30)
$textBoxServerName.Size = New-Object System.Drawing.Size(200, 30)
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

$form.Controls.Add($textBoxServerName)

# Disk Name Label
$labelDisk = New-Object System.Windows.Forms.Label
$labelDisk.Location = New-Object System.Drawing.Point(20, 60)
$labelDisk.Size = New-Object System.Drawing.Size(100, 30)
$labelDisk.Text = "Disk Name:"
$form.Controls.Add($labelDisk)

# Disk Name TextBox
$textBoxDisk = New-Object System.Windows.Forms.TextBox
$textBoxDisk.Location = New-Object System.Drawing.Point(120, 60)
$textBoxDisk.Size = New-Object System.Drawing.Size(200, 30)
$textBoxDisk.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $textBoxDisk.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($textBoxDisk.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($textBoxDisk.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($textBoxDisk.Text)
        }
        $e.SuppressKeyPress = $true
    }
})
$form.Controls.Add($textBoxDisk)

# OK Button
$buttonOK = New-Object System.Windows.Forms.Button
$buttonOK.Location = New-Object System.Drawing.Point(110, 100)
$buttonOK.Size = New-Object System.Drawing.Size(75, 23)
$buttonOK.Text = "OK"
$buttonOK.Add_Click({
    $diskName = $textBoxDisk.Text.ToUpper()
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

    try {
        if ($diskName -eq "C") {
            # Show status
            $statusLabel.Text = "Cleaning C disk. Please wait..."

            # Get disk space before cleanup
            $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Clear user cache
            $clearUserCache = Clear-UserCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String
                     
            # Clear system cache
            $clearSystemCache = Clear-SystemCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            # Compress IIS logs
            $clearIISLogs = Compress-IISLogs -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            # Get disk space after cleanup
            $After = Get-DiskSpaceDetails -session $session -diskName $diskName
            
            # Export cleanup report
            Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs       
        }
        else {
            # Show status
            $statusLabel.Text = "Getting disk information. Please wait..."

            # Get disk space details
            $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Get folder sizes
            $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName
                            
            # Export report
            Export-DataDiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes

        }
        # Close session
        Remove-PSSession -Session $session
        $form.Close()        
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
})
$form.Controls.Add($buttonOK)

# Exit Button
$buttonExit = New-Object System.Windows.Forms.Button
$buttonExit.Location = New-Object System.Drawing.Point(210, 100)
$buttonExit.Size = New-Object System.Drawing.Size(75, 23)
$buttonExit.Text = "Cancel"
$buttonExit.BackColor = [System.Drawing.Color]::LightCoral
$buttonExit.Add_Click({
    $form.Close()
}
)
$form.Controls.Add($buttonExit)

# Status Label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(120, 135)
$statusLabel.Size = New-Object System.Drawing.Size(300, 100)
$form.Controls.Add($statusLabel)

    # Show form
    $form.ShowDialog()