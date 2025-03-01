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
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
} catch {
    Write-Error "Failed to load Windows Forms assemblies: $_"
    exit 1
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
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-0) }

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

# Function to get the largest folders in a after cleanup
function Get-LargestFolders {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$path,
        [string[]]$exclude = @(),
        [int]$topN = 5
    )

    $scriptBlock = {
        param($path, $exclude, $topN)
        try {
            $folders = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | 
                       Where-Object { $_.Name -notin $exclude }
            $sizes = foreach ($folder in $folders) {
                try {
                    $size = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                            Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    [PSCustomObject]@{
                        Folder = $folder.FullName
                        SizeGB = [math]::Round($size / 1GB, 2)
                    }
                } catch {
                    Write-Warning "Error processing folder $($folder.FullName): $_"
                    continue
                }
            }
            $sizes | Sort-Object SizeGB -Descending | Select-Object -First $topN
        } catch {
            Write-Warning "Error in Get-LargestFolders script block: $_"
            return @()
        }
    }

    $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
    return $result
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
        [string]$iisLogCleanupLog,
        [array]$topUsers,
        [array]$topRoot
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

Disk usage before cleanup:
Drive C: | Used GB: $($Before.UsedSpace) | Free GB: $($Before.FreeSpace) | Total GB: $($Before.TotalSize) | Free Percentage: $($Before.FreePercentage)%

Disk usage after cleanup:
Drive C: | Used GB: $($After.UsedSpace) | Free GB: $($After.FreeSpace) | Total GB: $($After.TotalSize) | Free Percentage: $($After.FreePercentage)%

Space saved: $SpaceSaved GB

#######################################################################
$userCacheLog
#######################################################################
$systemCacheLog
#######################################################################
$iisLogCleanupLog

"@

    # Append top folders if available
    if ($topUsers -and $topUsers.Count -gt 0) {
        $Report +="#######################################################################"
        $Report += "`nTop 5 largest folders in C:\Users:`n"
        $Report += ($topUsers | ForEach-Object { " - $($_.Folder): $($_.SizeGB)GB" }) -join "`n"
    }

    if ($topRoot -and $topRoot.Count -gt 0) {
        $Report += "`n`nTop 5 largest folders in C:\ (excluding system folders):`n"
        $Report += ($topRoot | ForEach-Object { " - $($_.Folder): $($_.SizeGB)GB" }) -join "`n"
    }

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
                    Name = "+ $($item.Name)"
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
        $output += "`n- $($folder.FolderName)`n"
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
-------------------------------------------------------------------------
Server name: $serverName | Date: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")

Disk usage
Drive $($diskName): | Used GB: $($diskInfo.UsedSpace) | Free GB: $($diskInfo.FreeSpace) | Total GB: $($diskInfo.TotalSize) | Free Percentage: $($diskInfo.FreePercentage)%

#######################################################################
$folderSizes
"@

    # Write report to file
    $reportContent | Out-File -FilePath $reportPath -Force

    if (Test-Path -Path $reportPath) {
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
            
            $freePercentageAfterCleanup = $After.FreePercentage

            # Check if free space is still below 10%
            $topUsers = $null
            $topRoot = $null
            if ($After.FreePercentage -lt 10) {
                Update-StatusLabel -text "Free space still low. Identifying large folders..."             
                $topUsers = Get-LargestFolders -session $session -path "C:\Users" -topN 5
                $excludeRoot = @("Users", "Windows", "Program Files", "Program Files (x86)", "Program Data")
                $topRoot = Get-LargestFolders -session $session -path "C:\" -exclude $excludeRoot -topN 5
            }

            [System.Windows.Forms.MessageBox]::Show(
                "Cleanup complete. Free space is $($freePercentageAfterCleanup)%.`nPlease check report for details.", 
                "Information", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

            # Export cleanup report
            #Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs       
            Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After `
                -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs `
                -topUsers $topUsers -topRoot $topRoot
        }
        else {
            # Show status
            Update-StatusLabel -text "Getting disk information. Please wait..."

            # Get disk space details
            $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Get folder sizes
            $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName

            $freePercentageDataDisk = $diskInfo.FreePercentage

            [System.Windows.Forms.MessageBox]::Show(
                "Drive $($diskName). Free space is $($freePercentageDataDisk)%.`nPlease check report for details.", 
                "Information", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
                            
            # Export report
            Export-DataDiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes

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