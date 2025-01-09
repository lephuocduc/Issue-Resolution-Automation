#NOTES
# Name:   LowFreeSpace-DataDisk.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION
# This script is designed to check the disk space of a specified disk on a remote server, and export a report with disk information and the sizes of items within each first-level folder on the disk.

#REQUIREMENT
# The script requires the user to input the server name and disk name to check the disk space.
# The script also requires the user to enter credentials to connect to the remote server.


#INPUTS
# The script prompts the user to input the server name and disk name to check the disk space.
# The script also prompts the user to enter credentials to connect to the remote server.


#OUTPUTS
# The script outputs a report with the following information:
# - Server name
# - Disk name
# - Total size of the disk
# - Free space on the disk
# - Percentage of disk space used
# - Sizes of items (both folders and files) within each first-level folder on the disk

#EXAMPLE
# To run the script, open a PowerShell console and run the following command:
# .\LowFreeSpace-DataDisk.ps1
# The script will prompt you to enter the server name, disk name, and credentials to connect to the remote server.
# The script will then generate a report with the disk information and the sizes of items within each first-level folder on the disk.
# The report will be exported to a text file in the C:\temp directory with a timestamp in the file name.



# Pass the server name as a parameter from UI.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerName
)

# Load module
. "$PSScriptRoot/../modules/module.ps1"
. "$PSScriptRoot/LowFreeSpace-C-Disk.ps1"

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
        } -ArgumentList $diskName -ErrorAction Stop
        return $diskExists
    }
    catch {
        return $false
    }
}

# Function to clear system cache
# Function to clear user cache on a remote PC
function Clear-UserCache {
    param (
        [System.Management.Automation.Runspaces.PSSession]$session,
        [string[]]$ExcludedProfiles = @("Administrator", "Public", "SVC_DailyChecks")
    )

    Invoke-Command -Session $session -ScriptBlock {
        param($ExcludedProfiles)

        $ProfileFolders = Get-ChildItem -Directory C:\Users -Exclude $ExcludedProfiles | Select-Object -ExpandProperty Name
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
                Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose
            }
        }
    } -ArgumentList $ExcludedProfiles
}

# Function to clear system cache
# Function to clear system cache on a remote PC
function Clear-SystemCache {
    param (
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    Invoke-Command -Session $session -ScriptBlock {
        # Windows Update cache (older than 5 days)
        Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose

        # Windows Installer patch cache (older than 5 days)
        Get-ChildItem -Path "C:\Windows\Installer\$PatchCache$\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose

        # SCCM cache (older than 5 days)
        Get-ChildItem -Path "C:\Windows\ccmcache\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose
    }
}

# Function to compress IIS log files on a remote PC
function Compress-IISLogs {
    param (
        [System.Management.Automation.Runspaces.PSSession]$session,
        [string]$IISLogPath = "C:\inetpub\logs\LogFiles",
        [string]$ArchivePath = "C:\inetpub\logs\Archive"
    )

    Invoke-Command -Session $session -ScriptBlock {
        param($IISLogPath, $ArchivePath)

        # Ensure the archive directory exists
        if (-not (Test-Path $ArchivePath)) {
            New-Item -Path $ArchivePath -ItemType Directory
        }

        # Get IIS log files older than 6 months
        $OldLogs = Get-ChildItem -Path "$IISLogPath\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-6) }

        foreach ($Log in $OldLogs) {
            $ArchiveFileName = "$ArchivePath\$($Log.Name).zip"
            Compress-Archive -Path $Log.FullName -DestinationPath $ArchiveFileName -Update
            Remove-Item -Path $Log.FullName -Force -Verbose
        }
    } -ArgumentList $IISLogPath, $ArchivePath
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
        [PSCustomObject]$Before,
        [PSCustomObject]$After,
        [string]$LogFilePath = "C:\Temp\cleanup_report.log"
    )

    $SpaceSaved = $After.FreeSpace - $Before.FreeSpace
    $Report = @"
-------------------------------------------------------------------------
Cleanup Report
Date: $(Get-Date)
-------------------------------------------------------------------------
Disk usage before cleanup:
Drive C: | Used GB: $($Before.UsedSpace) | Free GB: $($Before.FreeSpace)
-------------------------------------------------------------------------
Disk usage after cleanup:
Drive C: | Used GB: $($After.UsedSpace) | Free GB: $($After.FreeSpace)
-------------------------------------------------------------------------
Space saved: $SpaceSaved GB
-------------------------------------------------------------------------
"@
    Add-Content -Path $LogFilePath -Value $Report
}


# Check Disk Info
function Get-DiskSpaceInfo {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$diskName
    )

    $diskInfo = Invoke-Command -Session $session -ScriptBlock {
        param($diskName)
        $drive = Get-PSDrive -Name $diskName
        $freeSpace = [math]::Round($drive.Free / 1GB, 2)
        $totalSize = [math]::Round(($drive.Free + $drive.Used) / 1GB, 2)
        $usedPercentage = [math]::Round(($drive.Used / ($drive.Free + $drive.Used)) * 100, 2)
        
        return @{
            FreeSpace = $freeSpace
            TotalSize = $totalSize
            UsedPercentage = $usedPercentage
        }
    } -ArgumentList $diskName

    $output = "`nDisk ${diskName} Information:`n"
    $output += "Total Size: $($diskInfo.TotalSize) GB`n"
    $output += "Free Space: $($diskInfo.FreeSpace) GB`n"
    $output += "Used: $($diskInfo.UsedPercentage)%`n"
    $output += "-----------------------------------------`n"
    return $output
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
    $reportPath = "C:\temp\LowFreeSpace-DataDisk-$serverName-$timestamp.txt"

    # Build report content
    $reportContent = "Server name: $serverName"
    $reportContent += $diskInfo
    $reportContent += $folderSizes
    $reportContent += "`nReport generated on: $(Get-Date)"

    # Write report to file
    $reportContent | Out-File -FilePath $reportPath -Force
    Write-Message -message "Report exported to: $reportPath"
}

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "LowFreeSpace-DataDisk"
$form.Size = New-Object System.Drawing.Size(400, 250)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true  # Keep form on top

# Disk Name Label
$labelDisk = New-Object System.Windows.Forms.Label
$labelDisk.Location = New-Object System.Drawing.Point(20, 50)
$labelDisk.Size = New-Object System.Drawing.Size(100, 30)
$labelDisk.Text = "Disk Name:"
$form.Controls.Add($labelDisk)

# Disk Name TextBox
$textBoxDisk = New-Object System.Windows.Forms.TextBox
$textBoxDisk.Location = New-Object System.Drawing.Point(120, 50)
$textBoxDisk.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($textBoxDisk)

# OK Button
$buttonOK = New-Object System.Windows.Forms.Button
$buttonOK.Location = New-Object System.Drawing.Point(120, 80)
$buttonOK.Size = New-Object System.Drawing.Size(75, 23)
$buttonOK.Text = "OK"
$buttonOK.Add_Click({
    $diskName = $textBoxDisk.Text.ToUpper()
    
    if ([string]::IsNullOrEmpty($diskName)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter disk name.", "Validation Error")
        return
    }
 
    if (-not (Test-DiskAvailability -session $session -diskName $diskName)) {
        Write-Message -message "Disk '$diskName' is not available on server '$serverName'."
        [System.Windows.Forms.MessageBox]::Show("Please enter disk name.", "Validation Error")
        return
    }

    try {
        if ($diskName -eq "C") {
            # Get disk space before cleanup
            $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Clear user cache (Temporary Internet Files, Edge cache, Temp, Chrome cache, Teams cache, etc.)
            Write-Message -message "Clearing user cache..."
            Clear-UserCache -session $session
            
            # Clear system cache (Windows Update, Windows Installer, SCCM)
            Write-Message -message "Clearing system cache..."
            Clear-SystemCache -session $session

            # Compress IIS log files older than 6 months
            Write-Message -message "Compresing IIS log files..."
            Compress-IISLogs -session $session -IISLogPath "C:\inetpub\logs\LogFiles" -ArchivePath "C:\inetpub\logs\Archive"

            # Get disk space after cleanup
            $After = Get-DiskSpaceDetails -session $session -diskName $diskName
            
            # Export cleanup report
            Export-CDisk-Cleanup-Report -Before $Before -After $After
            Write-Message -message "Cleanup report exported successfully."

            Remove-PSSession -Session $session
            $form.Close()
        }
        else {
            Write-Message -message "Checking disk space for '$diskName' disk on server '$serverName'..."
            $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName

            Write-Message -message "Getting folder sizes for '$diskName' disk on server '$serverName'..."
            $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName
                            
            # Export report
            Write-Message -message "Exporting report..."
            Export-DataDiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes
            Remove-PSSession -Session $session
            $form.Close()
        }        
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
})
$form.Controls.Add($buttonOK)

# Exit Button
$buttonExit = New-Object System.Windows.Forms.Button
$buttonExit.Location = New-Object System.Drawing.Point(200, 80)
$buttonExit.Size = New-Object System.Drawing.Size(75, 23)
$buttonExit.Text = "Exit"
$buttonExit.BackColor = [System.Drawing.Color]::LightCoral
$buttonExit.Add_Click({
    Write-Message -message "Script execution canceled."
    $form.Close()
}
)
$form.Controls.Add($buttonExit)

function Start-DiskChecking {
    param(
        [string]$serverName
    )

    Write-Message -message "Connecting to server '$serverName'..."
    if (-not (Test-ServerAvailability -serverName $serverName)) {
        Write-Message -message "Server '$serverName' is not reachable."
        return # Exit script
    }

    Write-Message -message "Creating session to server '$serverName'..."
    $session = Get-Session -serverName $serverName
    if ($null -eq $session) {
        Write-Message -message "Session creation canceled or retry limit reached."
        return
    }

    Write-Message -message "Session created successfully."
    $form.ShowDialog()
    
}

# Entry Point
Start-DiskChecking -serverName $ServerName