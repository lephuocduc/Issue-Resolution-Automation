& {
param($PoshToolsRoot)
#NOTES
# Name:   UI.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION
# This script provides a simple user interface to execute PowerShell scripts. The form contains buttons that, when clicked, execute the corresponding script. The script paths are hard-coded in the button definitions, but you can modify the script to load the paths from a configuration file or other source.

#REQUIREMENT
# Run this script as an administrator to ensure the execution of PowerShell scripts is allowed.

#INPUTS
# None

#OUTPUTS
# None

#EXAMPLE
# .\UI.ps1
# This example runs the script and displays the user interface form. Clicking the buttons will execute the corresponding PowerShell scripts.
# The "Exit" button closes the form.

# Load module
# Function to write message to user about script execution
function Write-Message {
    param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    # Create temp directory if not exists
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp"
    }

    $message | Out-File "C:\temp\script_status.txt" -Force
}

# Function to prompt for server name and check availability
function Test-ServerAvailability {
    param(
        [string]$serverName
    )
    return Test-Connection -ComputerName $serverName -Count 1 -Quiet
}

# Function to attempt to create a session and handle credential failures
function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        $credential = Get-Credential
        if ($null -eq $credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            continue
        }
    } while ($true)
}

# Write message at the start
Write-Message -message "Please input server name and select a script to execute."

# Load Windows Forms Assembly
$Parameters = @{
	AssemblyName = 'System.Windows.Forms'
}
Add-Type @Parameters

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Script Manager"
$form.Size = New-Object System.Drawing.Size(650, 300)
$form.StartPosition = "CenterScreen"

# Set the icon
$iconPath = "$PSScriptRoot\icon.ico"  # Path to your icon file
if (Test-Path $iconPath) {
    $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
}
<#
# Function to Execute PowerShell Script
function Invoke-Script {
    param ($scriptPath)
    try {
        if (-not (Test-Path -Path $scriptPath)) {
            [System.Windows.Forms.MessageBox]::Show("Script not found: $scriptPath", "Error")
            return
        }
        
        # Get server name and validate
        $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        
        # Run script with server name parameter
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ServerName `"$serverName`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -NoNewWindow        
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
}#>

# Function to create responsive buttons with automatic placement
function New-ResponsiveButtons {
    param (
        [System.Windows.Forms.Form]$form,
        [Array]$buttonDefinitions
    )

    $yOffset = 20  # Initial offset from the top
    $spacing = 10  # Spacing between buttons

    foreach ($definition in $buttonDefinitions) {
        # Create the button
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $definition.Text

        # Measure the text size
        $graphics = [System.Drawing.Graphics]::FromImage((New-Object System.Drawing.Bitmap 1,1))
        $textSize = $graphics.MeasureString($button.Text, $button.Font)
        $button.Size = New-Object System.Drawing.Size(($textSize.Width + 50), ($textSize.Height + 20)) # Add padding

        # Set button location
        $button.Location = New-Object System.Drawing.Point(20, $yOffset)
        $yOffset += $button.Height + $spacing  # Update offset for next button

        # Add BackColor if specified
        if ($definition.BackColor) {
            $button.BackColor = $definition.BackColor
        }

        # Add click event
        $button.Add_Click($definition.OnClick)

        # Add the button to the form
        $form.Controls.Add($button)
        
    }
}

# Server Name Label
$labelServer = New-Object System.Windows.Forms.Label
$labelServer.Location = New-Object System.Drawing.Point(300, 30)
$labelServer.Size = New-Object System.Drawing.Size(100, 30)
$labelServer.Text = "Server Name:"
$form.Controls.Add($labelServer)

# Server Name TextBox
$textBoxServer = New-Object System.Windows.Forms.TextBox
$textBoxServer.Location = New-Object System.Drawing.Point(400, 30)
$textBoxServer.Size = New-Object System.Drawing.Size(200, 60)
$textBoxServer.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        $textBoxServer.SelectAll()
        $e.SuppressKeyPress = $true
    }
})
$form.Controls.Add($textBoxServer)

# Status Label
$statusLabel = New-Object System.Windows.Forms.TextBox
$statusLabel.Location = New-Object System.Drawing.Point(300, 60)
$statusLabel.Size = New-Object System.Drawing.Size(300, 60)
$statusLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
$statusLabel.Padding = New-Object System.Windows.Forms.Padding(5)
$statusLabel.ReadOnly = $true  # Make it read-only but selectable
$statusLabel.Multiline = $true # Support multiple lines
$statusLabel.BackColor = $form.BackColor  # Match form background
$statusLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Left

# Add context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyMenuItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::C
# Add click event to copy selected text or all text to clipboard
$copyMenuItem.Add_Click({
    if ($statusLabel.SelectedText) {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.SelectedText)
    } else {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.Text)
    }
})

# Add Ctrl+A shortcut to select all text
$statusLabel.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq 'A') {
        $statusLabel.SelectAll()
        $e.SuppressKeyPress = $true
    }
})

$contextMenu.Items.Add($copyMenuItem)
$statusLabel.ContextMenuStrip = $contextMenu

$form.Controls.Add($statusLabel)

# Define buttons
$buttons = @(
    @{
        Text = "Low Free Space"
        OnClick = {
            $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        #NOTES
# Name:   LowFreeSpace-DataDisk.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION

#REQUIREMENT

#INPUTS

#OUTPUTS

#EXAMPLE


# Load module
# Function to write message to user about script execution
function Write-Message {
    param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    # Create temp directory if not exists
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp"
    }

    $message | Out-File "C:\temp\script_status.txt" -Force
}

# Function to prompt for server name and check availability
function Test-ServerAvailability {
    param(
        [string]$serverName
    )
    return Test-Connection -ComputerName $serverName -Count 1 -Quiet
}

# Function to attempt to create a session and handle credential failures
function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        $credential = Get-Credential
        if ($null -eq $credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            continue
        }
    } while ($true)
}

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
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-6) }

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
    Write-Message -message "Cleanup report exported to: $LogFilePath"
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
    $reportPath = "C:\temp\LowFreeSpace-DataDisk-$serverName-$timestamp.txt"

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
    Write-Message -message "Report exported to: $reportPath"
}

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Low Free Space"
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
    
    # Validate disk name
    if ([string]::IsNullOrEmpty($diskName)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter disk name.", "Validation Error")
        return
    }
    
    # Connect to server
    if (-not (Test-DiskAvailability -session $session -diskName $diskName)) {
        Write-Message -message "Disk '$diskName' is not available on server '$serverName'."
        [System.Windows.Forms.MessageBox]::Show("Disk '$diskName' is not available on server '$serverName'.", "Validation Error")
        return
    }

    try {
        if ($diskName -eq "C") {
            # Get disk space before cleanup
            $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Clear user cache
            Write-Message -message "Clearing user cache..."
            $clearUserCache = Clear-UserCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String
                     
            # Clear system cache
            Write-Message -message "Clearing system cache..."
            $clearSystemCache = Clear-SystemCache -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            # Compress IIS logs
            Write-Message -message "Compresing IIS log files..."
            $clearIISLogs = Compress-IISLogs -session $session -Verbose *>&1 | ForEach-Object {
                "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
            } | Out-String

            # Get disk space after cleanup
            $After = Get-DiskSpaceDetails -session $session -diskName $diskName
            
            # Export cleanup report
            Export-CDisk-Cleanup-Report -serverName $serverName -Before $Before -After $After -userCacheLog $clearUserCache -systemCacheLog $clearSystemCache -iisLogCleanupLog $clearIISLogs            
        }
        else {
            # Get disk space details
            Write-Message -message "Checking disk space for '$diskName' disk on server '$serverName'..."
            $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName

            # Get folder sizes
            Write-Message -message "Getting folder sizes for '$diskName' disk on server '$serverName'..."
            $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName
                            
            # Export report
            Write-Message -message "Exporting report..."
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

    # Validate server name
    Write-Message -message "Connecting to server '$serverName'..."
    if (-not (Test-ServerAvailability -serverName $serverName)) {
        Write-Message -message "Server '$serverName' is not reachable."
        return # Exit script
    }

    # Create session
    Write-Message -message "Creating session to server '$serverName'..."
    $session = Get-Session -serverName $serverName
    if ($null -eq $session) {
        Write-Message -message "Session creation canceled or retry limit reached."
        return
    }

    # Show form
    Write-Message -message "Session created successfully."
    $form.ShowDialog()
    
}

# Entry Point
Start-DiskChecking -serverName $ServerName
        }
    },
    @{
        Text = "Another Script"
        OnClick = {
            $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        . (Join-Path $PSScriptRoot 'Scripts\AnotherScript.ps1') -ServerName $serverName -NoProfile -ExecutionPolicy Bypass -NoNewWindow
        }
    },
    @{
        Text = "Exit"
        BackColor = [System.Drawing.Color]::LightCoral
        OnClick = {
            $form.Close()
        }
    }
)

# Create buttons
New-ResponsiveButtons -form $form -buttonDefinitions $buttons

# Create timer for file monitoring
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100 # Check more frequently (100ms)
# Add tick event to update status label from file content if changed
$timer.Add_Tick({
    try {
        if (Test-Path "C:\temp\script_status.txt") {
            $newContent = [System.IO.File]::ReadAllText("C:\temp\script_status.txt")
            if ($newContent -ne $statusLabel.Text) {
                $statusLabel.Text = $newContent
                $statusLabel.Update() # Force immediate UI update
                [System.Windows.Forms.Application]::DoEvents() # Process UI events
                Write-Debug "Status updated: $newContent"
            }
        }
    }
    catch {
        Write-Debug "Error reading status file: $_"
    }
})

# Start timer
$timer.Start()

# Add form closing cleanup
$form.Add_FormClosing({
    $timer.Stop()
    $timer.Dispose()
})

# Show Form
$form.ShowDialog()
}