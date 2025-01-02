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

function Export-DiskReport {
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
    $diskName = $textBoxDisk.Text
    
    if ([string]::IsNullOrEmpty($diskName)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter disk name.", "Validation Error")
        return
    }
 
    if ($null -eq $session -or -not (Test-DiskAvailability -session $session -diskName $diskName)) {
        Write-Message -message "Disk '$diskName' is not available on server '$serverName'."
        [System.Windows.Forms.MessageBox]::Show("Disk '$diskName' is not available on server '$serverName'.", "Error")
        return
    }

    try {
        $diskInfo = Get-DiskSpaceInfo -session $session -diskName $diskName 
        $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName
                        
        # Export report
        Export-DiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes
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

function MainFunction {
    param(
        [string]$serverName
    )
    if (-not (Test-ServerAvailability -serverName $serverName)) {
        Write-Message -message "Server '$serverName' is not reachable."
        return # Exit script
    }

    $session = Get-Session -serverName $serverName
    if ($null -eq $session) {
        Write-Message -message "Session creation canceled or retry limit reached."
        return
    }

    $form.ShowDialog()
    
}

# Entry Point
MainFunction -serverName $ServerName