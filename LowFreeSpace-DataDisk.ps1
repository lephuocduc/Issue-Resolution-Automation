# Load Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

# Function to prompt for server name and check availability
function Test-ServerAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [string]$serverName
    )
    if (-not (Test-Connection -ComputerName $serverName -Count 1 -Quiet)) {
        return $false
    }
    else {
        return $true
    }
}

# Function to attempt to create a session and handle credential failures
function Get-Session {
    param($serverName)
    $statusLabel.Text = "Logging in to $serverName..."
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        $credential = Get-Credential
        if ($credential -eq $null -or $retryCount -ge $maxRetries) {
            $statusLabel.Text = "Session creation canceled or retry limit reached."
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            $statusLabel.Text = "Session created successfully."
            return $session
        } catch {
            $statusLabel.Text = "Failed to create session. Error: $_"
        }
    } while ($true)
}

# Function to check if disk exists on the server
function Test-DiskAvailability {
    [CmdletBinding()]
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
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
        return $false
    }
}

# Check Disk Info
function Get-DiskSpaceInfo {
    param($session, $diskName)

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

    # Color coding based on used percentage
    $color = switch($diskInfo.UsedPercentage) {
        {$_ -ge 90} {'Red'}
        {$_ -ge 80} {'Yellow'}
        default {'Green'}
    }

    $output = "`nDisk ${diskName} Space Information:`n"
    $output += "Total Size: $($diskInfo.TotalSize) GB`n"
    $output += "Free Space: $($diskInfo.FreeSpace) GB`n"
    $output += "Used: $($diskInfo.UsedPercentage)%`n"
    $output += "-----------------------------------------`n"
    return $output
}

# Function to list and sort sizes of items (both folders and files) within each first-level folder
function Get-SecondLevelFolderSizes {
    param($session, $diskName)
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
    $statusLabel.Text = "The report has been exported to $reportPath"   
}

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "LowFreeSpace-DataDisk"
$form.Size = New-Object System.Drawing.Size(400, 300)
$form.StartPosition = "CenterScreen"

# Server Name Label
$labelServer = New-Object System.Windows.Forms.Label
$labelServer.Location = New-Object System.Drawing.Point(20, 20)
$labelServer.Size = New-Object System.Drawing.Size(100, 20)
$labelServer.Text = "Server Name:"
$form.Controls.Add($labelServer)

# Server Name TextBox
$textBoxServer = New-Object System.Windows.Forms.TextBox
$textBoxServer.Location = New-Object System.Drawing.Point(120, 20)
$textBoxServer.Size = New-Object System.Drawing.Size(200, 20)
$form.Controls.Add($textBoxServer)

# Disk Name Label
$labelDisk = New-Object System.Windows.Forms.Label
$labelDisk.Location = New-Object System.Drawing.Point(20, 50)
$labelDisk.Size = New-Object System.Drawing.Size(100, 20)
$labelDisk.Text = "Disk Name:"
$form.Controls.Add($labelDisk)

# Disk Name TextBox
$textBoxDisk = New-Object System.Windows.Forms.TextBox
$textBoxDisk.Location = New-Object System.Drawing.Point(120, 50)
$textBoxDisk.Size = New-Object System.Drawing.Size(200, 20)
$form.Controls.Add($textBoxDisk)

# Status Label for Checking
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(20, 110)
$statusLabel.Size = New-Object System.Drawing.Size(350, 50)
$form.Controls.Add($statusLabel)

# OK Button
$buttonOK = New-Object System.Windows.Forms.Button
$buttonOK.Location = New-Object System.Drawing.Point(120, 80)
$buttonOK.Size = New-Object System.Drawing.Size(75, 23)
$buttonOK.Text = "OK"
$buttonOK.Add_Click({
    $serverName = $textBoxServer.Text
    $diskName = $textBoxDisk.Text
    
    if ([string]::IsNullOrEmpty($serverName) -or [string]::IsNullOrEmpty($diskName)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter both server name and disk name.", "Validation Error")
        return
    }

    $statusLabel.Text = "Connecting to '$serverName...'"
    if (-not (Test-ServerAvailability -serverName $serverName)) {
        $statusLabel.Text = "Server '$serverName' is not reachable."
        return
    }
    $statusLabel.Text = "Connected to '$serverName'"

    

    $session = Get-Session -serverName $serverName
    $statusLabel.Text = "Checking disk $diskName on $serverName..."
    if ($null -eq $session -or -not (Test-DiskAvailability -session $session -diskName $diskName)) {
        $statusLabel.Text = "Disk $diskName not found on $serverName."
        return
    }

    try {
        $statusLabel.Text = "Checking disk $diskName on $serverName..."
        $diskInfo = Get-DiskSpaceInfo -session $session -diskName $diskName 
        $folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName
                        
        # Export report
        Export-DiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes
        Remove-PSSession -Session $session
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
$buttonExit.Add_Click({ $form.Close() })
$form.Controls.Add($buttonExit)


# Show Form
$form.ShowDialog()

