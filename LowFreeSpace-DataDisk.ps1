# Function to prompt for server name and check availability
function Get-ValidServerName {
    $serverName = $null
    do {
        $serverName = Read-Host "Enter server name"
        $pingResult = Test-Connection -ComputerName $serverName -Count 1 -Quiet
        if (-not $pingResult) {
            Write-Host "Server not available, please retype."
        }
    } while (-not $pingResult)
    return $serverName
}

# Function to attempt to create a session and handle credential failures
function Get-Session {
    param($serverName)
    
    do {
        $credential = Get-Credential -Message "Enter your credentials"
        if ($credential -eq $null) {
            Write-Host "Login cancelled" -ForegroundColor Yellow
            exit
        }
        
        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            Write-Host "Successfully connected to $serverName" -ForegroundColor Green
            return $session
        } catch {
            Write-Host "Failed to connect to $serverName. Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } while ($true)
}

# Function to check if disk exists on the server
function Check-DiskExistence {
    param($session, $diskName)
    $diskExists = Invoke-Command -Session $session -ScriptBlock {
        param($diskName)
        $disk = Get-PSDrive -Name $diskName -ErrorAction SilentlyContinue
        return $disk -ne $null
    } -ArgumentList $diskName
    return $diskExists
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

# Function to prompt for disk name and verify its existence
function Get-ValidDiskName {
    param($session)
    do {
        $diskName = Read-Host "Enter disk name"
        $diskExists = Check-DiskExistence -session $session -diskName $diskName
        if (-not $diskExists) {
            Write-Host "Disk '$diskName' does not exist on server '$serverName'. Please enter a valid disk name."
        }
    } while (-not $diskExists)
    return $diskName
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

    # Display to console
    Write-Host "`nServer name: $serverName" -ForegroundColor Cyan
    Write-Host $diskInfo
    Write-Host $folderSizes
    Write-Host "Report generated on: $(Get-Date)" -ForegroundColor Gray

    # Write report to file
    $reportContent | Out-File -FilePath $reportPath -Force

    Write-Host "`nThe report has been exported to $reportPath" -ForegroundColor Green
}

# Main script
$serverName = Get-ValidServerName
$session = Get-Session -serverName $serverName
$diskName = Get-ValidDiskName -session $session

# Get information
$diskInfo = Get-DiskSpaceInfo -session $session -diskName $diskName
$folderSizes = Get-SecondLevelFolderSizes -session $session -diskName $diskName

# Export report
Export-DiskReport -serverName $serverName -diskName $diskName -diskInfo $diskInfo -folderSizes $folderSizes

# Clean up session
Remove-PSSession -Session $session