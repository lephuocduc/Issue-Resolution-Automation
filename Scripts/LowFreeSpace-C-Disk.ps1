function Clear-UserCache {
    param (
        [string[]]$ExcludedProfiles = @("Administrator", "Public", "SVC_DailyChecks")
    )

    $ProfileFolders = Get-ChildItem -Directory C:\Users -Exclude $ExcludedProfiles | Select-Object -ExpandProperty Name
    foreach ($Folder in $ProfileFolders) {
        $PathsToClean = @(
            # User cache folders to clean (older than 5 days)
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
}

function Clear-SystemCache {
    # Windows Update cache (older than 5 days)
    Get-ChildItem -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose

    # Windows Installer patch cache (older than 5 days)
    Get-ChildItem -Path "C:\Windows\Installer\$PatchCache$\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose

    # SCCM cache (older than 5 days)
    Get-ChildItem -Path "C:\Windows\ccmcache\*" -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | Remove-Item -Force -Recurse -Verbose

    # Compress and archive IIS log files (older than 6 months)
    Compress-IISLogs -IISLogPath "C:\inetpub\logs\LogFiles" -ArchivePath "C:\inetpub\logs\Archive"
}

function Compress-IISLogs {
    param (
        [string]$IISLogPath = "C:\inetpub\logs\LogFiles",
        [string]$ArchivePath = "C:\inetpub\logs\Archive"
    )

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
}

function Get-DiskSpace {
    param (
        [string]$DriveLetter = "C"
    )
    $Drive = Get-PSDrive $DriveLetter
    return [PSCustomObject]@{
        UsedSpace = [math]::Round(($Drive.Used / 1GB), 2)
        FreeSpace = [math]::Round(($Drive.Free / 1GB), 2)
    }
}

function New-Report {
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

function Invoke-CDisk-Cleanup {
    # Ensure running with administrative privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        [System.Windows.Forms.MessageBox]::Show("Please run this script as an administrator.", "Error")
        return
    }

    $Before = Get-DiskSpace -DriveLetter "C"

    # Clean user cache
    Clear-UserCache

    # Clean system cache
    Clear-SystemCache

    $After = Get-DiskSpace -DriveLetter "C"

    # Generate report
    New-Report -Before $Before -After $After
}