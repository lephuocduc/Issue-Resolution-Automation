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
        Write-Host "Exporting disk report for $diskName on $serverName"
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

        return $reportPath
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Host "Error exporting disk report for $diskName on $serverName': $errorDetails"
    }
}