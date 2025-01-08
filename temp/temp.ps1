function Invoke-CDisk-Cleanup {
    # Content from cleanup1.txt
    $fiser = Get-ChildItem C:\temp\*.log | select -expand fullname
    $fiser -match "housekeeping.log"
    If ($fiser -eq 'False') {
        New-Item -Path 'C:\Temp\housekeeping.log' -ItemType File
    }

    $ResultCSV = 'C:\Temp\housekeeping.log'
    If ((Get-Item $ResultCSV).Length -gt 5Mb) { 
        Remove-Item $ResultCSV -Force | Out-Null
    }

    $fiser = Get-ChildItem C:\temp\*.log | select -expand fullname
    $fiser -match "housekeeping.log"
    If ($fiser -eq 'False') {
        New-Item -Path 'C:\Temp\housekeeping.log' -ItemType File
    }

    $ResultCSV2 = New-Item -Path 'C:\Temp\removed.log' -ItemType File -Force

    $Drive_C_Before = Get-PSDrive C
    $Used_size_C_Before = [math]::Round(($Drive_C_Before.used/1GB), 2)
    $Free_size_C_Before = [math]::Round(($Drive_C_Before.free/1GB), 2)
    $ExcludedProfiles = @("Administrator","Public","SVC_DailyChecks")
    $ProfileFolders = Get-ChildItem -Directory C:\Users -Exclude $ExcludedProfiles | Select Name
    Foreach ($Folder in $ProfileFolders.Name) {
        remove-item -path "C:\Users\$Folder\AppData\Local\Microsoft\Windows\Temporary Internet Files\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\Users\$Folder\AppData\Local\Temp\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Terminal Server Client\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Teams\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Windows\InetCache\IE\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Windows\WebCache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Code Cache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Service Worker\CacheStorage\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
    }

    $Drive_C_After = Get-PSDrive C
    $Used_size_C_After = [math]::Round(($Drive_C_After.used/1GB), 2)
    $Free_size_C_After = [math]::Round(($Drive_C_After.free/1GB), 2)
    $Gain_AllDrives = ($Free_size_C_After-$Free_size_C_Before)
    $data = Get-Date
    $sterse = Get-Content $ResultCSV2

    $Rezultate = "
    -------------------------------------------------------------------------
    Daily cleanup script results
    Hostname:$env:computername
    Date: $data
    -------------------------------------------------------------------------
    Disk usage before cleanup:
    
    Drive C: | Used GB: $Used_size_C_Before | Free GB: $Free_size_C_Before
    
    -------------------------------------------------------------------------
    Disk usage after cleanup:
    
    Drive C: | Used GB: $Used_size_C_After | Free GB: $Free_size_C_After
    
    -------------------------------------------------------------------------
    Total gain in GB: $Gain_AllDrives
    -------------------------------------------------------------------------
    Logs of file processed in this run be found down below (WARNING can be quite some files)
    $sterse
    -------------------
    Report END
    -------------------
    "

    $Rezultate >> $ResultCSV

    # Content from cleanup2.txt
    $Global:Result  =@()
    $Global:ExclusionList  =@()

    $ProgressCounter = 0

    $ResultCSV = 'C:\Temp\Clean-CMClientCache.log'
    If (Test-Path $ResultCSV) {
        If ((Get-Item $ResultCSV).Length -gt 500KB) {
            Remove-Item $ResultCSV -Force | Out-Null
        }
    }

    [String]$ResultPath =  Split-Path $ResultCSV -Parent
    If ((Test-Path $ResultPath) -eq $False) {
        New-Item -Path $ResultPath -Type Directory | Out-Null
    }

    $Date = Get-Date

    Function Write-Log {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [Alias('Name')]
            [string]$EventLogName = 'Configuration Manager',
            [Parameter(Mandatory=$false,Position=1)]
            [Alias('Source')]
            [string]$EventLogEntrySource = 'Clean-CMClientCache',
            [Parameter(Mandatory=$false,Position=2)]
            [Alias('ID')]
            [int32]$EventLogEntryID = 1,
            [Parameter(Mandatory=$false,Position=3)]
            [Alias('Type')]
            [string]$EventLogEntryType = 'Information',
            [Parameter(Mandatory=$true,Position=4)]
            [Alias('Message')]
            $EventLogEntryMessage
        )

        If (([System.Diagnostics.EventLog]::Exists($EventLogName) -eq $false) -or ([System.Diagnostics.EventLog]::SourceExists($EventLogEntrySource) -eq $false )) {
            New-EventLog -LogName $EventLogName -Source $EventLogEntrySource
        }

        $ResultString = Out-String -InputObject $Result -Width 1000
        Write-EventLog -LogName $EventLogName -Source $EventLogEntrySource -EventId $EventLogEntryID -EntryType $EventLogEntryType -Message $ResultString

        $EventLogEntryMessage | Export-Csv -Path $ResultCSV -Delimiter ';' -Encoding UTF8 -NoTypeInformation -Append -Force

        $EventLogEntryMessage | Format-Table Name,TotalDeleted`(MB`)
    }

    Function Remove-CacheItem {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,Position=0)]
            [Alias('CacheTD')]
            [string]$CacheItemToDelete,
            [Parameter(Mandatory=$true,Position=1)]
            [Alias('CacheN')]
            [string]$CacheItemName
        )

        If ($CacheItems.ContentID -contains $CacheItemToDelete) {
            $CacheItemLocation = $CacheItems | Where {$_.ContentID -Contains $CacheItemToDelete} | Select -ExpandProperty Location
            $CacheItemSize =  Get-ChildItem $CacheItemLocation -Recurse -Force | Measure-Object -Property Length -Sum | Select -ExpandProperty Sum

            If ($CacheItemSize -gt '0.00') {
                $CMObject = New-Object -ComObject 'UIResource.UIResourceMgr'
                $CMCacheObjects = $CMObject.GetCacheInfo()
                $CMCacheObjects.GetCacheElements() | Where-Object {$_.ContentID -eq $CacheItemToDelete} |
                    ForEach-Object {
                        $CMCacheObjects.DeleteCacheElement($_.CacheElementID)
                        Write-Host 'Deleted: '$CacheItemName -Verbose
                    }

                $ResultProps = [ordered]@{
                    'Name' = $CacheItemName
                    'ID' = $CacheItemToDelete
                    'Location' = $CacheItemLocation
                    'Size(MB)' = '{0:N2}' -f ($CacheItemSize / 1MB)
                    'Status' = 'Deleted!'
                }

                $Global:Result  += New-Object PSObject -Property $ResultProps
            }
        }
        Else {
            Write-Host 'Already Deleted:'$CacheItemName '|| ID:'$CacheItemToDelete -Verbose
        }
    }

    Function Remove-CachedApplications {
        Try {
            $CM_Applications = Get-WmiObject -Namespace root\ccm\ClientSDK -Query 'SELECT * FROM CCM_Application' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Application List from WMI - Failed!'
        }

        Foreach ($Application in $CM_Applications) {
            If ($CM_Applications.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Applications' -CurrentOperation $Application.FullName -PercentComplete (($ProgressCounter / $CM_Applications.Count) * 100)
            }

            $Application.Get()

            Foreach ($DeploymentType in $Application.AppDTs) {
                $AppType = 'Install',$DeploymentType.Id,$DeploymentType.Revision
                $AppContent = Invoke-WmiMethod -Namespace root\ccm\cimodels -Class CCM_AppDeliveryType -Name GetContentInfo -ArgumentList $AppType

                If ($Application.InstallState -eq 'Installed' -and $Application.IsMachineTarget -and $AppContent.ContentID) {
                    Remove-CacheItem -CacheTD $AppContent.ContentID -CacheN $Application.FullName
                }
                Else {
                    $Global:ExclusionList += $AppContent.ContentID
                }
            }
        }
    }

    Function Remove-CachedPackages {
        $PackageIDDeleteTrue = @()
        $PackageIDDeleteFalse = @()

        Try {
            $CM_Packages = Get-WmiObject -Namespace root\ccm\ClientSDK -Query 'SELECT PackageID,PackageName,LastRunStatus,RepeatRunBehavior FROM CCM_Program' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Package List from WMI - Failed!'
        }

        ForEach ($Program in $CM_Packages) {
            If ($Program.LastRunStatus -eq 'Succeeded' -and $Program.RepeatRunBehavior -ne 'RerunAlways' -and $Program.RepeatRunBehavior -ne 'RerunIfSuccess') {
                If ($Program.PackageID -notcontains $PackageIDDeleteTrue) {
                    $PackageIDDeleteTrue += $Program.PackageID
                }
            }
            Else {
                If ($Program.PackageID -notcontains $PackageIDDeleteFalse) {
                    $PackageIDDeleteFalse += $Program.PackageID
                }
            }
        }

        ForEach ($Package in $PackageIDDeleteTrue) {
            If ($CM_Packages.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Packages' -CurrentOperation $Package.PackageName -PercentComplete (($ProgressCounter / $CM_Packages.Count) * 100)
                Start-Sleep -Milliseconds 800
            }

            If ($Package -notcontains $PackageIDDeleteFalse) {
                Remove-CacheItem -CacheTD $Package.PackageID -CacheN $Package.PackageName
            }
            Else {
                $Global:ExclusionList += $Package.PackageID
            }
        }
    }

    Function Remove-CachedUpdates {
        Try {
            $CM_Updates = Get-WmiObject -Namespace root\ccm\SoftwareUpdates\UpdatesStore -Query 'SELECT UniqueID,Title,Status FROM CCM_UpdateStatus' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Software Update List from WMI - Failed!'
        }

        ForEach ($Update in $CM_Updates) {
            If ($CM_Updates.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Updates' -CurrentOperation $Update.Title -PercentComplete (($ProgressCounter / $CM_Updates.Count) * 100)
            }

            If ($Update.Status -eq 'Installed') {
                Remove-CacheItem -CacheTD $Update.UniqueID -CacheN $Update.Title
            }
            Else {
                $Global:ExclusionList += $Update.UniqueID
            }
        }
    }

    Function Remove-OrphanedCacheItems {
        ForEach ($CacheItem in $CacheItems) {
            If ($CacheItems.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Orphaned Cache Items' -CurrentOperation $CacheItem.ContentID -PercentComplete (($ProgressCounter / $CacheItems.Count) * 100)
            }

            If ($Global:ExclusionList -notcontains $CacheItem.ContentID) {
                Remove-CacheItem -CacheTD $CacheItem.ContentID -CacheN 'Orphaned Cache Item'
            }
        }
    }

    Function inetPubCleanup ($path) {
        $dirsToArchive = @()
        $zipsArray = @()

        $currentDate = Get-Date
        $dateToArchive = $currentDate.addMonths(-6)

        $files = Get-ChildItem $path | Where-Object {$_.LastWriteTime -lt $dateToArchive -and $_.Extension -eq ".log"}
        $zips = Get-ChildItem $path | where {$_.Extension -eq ".zip"}
        Foreach($zip in $zips) {
            $zipsArray +=$zip.Name
        }

        foreach($file in $files) {
            $newFolder = (Get-Culture).DateTimeFormat.GetMonthName($file.lastWriteTime.month)+$file.lastWriteTime.Year
            $dirPath = $path+"\"+$newFolder

            If($zipsArray.Contains($newFolder+".zip")) {
                Compress-Archive -Path $path"\"$file -Update -DestinationPath $dirPath".zip" -Verbose
                Remove-Item -Path $path"\"$file -Force -Verbose
            }
            Else {
                if(Test-Path $dirPath) {
                    if($dirsToArchive.Contains($dirPath)) {
                    }
                    else {
                        $dirsToArchive +=$dirPath
                    }
                    Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
                }
                else {
                    New-Item -ItemType Directory -path $dirPath
                    if($dirsToArchive.Contains($dirPath)) {
                    }
                    else {
                        $dirsToArchive +=$dirPath
                    }
                    Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
                }
            }
        }

        foreach($dirtoArchive in $dirsToArchive) {
            Compress-Archive -LiteralPath $dirToArchive -DestinationPath $dirToArchive
            Remove-Item -Path $dirtoArchive -Force -Recurse -Verbose
        }
    }

    Function Cleanup {
        $DaysToDelete = 5
        $LogDate = get-date -format "MM-d-yy-HH"
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.Namespace(0xA)
        $ErrorActionPreference = "SilentlyContinue"

        Start-Transcript -Path C:\Temp\Clean-DriveC.log

        Clear-Host

        $Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
        @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
        @{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
        @{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
        @{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize | Out-String 

        if(Test-Path "C:\Windows\SoftwareDistribution\Download") {
            Get-ChildItem "C:\Windows\SoftwareDistribution\Download" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
            remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
        }

        Get-ChildItem "C:\Windows\ccmcache" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
        remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue

        if(Test-Path "C:\Windows\CCM\Temp") {
            Get-ChildItem "C:\Windows\CCM\Temp" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
            remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
        }

        Get-ChildItem "C:\Windows\Temp\*" -function Invoke-CDisk-Cleanup {
    # Content from cleanup1.txt
    $fiser = Get-ChildItem C:\temp\*.log | select -expand fullname
    $fiser -match "housekeeping.log"
    If ($fiser -eq 'False') {
        New-Item -Path 'C:\Temp\housekeeping.log' -ItemType File
    }

    $ResultCSV = 'C:\Temp\housekeeping.log'
    If ((Get-Item $ResultCSV).Length -gt 5Mb) { 
        Remove-Item $ResultCSV -Force | Out-Null
    }

    $fiser = Get-ChildItem C:\temp\*.log | select -expand fullname
    $fiser -match "housekeeping.log"
    If ($fiser -eq 'False') {
        New-Item -Path 'C:\Temp\housekeeping.log' -ItemType File
    }

    $ResultCSV2 = New-Item -Path 'C:\Temp\removed.log' -ItemType File -Force

    $Drive_C_Before = Get-PSDrive C
    $Used_size_C_Before = [math]::Round(($Drive_C_Before.used/1GB), 2)
    $Free_size_C_Before = [math]::Round(($Drive_C_Before.free/1GB), 2)
    $ExcludedProfiles = @("Administrator","Public","SVC_DailyChecks")
    $ProfileFolders = Get-ChildItem -Directory C:\Users -Exclude $ExcludedProfiles | Select Name
    Foreach ($Folder in $ProfileFolders.Name) {
        remove-item -path "C:\Users\$Folder\AppData\Local\Microsoft\Windows\Temporary Internet Files\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\Users\$Folder\AppData\Local\Temp\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Terminal Server Client\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Teams\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Windows\InetCache\IE\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Windows\WebCache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Code Cache\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
        remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Service Worker\CacheStorage\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
    }

    $Drive_C_After = Get-PSDrive C
    $Used_size_C_After = [math]::Round(($Drive_C_After.used/1GB), 2)
    $Free_size_C_After = [math]::Round(($Drive_C_After.free/1GB), 2)
    $Gain_AllDrives = ($Free_size_C_After-$Free_size_C_Before)
    $data = Get-Date
    $sterse = Get-Content $ResultCSV2

    $Rezultate = "
    -------------------------------------------------------------------------
    Daily cleanup script results
    Hostname:$env:computername
    Date: $data
    -------------------------------------------------------------------------
    Disk usage before cleanup:
    
    Drive C: | Used GB: $Used_size_C_Before | Free GB: $Free_size_C_Before
    
    -------------------------------------------------------------------------
    Disk usage after cleanup:
    
    Drive C: | Used GB: $Used_size_C_After | Free GB: $Free_size_C_After
    
    -------------------------------------------------------------------------
    Total gain in GB: $Gain_AllDrives
    -------------------------------------------------------------------------
    Logs of file processed in this run be found down below (WARNING can be quite some files)
    $sterse
    -------------------
    Report END
    -------------------
    "

    $Rezultate >> $ResultCSV

    # Content from cleanup2.txt
    $Global:Result  =@()
    $Global:ExclusionList  =@()

    $ProgressCounter = 0

    $ResultCSV = 'C:\Temp\Clean-CMClientCache.log'
    If (Test-Path $ResultCSV) {
        If ((Get-Item $ResultCSV).Length -gt 500KB) {
            Remove-Item $ResultCSV -Force | Out-Null
        }
    }

    [String]$ResultPath =  Split-Path $ResultCSV -Parent
    If ((Test-Path $ResultPath) -eq $False) {
        New-Item -Path $ResultPath -Type Directory | Out-Null
    }

    $Date = Get-Date

    Function Write-Log {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [Alias('Name')]
            [string]$EventLogName = 'Configuration Manager',
            [Parameter(Mandatory=$false,Position=1)]
            [Alias('Source')]
            [string]$EventLogEntrySource = 'Clean-CMClientCache',
            [Parameter(Mandatory=$false,Position=2)]
            [Alias('ID')]
            [int32]$EventLogEntryID = 1,
            [Parameter(Mandatory=$false,Position=3)]
            [Alias('Type')]
            [string]$EventLogEntryType = 'Information',
            [Parameter(Mandatory=$true,Position=4)]
            [Alias('Message')]
            $EventLogEntryMessage
        )

        If (([System.Diagnostics.EventLog]::Exists($EventLogName) -eq $false) -or ([System.Diagnostics.EventLog]::SourceExists($EventLogEntrySource) -eq $false )) {
            New-EventLog -LogName $EventLogName -Source $EventLogEntrySource
        }

        $ResultString = Out-String -InputObject $Result -Width 1000
        Write-EventLog -LogName $EventLogName -Source $EventLogEntrySource -EventId $EventLogEntryID -EntryType $EventLogEntryType -Message $ResultString

        $EventLogEntryMessage | Export-Csv -Path $ResultCSV -Delimiter ';' -Encoding UTF8 -NoTypeInformation -Append -Force

        $EventLogEntryMessage | Format-Table Name,TotalDeleted`(MB`)
    }

    Function Remove-CacheItem {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,Position=0)]
            [Alias('CacheTD')]
            [string]$CacheItemToDelete,
            [Parameter(Mandatory=$true,Position=1)]
            [Alias('CacheN')]
            [string]$CacheItemName
        )

        If ($CacheItems.ContentID -contains $CacheItemToDelete) {
            $CacheItemLocation = $CacheItems | Where {$_.ContentID -Contains $CacheItemToDelete} | Select -ExpandProperty Location
            $CacheItemSize =  Get-ChildItem $CacheItemLocation -Recurse -Force | Measure-Object -Property Length -Sum | Select -ExpandProperty Sum

            If ($CacheItemSize -gt '0.00') {
                $CMObject = New-Object -ComObject 'UIResource.UIResourceMgr'
                $CMCacheObjects = $CMObject.GetCacheInfo()
                $CMCacheObjects.GetCacheElements() | Where-Object {$_.ContentID -eq $CacheItemToDelete} |
                    ForEach-Object {
                        $CMCacheObjects.DeleteCacheElement($_.CacheElementID)
                        Write-Host 'Deleted: '$CacheItemName -Verbose
                    }

                $ResultProps = [ordered]@{
                    'Name' = $CacheItemName
                    'ID' = $CacheItemToDelete
                    'Location' = $CacheItemLocation
                    'Size(MB)' = '{0:N2}' -f ($CacheItemSize / 1MB)
                    'Status' = 'Deleted!'
                }

                $Global:Result  += New-Object PSObject -Property $ResultProps
            }
        }
        Else {
            Write-Host 'Already Deleted:'$CacheItemName '|| ID:'$CacheItemToDelete -Verbose
        }
    }

    Function Remove-CachedApplications {
        Try {
            $CM_Applications = Get-WmiObject -Namespace root\ccm\ClientSDK -Query 'SELECT * FROM CCM_Application' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Application List from WMI - Failed!'
        }

        Foreach ($Application in $CM_Applications) {
            If ($CM_Applications.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Applications' -CurrentOperation $Application.FullName -PercentComplete (($ProgressCounter / $CM_Applications.Count) * 100)
            }

            $Application.Get()

            Foreach ($DeploymentType in $Application.AppDTs) {
                $AppType = 'Install',$DeploymentType.Id,$DeploymentType.Revision
                $AppContent = Invoke-WmiMethod -Namespace root\ccm\cimodels -Class CCM_AppDeliveryType -Name GetContentInfo -ArgumentList $AppType

                If ($Application.InstallState -eq 'Installed' -and $Application.IsMachineTarget -and $AppContent.ContentID) {
                    Remove-CacheItem -CacheTD $AppContent.ContentID -CacheN $Application.FullName
                }
                Else {
                    $Global:ExclusionList += $AppContent.ContentID
                }
            }
        }
    }

    Function Remove-CachedPackages {
        $PackageIDDeleteTrue = @()
        $PackageIDDeleteFalse = @()

        Try {
            $CM_Packages = Get-WmiObject -Namespace root\ccm\ClientSDK -Query 'SELECT PackageID,PackageName,LastRunStatus,RepeatRunBehavior FROM CCM_Program' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Package List from WMI - Failed!'
        }

        ForEach ($Program in $CM_Packages) {
            If ($Program.LastRunStatus -eq 'Succeeded' -and $Program.RepeatRunBehavior -ne 'RerunAlways' -and $Program.RepeatRunBehavior -ne 'RerunIfSuccess') {
                If ($Program.PackageID -notcontains $PackageIDDeleteTrue) {
                    $PackageIDDeleteTrue += $Program.PackageID
                }
            }
            Else {
                If ($Program.PackageID -notcontains $PackageIDDeleteFalse) {
                    $PackageIDDeleteFalse += $Program.PackageID
                }
            }
        }

        ForEach ($Package in $PackageIDDeleteTrue) {
            If ($CM_Packages.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Packages' -CurrentOperation $Package.PackageName -PercentComplete (($ProgressCounter / $CM_Packages.Count) * 100)
                Start-Sleep -Milliseconds 800
            }

            If ($Package -notcontains $PackageIDDeleteFalse) {
                Remove-CacheItem -CacheTD $Package.PackageID -CacheN $Package.PackageName
            }
            Else {
                $Global:ExclusionList += $Package.PackageID
            }
        }
    }

    Function Remove-CachedUpdates {
        Try {
            $CM_Updates = Get-WmiObject -Namespace root\ccm\SoftwareUpdates\UpdatesStore -Query 'SELECT UniqueID,Title,Status FROM CCM_UpdateStatus' -ErrorAction Stop
        }
        Catch {
            Write-Host 'Get SCCM Software Update List from WMI - Failed!'
        }

        ForEach ($Update in $CM_Updates) {
            If ($CM_Updates.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Updates' -CurrentOperation $Update.Title -PercentComplete (($ProgressCounter / $CM_Updates.Count) * 100)
            }

            If ($Update.Status -eq 'Installed') {
                Remove-CacheItem -CacheTD $Update.UniqueID -CacheN $Update.Title
            }
            Else {
                $Global:ExclusionList += $Update.UniqueID
            }
        }
    }

    Function Remove-OrphanedCacheItems {
        ForEach ($CacheItem in $CacheItems) {
            If ($CacheItems.Count -ne $null) {
                $ProgressCounter++
                Write-Progress -Activity 'Processing Orphaned Cache Items' -CurrentOperation $CacheItem.ContentID -PercentComplete (($ProgressCounter / $CacheItems.Count) * 100)
            }

            If ($Global:ExclusionList -notcontains $CacheItem.ContentID) {
                Remove-CacheItem -CacheTD $CacheItem.ContentID -CacheN 'Orphaned Cache Item'
            }
        }
    }

    Function inetPubCleanup ($path) {
        $dirsToArchive = @()
        $zipsArray = @()

        $currentDate = Get-Date
        $dateToArchive = $currentDate.addMonths(-6)

        $files = Get-ChildItem $path | Where-Object {$_.LastWriteTime -lt $dateToArchive -and $_.Extension -eq ".log"}
        $zips = Get-ChildItem $path | where {$_.Extension -eq ".zip"}
        Foreach($zip in $zips) {
            $zipsArray +=$zip.Name
        }

        foreach($file in $files) {
            $newFolder = (Get-Culture).DateTimeFormat.GetMonthName($file.lastWriteTime.month)+$file.lastWriteTime.Year
            $dirPath = $path+"\"+$newFolder

            If($zipsArray.Contains($newFolder+".zip")) {
                Compress-Archive -Path $path"\"$file -Update -DestinationPath $dirPath".zip" -Verbose
                Remove-Item -Path $path"\"$file -Force -Verbose
            }
            Else {
                if(Test-Path $dirPath) {
                    if($dirsToArchive.Contains($dirPath)) {
                    }
                    else {
                        $dirsToArchive +=$dirPath
                    }
                    Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
                }
                else {
                    New-Item -ItemType Directory -path $dirPath
                    if($dirsToArchive.Contains($dirPath)) {
                    }
                    else {
                        $dirsToArchive +=$dirPath
                    }
                    Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
                }
            }
        }

        foreach($dirtoArchive in $dirsToArchive) {
            Compress-Archive -LiteralPath $dirToArchive -DestinationPath $dirToArchive
            Remove-Item -Path $dirtoArchive -Force -Recurse -Verbose
        }
    }

    Function Cleanup {
        $DaysToDelete = 5
        $LogDate = get-date -format "MM-d-yy-HH"
        $objShell = New-Object -ComObject Shell.Application
        $objFolder = $objShell.Namespace(0xA)
        $ErrorActionPreference = "SilentlyContinue"

        Start-Transcript -Path C:\Temp\Clean-DriveC.log

        Clear-Host

        $Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
        @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
        @{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
        @{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
        @{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } |
        Format-Table -AutoSize | Out-String 

        if(Test-Path "C:\Windows\SoftwareDistribution\Download") {
            Get-ChildItem "C:\Windows\SoftwareDistribution\Download" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
            remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
        }

        Get-ChildItem "C:\Windows\ccmcache" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
        remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue

        if(Test-Path "C:\Windows\CCM\Temp") {
            Get-ChildItem "C:\Windows\CCM\Temp" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
            remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
        }

        Get-ChildItem "C:\Windows\Temp\*" -