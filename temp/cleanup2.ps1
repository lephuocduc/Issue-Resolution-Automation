<#
     Script to cleanup C drive
    It will cleanup the folowing folders:
    C:\Windows\SoftwareDistribution\Download
    C:\Windows\Temp\
    C:\users\*\AppData\Local\Temp\
    C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\
    C:\users\*\AppData\Local\Microsoft\Teams\
    C:\Windows\Installer\$PatchCache$ 
    C:\Windows\CCM\Temp
    C:\Windows\ccmcache
    Recycle Bin
 
    All files in above locations have no impact if deleted.
 
    Also, the script does not delete files newer than 5 days but this can be altered using the $DaysToDelete
    A log file will be created in C:\Windows\Temp at the end.
 
    The option to delete any .iso and .vhd files is also included but currently commented.
 
    Logs older than 6 months under C:\inetpub\logs\LogFiles\* will be archived.
#>
 
 
## Global variables
$Global:Result  =@()
$Global:ExclusionList  =@()
 
## Initialize progress Counter
$ProgressCounter = 0
 
## Configure Logging
#  Set log path
$ResultCSV = 'C:\Temp\Clean-CMClientCache.log'
 
#  Remove previous log it it's more than 500 KB
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
 
Function inetPubCleanup ($path)
{
   
    $dirsToArchive = @()
    $zipsArray = @()
 
 
    $currentDate = Get-Date
    $dateToArchive = $currentDate.addMonths(-6)
 
    $files = Get-ChildItem $path | Where-Object {$_.LastWriteTime -lt $dateToArchive -and $_.Extension -eq ".log"}
    $zips = Get-ChildItem $path | where {$_.Extension -eq ".zip"}
    Foreach($zip in $zips)
    {
        $zipsArray +=$zip.Name
    }
 
 
    foreach($file in $files)
    {
        $newFolder = (Get-Culture).DateTimeFormat.GetMonthName($file.lastWriteTime.month)+$file.lastWriteTime.Year
 
        $dirPath = $path+"\"+$newFolder
 
        If($zipsArray.Contains($newFolder+".zip"))
        {
            Compress-Archive -Path $path"\"$file -Update -DestinationPath $dirPath".zip" -Verbose
            Remove-Item -Path $path"\"$file -Force -Verbose
        }
        Else
        {
            if(Test-Path $dirPath)
            {
               
                if($dirsToArchive.Contains($dirPath))
                {
                   
                }
                else
                {
                    $dirsToArchive +=$dirPath
                }
                Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
            }
            else
            {
                New-Item -ItemType Directory -path $dirPath
                if($dirsToArchive.Contains($dirPath))
                {
                   
                }
                else
                {
                    $dirsToArchive +=$dirPath
                }
                Move-Item -Path $path"\"$file -Destination $dirPath -Verbose
            }
      
         }
    }
 
    foreach($dirtoArchive in $dirsToArchive)
    {
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
 
#$size = Get-ChildItem C:\Users\* -Include *.iso, *.vhd -Recurse -ErrorAction SilentlyContinue |
#Sort Length -Descending |
#Select-Object Name, Directory,
#@{Name="Size (GB)";Expression={ "{0:N2}" -f ($_.Length / 1GB) }} |
#Format-Table -AutoSize | Out-String
 
$Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
@{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
@{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
@{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
@{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } |
Format-Table -AutoSize | Out-String 
             
                    
## Stops the windows update service.
#Get-Service -Name wuauserv | Stop-Service -Force -Verbose -ErrorAction SilentlyContinue
## Windows Update Service has been stopped successfully!
 
## Deletes the contents of windows software distribution download.
if(Test-Path "C:\Windows\SoftwareDistribution\Download")
{
    Get-ChildItem "C:\Windows\SoftwareDistribution\Download" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
    Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
    remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
}
## The Contents of Windows SoftwareDistribution have been removed successfully!
 
<######################## Deletes the contents of windows ccmcache.
Get-ChildItem "C:\Windows\ccmcache" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows ccmcache have been removed successfully! #>
 
## Deletes the contents of windows CCM Temp.
if(Test-Path "C:\Windows\CCM\Temp")
{
    Get-ChildItem "C:\Windows\CCM\Temp" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
    Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
    remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
}
## The Contents of Windows CCM Temp have been removed successfully!
 
## Deletes the contents of the Windows Temp folder.
Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete)) } |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The Contents of Windows Temp have been removed successfully!
            
## Delets all files and folders in user's Temp folder.
Get-ChildItem "C:\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## The contents of C:\users\$env:USERNAME\AppData\Local\Temp\ have been removed successfully!
                   
## Remove all files and folders in user's Temporary Internet Files.
Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -recurse -ErrorAction SilentlyContinue
## All Temporary Internet Files have been removed successfully!
 
## Remove all files and folders in user's Temporary Teams Files.
Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Teams\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -recurse -ErrorAction SilentlyContinue
## All Temporary Teams Files have been removed successfully!
 
## Remove all files and folders in user's Temporary Teams Files.
Get-ChildItem "C:\users\*\AppData\Roaming\Microsoft\Teams\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -recurse -ErrorAction SilentlyContinue
## All Temporary Teams Files have been removed successfully!
 
## Remove Chrome cache for all users.
Get-ChildItem "C:\users\*\AppData\Local\Google\Chrome\User Data\Default\Cache\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## Chrome cache removed.
 
## Remove Chrome Code Cache for all users.
Get-ChildItem "C:\users\*\AppData\Local\Google\Chrome\User Data\Default\Code Cache\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## Chrome Code Cache removed.
 
## Remove Chrome GPUCache for all users.
Get-ChildItem "C:\users\*\AppData\Local\Google\Chrome\User Data\Default\GPUCache\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## Chrome GPUCache removed.
 
## Remove Chrome cache store for all users.
Get-ChildItem "C:\users\*\AppData\Local\Google\Chrome\User Data\Default\optimization_guide_hint_cache_store\*" `
-Recurse -Force -Verbose -ErrorAction SilentlyContinue |
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-$DaysToDelete))} |
remove-item -force -Verbose -recurse -ErrorAction SilentlyContinue
## Chrome cache store removed.
                   
## Cleans IIS Logs if applicable.
if(Test-Path "C:\inetpub\logs\LogFiles")
{
    $basePath = "C:\inetpub\logs\LogFiles"
    $inetPubDirs = Get-ChildItem -Directory -Path $basePath
    foreach($inetPubDir in $inetPubDirs)
    {
        inetPubCleanup($basePath+'\'+$inetPubDir.name)
    }
}
 
<#Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(-60)) } |
Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue#>
## All IIS Logfiles over x days old have been removed Successfully!
 
##Cleans Installer $PatchCache$ folder
Get-ChildItem 'C:\Windows\Installer\$PatchCache$\*' -Recurse -Force -ErrorAction SilentlyContinue |
#Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(-60)) } |
Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue
## All $PatchCache$ items have been removed Successfully!
                 
## deletes the contents of the recycling Bin.
## The Recycling Bin is now being emptied!
##$objFolder.items() | ForEach-Object { Remove-Item $_.path -ErrorAction Ignore -Force -Verbose -Recurse }
## The Recycling Bin has been emptied!
 
## Starts the Windows Update Service
#Get-Service -Name wuauserv | Start-Service -Verbose
 
if(Test-Path "C:\Windows\CCM")
{
    ## Get list of all non persisted content in CCMCache, only this content will be removed
    Try {
        $CacheItems = Get-WmiObject -Namespace root\ccm\SoftMgmtAgent -Query 'SELECT ContentID,Location FROM CacheInfoEx WHERE PersistInCache != 1' -ErrorAction Stop
    }
    #  Write to log in case of failure
    Catch {
        Write-Host 'Getting SCCM Cache Info from WMI - Failed! Check if SCCM Client is Installed!'
    }
 
    ## Call Remove-CachedApplications function
    Remove-CachedApplications
 
    ## Call Remove-CachedApplications function
    Remove-CachedPackages
 
    ## Call Remove-CachedApplications function
    Remove-CachedUpdates
 
    ## Call Remove-OrphanedCacheItems function
    Remove-OrphanedCacheItems
 
    ## Get Result sort it and build Result Object
    $Result =  $Global:Result | Sort-Object Size`(MB`) -Descending
 
    #  Calculate total deleted size
    $TotalDeletedSize = $Result | Measure-Object -Property Size`(MB`) -Sum | Select -ExpandProperty Sum
 
    #  If $TotalDeletedSize is zero write that nothing could be deleted
    If ($TotalDeletedSize -eq $null -or $TotalDeletedSize -eq '0.00') {
        $TotalDeletedSize = 'Nothing to Delete!'
    }
    Else {
        $TotalDeletedSize = '{0:N2}' -f $TotalDeletedSize
        }
 
    #  Build Result Object
    $ResultProps = [ordered]@{
        'Name' = 'Total Size of Items Deleted in MB: '+$TotalDeletedSize
        'ID' = 'N/A'
        'Location' = 'N/A'
        'Size(MB)' = 'N/A'
        'Status' = ' ***** Last Run Date: '+$Date+' *****'
    }
 
    #  Add total items deleted to result object
    $Result += New-Object PSObject -Property $ResultProps
 
    ## Write to log and console
    Write-Log -Message $Result
 
    ## Let the user know we are finished
    Write-Host 'Processing Finished!' -Verbose
}
 
 
$After =  Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,
@{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
@{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
@{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
@{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } |
Format-Table -AutoSize | Out-String
 
Hostname ; Get-Date | Select-Object DateTime
Write-Host "Before: $Before"
Write-Host "After: $After"
Write-Host $size
## Completed Successfully!
Stop-Transcript
Write-host ""
Read-Host -Prompt "Press Enter to exit"
}
 
#endregion
 
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
  }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
  
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
  
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
  
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
  
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
  
   # Exit from the current, unelevated, process
   exit
   }
 
Cleanup
========================================================
