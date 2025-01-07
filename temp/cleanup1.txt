$fiser = Get-ChildItem C:\temp\*.log | select -expand fullname
$fiser -match "housekeeping.log"
If ($fiser -eq 'False') {
New -Item -Path 'C:\Temp\housekeeping.log' -ItemType File
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
 
$ResultCSV2 =New-Item -Path 'C:\Temp\removed.log' -ItemType File -Force
 
$Drive_C_Before = Get-PSDrive C
$Used_size_C_Before = [math]::Round(($Drive_C_Before.used/1GB), 2)
$Free_size_C_Before = [math]::Round(($Drive_C_Before.free/1GB), 2)
$ExcludedProfiles = @("Administrator","Public","SVC_DailyChecks")
$ProfileFolders = Get-ChildItem -Directory C:\Users -Exclude $ExcludedProfiles | Select Name
Foreach ($Folder in $ProfileFolders.Name)
{
remove-item -path "C:\Users\$Folder\AppData\Local\Microsoft\Windows\Temporary Internet Files\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
remove-item -path "C:\Users\$Folder\AppData\Local\Temp\" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
remove-item -path "C:\users\$Folder\AppData\Local\Microsoft\Terminal Server Client\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
remove-item -path "C:\users\$Folder\AppData\Local\Google\Chrome\User Data\Default\Cache" -force -Recurse -Verbose 4>>$ResultCSV2  -ErrorAction SilentlyContinue
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
$data =Get-Date
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
