function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        # Only call Get-Credential if no credential was provided
        if ($null -eq $Credential) {
            $Credential = Get-Credential
        }
        if ($null -eq $Credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            if ($retryCount -ge $maxRetries) {
                return $null
            }
        }
    } while ($true)
}

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
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-0) }

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