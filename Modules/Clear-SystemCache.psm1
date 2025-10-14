function Clear-SystemCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    try {
        Write-Host "Starting to clear system cache"
        $ScriptBlock = {
            # Define cache locations and configurations
            $cacheConfigs = @(
                @{ 
                    Name = "Windows Update cache"
                    Path = "C:\Windows\SoftwareDistribution\Download\*"
                },
                @{ 
                    Name = "Windows Installer patch cache"
                    Path = "C:\Windows\Installer\$PatchCache$\*"
                },
                @{ 
                    Name = "SCCM cache"
                    Path = 'C:\Windows\ccmcache\*' 
                },
                @{ 
                    Name = "Windows Temp files"
                    Path = "C:\Windows\Temp\*"
                }
            )

            $daysOld = 5
            $cutoffDate = (Get-Date).AddDays(-$daysOld)

            # Process all file-based caches
            foreach ($config in $cacheConfigs) {
                try {
                    Write-Host "`nProcessing $($config.Name)..."
                    
                    if (-not (Test-Path -Path $config.Path -ErrorAction SilentlyContinue)) {
                        Write-Host "$($config.Name) not found - Skipping" -ForegroundColor Yellow
                        continue
                    }

                    $filesToDelete = Get-ChildItem -Path $config.Path -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -lt $cutoffDate }

                    if (-not $filesToDelete) {
                        Write-Host "No expired files found in $($config.Name)"
                        continue
                    }

                    Write-Host "Found $($filesToDelete.Count) files to delete:"
                    $successCount = 0
                    $errorCount = 0

                    foreach ($file in $filesToDelete) {
                        try {
                            Remove-Item -Path $file.FullName -Force -Recurse -ErrorAction Stop
                            Write-Host "  Deleted: $($file.FullName)" -ForegroundColor Green
                            $successCount++
                        }
                        catch {
                            Write-Host "  Error deleting: $($file.FullName)" -ForegroundColor Red
                            Write-Host "    Reason: $($_.Exception.Message)" -ForegroundColor Red
                            $errorCount++
                        }
                    }
                    
                    Write-Host "`n$($config.Name) results: $successCount deleted, $errorCount errors" -ForegroundColor Cyan
                }
                catch {
                    Write-Host "Error processing $($config.Name): $_" -ForegroundColor Red
                }
            }

            # Process Recycle Bin separately
            try {
                Write-Host "`nClearing Recycle Bin..."
                Clear-RecycleBin -Force -ErrorAction Stop
                Write-Host "Recycle Bin cleared" -ForegroundColor Green
            }
            catch {
                Write-Host "Error clearing Recycle Bin: $_" -ForegroundColor Red
            }
        }
        
        Invoke-Command -Session $session -ScriptBlock $ScriptBlock
        Write-Host "`nCache clearing operation completed" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error clearing system cache: $_" -ForegroundColor Red
    }
}