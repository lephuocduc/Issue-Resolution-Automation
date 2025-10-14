function Get-TopItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory=$true)]
        [string]$path,
        [string[]]$exclude = @(),
        [int]$topN = 10
    )

    try {
        $scriptBlock = {
            param($path, $exclude, $topN)
            
            try {
                # Convert exclude list to HashSet for O(1) lookups
                $excludeSet = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
                foreach ($item in $exclude) { [void]$excludeSet.Add($item) }

                # Cache for folder sizes
                $folderSizeCache = @{}
                
                # Recursive function to calculate folder sizes with caching
                function Get-FolderSize {
                    param($folderPath)
                    
                    # Return cached value if available
                    if ($folderSizeCache.ContainsKey($folderPath)) {
                        return $folderSizeCache[$folderPath]
                    }
                    
                    $size = 0
                    $childItems = $null
                    try {
                        $childItems = Get-ChildItem -LiteralPath $folderPath -ErrorAction Stop
                    } catch {
                        Write-Host "Access error in $folderPath': $_"
                        $folderSizeCache[$folderPath] = 0
                        return 0
                    }
                    
                    foreach ($item in $childItems) {
                        # Skip excluded items
                        if ($excludeSet.Contains($item.Name)) { continue }
                        
                        if ($item.PSIsContainer) {
                            $size += Get-FolderSize $item.FullName
                        } else {
                            $size += $item.Length
                        }
                    }
                    
                    # Update cache and return
                    $folderSizeCache[$folderPath] = $size
                    return $size
                }

                # Process root items
                $rootItems = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                             Where-Object { -not $excludeSet.Contains($_.Name) }
                
                if (-not $rootItems) {
                    Write-Host "No items found in $path after exclusions."
                    return @()
                }

                $results = foreach ($item in $rootItems) {
                    $sizeBytes = if ($item.PSIsContainer) {
                        Get-FolderSize $item.FullName
                    } else {
                        $item.Length
                    }
                    
                    [PSCustomObject]@{
                        Name     = $item.Name
                        FullPath = $item.FullName
                        SizeGB   = [math]::Round($sizeBytes / 1GB, 2)
                        IsFolder = $item.PSIsContainer
                    }
                }

                # Get top N items
                $topItems = $results | Sort-Object SizeGB -Descending | Select-Object -First $topN

                # Process top items
                $detailedOutput = foreach ($item in $topItems) {
                    $output = [PSCustomObject]@{
                        Name     = $item.Name
                        SizeGB   = $item.SizeGB
                        Type     = if ($item.IsFolder) { "Folder" } else { "File" }
                        SubItems = @()
                    }

                    if ($item.IsFolder) {
                        $childItems = Get-ChildItem -LiteralPath $item.FullPath -ErrorAction SilentlyContinue |
                                      Where-Object { -not $excludeSet.Contains($_.Name) }
                        
                        $childObjects = foreach ($child in $childItems) {
                            $childSizeBytes = if ($child.PSIsContainer) {
                                $folderSizeCache[$child.FullName]
                            } else {
                                $child.Length
                            }
                            
                            [PSCustomObject]@{
                                Name   = $child.Name
                                SizeMB = [math]::Round($childSizeBytes / 1MB, 2)
                                Type   = if ($child.PSIsContainer) { "Folder" } else { "File" }
                            }
                        }
                        
                        $output.SubItems = $childObjects | Sort-Object SizeMB -Descending | Select-Object -First 10
                    }
                    $output
                }

                return $detailedOutput
            } catch {
                Write-Host "Error in Get-TopItems script block: $_"
                return @()
            }
        }

        # Execute the script block on the remote session
        $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $path, $exclude, $topN
        Write-Host "Retrieved top $topN items in '$path'"
        return $result
    } catch {
        $errorDetails = "Exception: $($_.Exception.GetType().FullName)`nMessage: $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)"
        Write-Host "Error executing Get-TopItems: $errorDetails"
        return @()
    }
}