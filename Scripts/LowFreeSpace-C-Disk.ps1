# Still Coding

function Invoke-DiskCleanup {
    param($session)

    Invoke-Command -Session $session -ScriptBlock {
        # Run Disk Cleanup tool
        if (Test-Path "C:\Windows\System32\cleanmgr.exe") {
            Start-Process cleanmgr.exe -ArgumentList "/d C: /VERYLOWDISK /AUTOCLEAN" -NoNewWindow
        }
    }
}

function Invoke-CleanupScripts {
    param($session)
    
    try {
        # Copy cleanup scripts to remote server
        $cleanup1 = Get-Content "$PSScriptRoot/../temp/cleanup1.txt" -Raw
        $cleanup2 = Get-Content "$PSScriptRoot/../temp/cleanup2.txt" -Raw

        Invoke-Command -Session $session -ScriptBlock {
            param($script1, $script2)
            
            # Create temp directory if not exists
            if (-not (Test-Path "C:\temp")) {
                New-Item -ItemType Directory -Path "C:\temp" -Force
            }

            # Save scripts to remote server
            $script1 | Out-File "C:\temp\cleanup1.ps1" -Force
            $script2 | Out-File "C:\temp\cleanup2.ps1" -Force

            # Execute cleanup scripts
            & powershell.exe -ExecutionPolicy Bypass -File "C:\temp\cleanup1.ps1"
            & powershell.exe -ExecutionPolicy Bypass -File "C:\temp\cleanup2.ps1"

            # Cleanup temp scripts
            Remove-Item "C:\temp\cleanup1.ps1" -Force
            Remove-Item "C:\temp\cleanup2.ps1" -Force
        } -ArgumentList $cleanup1, $cleanup2
        
        return $true
    }
    catch {
        Write-Message "Error executing cleanup scripts: $_"
        return $false
    }
}

function Start-CDiskCleanup {
    param($serverName)

    if (-not (Test-ServerAvailability -serverName $serverName)) {
        Write-Message "Server '$serverName' is not available."
        return
    }

    $session = Get-Session -serverName $serverName
    if ($null -eq $session) {
        Write-Message "Failed to create session to '$serverName'."
        return
    }

    try {
        Write-Message "Starting disk cleanup on '$serverName'..."
        
        # Run Windows Disk Cleanup
        Invoke-DiskCleanup -session $session

        # Run custom cleanup scripts
        if (Invoke-CleanupScripts -session $session) {
            Write-Message "Cleanup completed successfully on '$serverName'."
        }
        else {
            Write-Message "Cleanup failed on '$serverName'."
        }
    }
    catch {
        Write-Message "Error during cleanup: $_"
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }
}

# Main execution
Start-CDiskCleanup -serverName $ServerName