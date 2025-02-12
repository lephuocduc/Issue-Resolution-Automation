# Set paths
$scriptManagerPath = Join-Path $PSScriptRoot "ScriptManager2.ps1"
$scriptsPath = Join-Path $PSScriptRoot "Scripts"

function Update-ScriptManagerContent {
    # Get all PS1 files except ScriptManager2.ps1
    $scriptFiles = Get-ChildItem -Path $scriptsPath -Filter "*.ps1" | 
                  Where-Object { $_.Name -ne "ScriptManager2.ps1" }
    
    # Read ScriptManager2.ps1
    $content = Get-Content -Path $scriptManagerPath -Raw

    # Update ComboBox items
    $scriptNames = $scriptFiles | ForEach-Object { 
        [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
    }
    $comboBoxItems = '"------------------------------",' + ($scriptNames | ForEach-Object { "'$_'" } -join ',')
    $content = $content -replace '(?<=\$comboBox\.Items\.AddRange\(@\().*?(?=\))', $comboBoxItems

    # Build switch cases
    $switchCases = @()
    $switchCases += '        "------------------------------"{'
    $switchCases += '            [System.Windows.Forms.MessageBox]::Show('
    $switchCases += '                "Please select a script from the dropdown.",'
    $switchCases += '                "Information",'
    $switchCases += '                [System.Windows.Forms.MessageBoxButtons]::OK,'
    $switchCases += '                [System.Windows.Forms.MessageBoxIcon]::Information'
    $switchCases += '            )'
    $switchCases += '            return'
    $switchCases += '        }'

    foreach ($script in $scriptFiles) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($script.Name)
        $switchCases += @"
        "$name" {
            . (Join-Path `$PSScriptRoot 'Scripts\$($script.Name)')
        }
"@
    }

    $switchCases += '        default {'
    $switchCases += '            [System.Windows.Forms.MessageBox]::Show('
    $switchCases += '                "No script is associated with the selection ''$selectedValue''.",'
    $switchCases += '                "Error",'
    $switchCases += '                [System.Windows.Forms.MessageBoxButtons]::OK,'
    $switchCases += '                [System.Windows.Forms.MessageBoxIcon]::Error'
    $switchCases += '            )'
    $switchCases += '            return'
    $switchCases += '        }'

    # Update switch section
    $switchPattern = '(?<=switch \(\$selectedValue\) \{).*?(?=\})'
    $newSwitchContent = "`n" + ($switchCases -join "`n") + "`n    "
    $content = $content -replace $switchPattern, $newSwitchContent

    # Save changes
    $content | Set-Content -Path $scriptManagerPath -Force
}

# Create FileSystemWatcher
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $scriptsPath
$watcher.Filter = "*.ps1"
$watcher.IncludeSubdirectories = $false
$watcher.EnableRaisingEvents = $true

# Define events
$action = {
    Start-Sleep -Seconds 1  # Wait for file operations to complete
    Update-ScriptManagerContent
}

# Register events
Register-ObjectEvent $watcher "Created" -Action $action
Register-ObjectEvent $watcher "Deleted" -Action $action
Register-ObjectEvent $watcher "Changed" -Action $action
Register-ObjectEvent $watcher "Renamed" -Action $action

# Initial update
Update-ScriptManagerContent

Write-Host "Watching Scripts folder for changes. Press Ctrl+C to stop."
while ($true) { Start-Sleep -Seconds 1 }