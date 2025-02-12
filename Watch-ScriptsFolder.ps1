$scriptManagerPath = Join-Path $PSScriptRoot "ScriptManager2.ps1"
$scriptsPath = Join-Path $PSScriptRoot "Scripts"

function Update-ScriptManagerContent {
    try {
        # Get script names
        $scriptNames = Get-ChildItem -Path $scriptsPath -Filter "*.ps1" |
                      Select-Object -ExpandProperty BaseName
        
        Write-Host "Found scripts: $($scriptNames -join ', ')"

        # Read content
        $content = Get-Content $scriptManagerPath -Raw

        # Update ComboBox items
        $comboBoxPattern = '\$comboBox\.Items\.AddRange\(@\([^)]+\)\)'
        $newComboBoxItems = "`$comboBox.Items.AddRange(@('" + ($scriptNames -join "','") + "'))"
        $content = $content -replace $comboBoxPattern, $newComboBoxItems

        # Build switch cases with proper formatting
        $switchCases = @"
        "------------------------------" {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a script from the dropdown.",
                "Information",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
"@

        foreach ($script in $scriptNames) {
            $switchCases += "`r`n        `"$script`" {`r`n            . (Join-Path `$PSScriptRoot 'Scripts\$script.ps1')`r`n        }"
        }

        $switchCases += @"

        default {
            [System.Windows.Forms.MessageBox]::Show(
                "No script is associated with the selection '`$selectedValue'.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
"@

        # Update switch block with proper formatting
        $switchPattern = '(?s)switch \(\$selectedValue\) \{.*?default \{.*?\}\s*\}'
        $newSwitchBlock = "switch (`$selectedValue) {$switchCases}`r`n    }"
        $content = $content -replace $switchPattern, $newSwitchBlock

        $content | Set-Content $scriptManagerPath -Force
        Write-Host "ScriptManager2.ps1 updated successfully"
    }
    catch {
        Write-Error "Error updating ScriptManager2.ps1: $_"
    }
}

# Execute update
Update-ScriptManagerContent