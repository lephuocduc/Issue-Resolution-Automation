$scriptManagerPath = Join-Path $PSScriptRoot "ScriptManager.ps1"
$scriptsRootPath = Join-Path $PSScriptRoot "..\Scripts"

function Update-ScriptManagerContent {
    try {
        # Get script names from subfolders
        $scriptNames = Get-ChildItem -Path $scriptsRootPath -Directory | ForEach-Object {
            $folderName = $_.Name
            Get-ChildItem -Path $_.FullName -Filter "*.ps1" | 
            Select-Object @{
                Name = 'Name'
                Expression = { $_.BaseName }
            }, @{
                Name = 'Folder'
                Expression = { $folderName }
            }
        }
        
        Write-Host "Found scripts: $($scriptNames.Name -join ', ')"

        # Read content
        $content = Get-Content $scriptManagerPath -Raw

        # Update ComboBox items
        $comboBoxPattern = '\$comboBox\.Items\.AddRange\(@\([^)]+\)\)'
        $newComboBoxItems = "`$comboBox.Items.AddRange(@('" + ($scriptNames.Name -join "','") + "'))"
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
            $switchCases += @"

        "$($script.Name)" {
            . (Join-Path `$PSScriptRoot "..\Scripts\$($script.Folder)\$($script.Name).ps1") -ADM_Credential `$script:ADM_Credential
        }
"@
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
        Write-Host "ScriptManager.ps1 updated successfully"
    }
    catch {
        Write-Error "Error updating ScriptManager.ps1: $_"
    }
}

# Execute update
Update-ScriptManagerContent