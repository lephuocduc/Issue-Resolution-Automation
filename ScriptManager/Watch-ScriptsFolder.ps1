$scriptManagerPath = Join-Path $PSScriptRoot "ScriptManager.ps1"
$scriptsRootPath = Join-Path $PSScriptRoot "..\Scripts"

# Helper function to insert spaces before capital letters
function Split-CamelCase {
    param (
        [string]$Text
    )
    $result = ""
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $char = $Text[$i]
        if ($i -gt 0 -and [char]::IsUpper($char)) {
            $result += " "
        }
        $result += $char
    }
    return $result
}

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
                Name = 'DisplayName'
                Expression = { Split-CamelCase $_.BaseName }
            }, @{
                Name = 'Folder'
                Expression = { $folderName }
            }
        }
        
        Write-Host "Found scripts: $($scriptNames.Name -join ', ')"

        # Read content
        $content = Get-Content $scriptManagerPath -Raw

        # Update ComboBox items with display names
        $comboBoxPattern = '\$comboBox\.Items\.AddRange\(@\([^)]+\)\)'
        $newComboBoxItems = "`$comboBox.Items.AddRange(@('" + ($scriptNames.DisplayName -join "','") + "'))"
        $content = $content -replace $comboBoxPattern, $newComboBoxItems

        # Build switch cases with proper formatting, using original names
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
        "ThisIsToImportModules" {
            # Get all .ps1 and .psm1 files in the Modules directory
            `$modulePath = Join-Path `$PSScriptRoot "..\Modules"
            `$files = Get-ChildItem -Path `$modulePath -Filter *.ps* -File

            foreach (`$file in `$files) {
                # Dot-source each file to load it into the current scope
                . `$file.FullName
            }
        } 
"@

        foreach ($script in $scriptNames) {
            # Map display name to original name in switch case
            $switchCases += @"

        "$($script.DisplayName)" {
            . (Join-Path `$PSScriptRoot "..\Scripts\$($script.Folder)\$($script.Name).ps1") -ADM_Credential `$script:ADM_Credential -JumpHost `$script:JumpHost
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