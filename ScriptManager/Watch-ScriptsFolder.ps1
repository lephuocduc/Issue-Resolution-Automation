$scriptManagerPath = Join-Path $PSScriptRoot "ScriptManager.ps1"
$scriptsRootPath = Join-Path $PSScriptRoot "..\Scripts"
$modulesPath = Join-Path $PSScriptRoot "..\Modules"

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

function Update-ChildScripts {
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

function Update-ModuleScripts {
    try {
        $scriptObjects = Get-ChildItem -Path $modulesPath -Filter "*.psm1" -File | 
            Select-Object @{
                Name = 'Name'
                Expression = { $_.Name } 
            }
        
        if ($scriptObjects.Count -eq 0) {
            Write-Warning "Still found 0 files. Check that `dev:modulesPath` points to the correct folder."
            return
        }

        Write-Host "Found $($scriptObjects.Count) module files."

        # 2. Build the new import block string
        # Note: We removed '$($_.Folder)' because your files are not in subfolders.
        $newImportString = $scriptObjects | ForEach-Object {
            ". (Join-Path `$PSScriptRoot ""..\Modules\$($_.Name)"")"
            "Import-Module ""`$PSScriptRoot\..\Modules\$($_.Name)"" -Force"
        } | Out-String

        $newImportString = $newImportString.TrimEnd()

        # 3. Read content
        $content = Get-Content $scriptManagerPath -Raw

        # 4. The Regex Logic
        $marker  = [Regex]::Escape("# Import all the modules !@#$%^")
        
        # Pattern: Match marker -> lazily match content -> stop at blank line
        $pattern = "(?s)($marker).*?(?=\r?\n\s*\r?\n)"
        
        $replacement = "`$1`r`n$newImportString"

        if ($content -match $pattern) {
            $content = $content -replace $pattern, $replacement
            $content | Set-Content $scriptManagerPath -Force
            Write-Host "Success: Modules import block updated." -ForegroundColor Green
        }
        else {
            Write-Warning "Could not find the marker '# Import all the modules !@#$%^' followed by a blank line."
        }
    }
    catch {
        Write-Error "Error updating Module Scripts: $_"
    }    
}
# Execute update
Update-ChildScripts
Update-ModuleScripts