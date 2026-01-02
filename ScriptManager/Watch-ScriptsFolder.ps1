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
            . (Join-Path `$PSScriptRoot "..\Scripts\$($script.Folder)\$($script.Name).ps1") -ADM_Credential `$script:ADM_Credential -JumpHost `$script:JumpHost -ModuleContents `$script:ModuleContents
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
        # 1. Get the module files
        $moduleFiles = Get-ChildItem -Path $modulesPath -Filter "*.psm1" -File
        
        if (-not $moduleFiles) {
            Write-Warning "No .psm1 files found in folder."
            return
        }

        # Build the list: 'Name.psm1', (with trailing commas except last, or just simple list)
        # Note: PowerShell arrays @( ) handle trailing commas fine.
        $newModuleList = $moduleFiles | ForEach-Object { "    ""$($_.Name)""" } 
        $joinedModules = ($newModuleList -join ",`r`n")

        # 2. Read content
        if (-not (Test-Path $scriptManagerPath)) { throw "Path not found." }
        $content = Get-Content $scriptManagerPath -Raw

        # 3. THE FIX: Using Single Quotes to prevent PowerShell variable expansion
        # We escape the $ for Regex (\$), but keep the string literal (')
        $pattern = '(?s)(\$ModuleList\s*=\s*@\()(.*?)(\))'
        
        # In the replacement string, we use backticks to escape the $ for PowerShell
        # so that Regex sees $1 and $3 as backreferences.
        $replacement = "`$1`r`n$joinedModules`r`n`$3"

        if ($content -match $pattern) {
            $content = $content -replace $pattern, $replacement
            $content | Set-Content $scriptManagerPath -Force
            Write-Host "Success: Updated $($moduleFiles.Count) modules in `$ModuleList." -ForegroundColor Green
        }
        else {
            Write-Warning "Could not find the array definition: `$ModuleList = @( )"
            Write-Host "Debug: Ensure your file has exactly: `$ModuleList = @(" -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }    
}
# Execute update
Update-ChildScripts
#Update-ModuleScripts