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
        if (-not (Test-Path $modulesPath)) {
            Write-Warning "Modules path '$modulesPath' does not exist."
            return
        }

        $moduleNames = Get-ChildItem -Path $modulesPath -Filter '*.psm1' -File |
                       Sort-Object BaseName |
                       ForEach-Object { $_.BaseName }

        if (-not $moduleNames -or $moduleNames.Count -eq 0) {
            Write-Warning "No .psm1 files found in '$modulesPath'."
            return
        }

        # Build array lines with no blank line after the opening '@('
        $items = $moduleNames | ForEach-Object { "    `"" + $_ + "`"," }
        # Remove trailing comma from last item for neat formatting
        $items[-1] = $items[-1].TrimEnd(',')

        # New block: no blank line immediately after '@('
        $newBlock = '$modules = @(' + "`r`n" + ($items -join "`r`n") + "`r`n)"

        # Read file
        $content = Get-Content -Path $scriptManagerPath -Raw -ErrorAction Stop

        # Find existing $modules block (singleline / dotall) and replace it safely
        $moduleBlockPattern = '(?s)\$modules\s*=\s*@\(\s*.*?\s*\)'
        $match = [regex]::Match($content, $moduleBlockPattern)

        if ($match.Success) {
            $content = $content.Replace($match.Value, $newBlock)
            Set-Content -Path $scriptManagerPath -Value $content -Force -Encoding UTF8
            Write-Host "Success: $scriptManagerPath updated with $($moduleNames.Count) modules." -ForegroundColor Green
        }
        else {
            Write-Warning "Could not find a `$modules = @(...)` block to replace in '$scriptManagerPath'."
        }
    }
    catch {
        Write-Error "Error updating Module Scripts: $_"
    }
}

function New-ScriptPackage {
    [CmdletBinding()]
    param()

    # Define paths relative to this script's location ($PSScriptRoot)
    $OutputFilePath = Join-Path -Path $PSScriptRoot -ChildPath "package.ps1"
    $ModulesPath    = Join-Path -Path $PSScriptRoot -ChildPath "..\Modules"
    $MainScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "ScriptManager.ps1"

    Write-Host "Building package at: $OutputFilePath" -ForegroundColor Cyan

    # 1. Initialize package.ps1 with the start of the ScriptBlock
    '$Content = {' | Set-Content -Path $OutputFilePath -Force

    # 2. Inject all .psm1 modules into the ScriptBlock
    if (Test-Path -Path $ModulesPath) {
        $ModuleFiles = Get-ChildItem -Path $ModulesPath -Filter "*.psm1"
        
        foreach ($file in $ModuleFiles) {
            Write-Host "  Bundling module: $($file.Name)" -ForegroundColor Gray
            
            # Add a comment for readability in the final file
            Add-Content -Path $OutputFilePath -Value "`n    # --- Module: $($file.Name) ---"
            
            # Append the module content
            Get-Content -Path $file.FullName | Add-Content -Path $OutputFilePath
        }
    }
    else {
        Write-Warning "Modules folder not found at: $ModulesPath"
    }

    # Close the ScriptBlock
    Add-Content -Path $OutputFilePath -Value "`n}"

    # 3. Append the Main ScriptManager content
    if (Test-Path -Path $MainScriptPath) {
        Write-Host "  Appending main script: ScriptManager.ps1" -ForegroundColor Gray
        
        Add-Content -Path $OutputFilePath -Value "`n# --- Main Script ---"
        Get-Content -Path $MainScriptPath | Add-Content -Path $OutputFilePath
    }
    else {
        Write-Error "ScriptManager.ps1 not found at: $MainScriptPath"
    }

    Write-Host "Build Complete." -ForegroundColor Green
}

# Execute update
Update-ChildScripts
#Update-ModuleScripts
New-ScriptPackage