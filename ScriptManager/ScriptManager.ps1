#NOTES
# Name:   ScriptManager.ps1
# Author:  Duc Le

# Major Release History:

# Version:  1.0

# Version: 1.1
# - Added Bitwarden CLI installation check and authentication.

#DESCRIPTION
# This script creates a Windows Forms application with a ComboBox to select and execute different PowerShell scripts.

#REQUIREMENT
# None
 
#INPUTS
# Select a script from the ComboBox to execute.

#OUTPUTS
# Executes the selected PowerShell script.

#EXAMPLE
# Run the script and select "Low Free Space" from the ComboBox to execute the LowFreeSpace.ps1 script.

# Get content of the bitwarden.json file

# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Import the Get-BitwardenAuthentication module
Import-Module -Name $PSScriptRoot\Modules\Get-BitwardenAuthentication.psm1 -Force

$script:ADM_Credential = $null
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

function Unprotect-BitwardenConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    # Unprotect the encrypted file and convert from JSON
    try {
        $decryptedContent = Unprotect-CmsMessage -Path $ConfigPath | ConvertFrom-Json
        return $decryptedContent
    }
    catch {
        throw
    }
}

# Decrypt the Bitwarden configuration
$DecryptedContent = Unprotect-BitwardenConfig -ConfigPath "$PSScriptRoot/EncryptedBitwarden.json"
# Extract values
$clientId = $DecryptedContent.bitwarden.clientId
$clientSecret = $DecryptedContent.bitwarden.clientSecret
$masterPassword = $DecryptedContent.bitwarden.masterPassword
$credentialName = $DecryptedContent.bitwarden.credentialName

# Check if any required value is missing
if (-not $clientId -or -not $clientSecret -or -not $masterPassword -or -not $credentialName) {
    throw "One or more Bitwarden configuration values are missing."
}

function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($bitwarden_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp"
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "ScriptManager-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

# Get all video controller objects
$screens = Get-WmiObject -Class Win32_VideoController

# Initialize scale factors
$scaleX = 1
$scaleY = 1

# Set design resolution
$designWidth = 1920
$designHeight = 1080

<#
# Loop through all video controllers
foreach ($screen in $screens) {
    $screenWidth = $screen.CurrentHorizontalResolution
    $screenHeight = $screen.CurrentVerticalResolution
    if ($screenWidth -and $screenHeight) {
        $scaleX = $screenWidth / $designWidth
        $scaleY = $screenHeight / $designHeight
    }
}#>
    
# Bitwarden form
$bitwarden_form = New-Object System.Windows.Forms.Form
$bitwarden_form.Text = "Script Manager - Checking"
$bitwarden_form.Size = New-Object System.Drawing.Size([Math]::Round(410 * $scaleX) , [Math]::Round(120 * $scaleY))  # Adjust size based on screen resolution
$bitwarden_form.StartPosition = "CenterScreen"
$bitwarden_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$bitwarden_form.MaximizeBox = $false

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel.Font = New-Object System.Drawing.Font($statusLabel.Font.FontFamily, [Math]::Round(11* $scaleY))  # Adjust font size based on screen resolution
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$statusLabel.Location = New-Object System.Drawing.Point([Math]::Round(([Math]::Round($bitwarden_form.Size.Width / 2) - $statusLabel_width) * $scaleX), [Math]::Round(([Math]::Round(($bitwarden_form.Size.Height / 2) - $statusLabel.PreferredHeight)) * $scaleY))

  # Initially hidden until the check is done
$bitwarden_form.Controls.Add($statusLabel)
$bitwarden_form.Add_Shown({
    try {
        # Retrieve the ADM_Credential
        Update-StatusLabel -text "Authenticating with Bitwarden..."
        $script:ADM_Credential = Get-BitwardenAuthentication -ClientId $clientId -ClientSecret $clientSecret -MasterPassword $masterPassword -CredentialName $credentialName
        $bitwarden_form.Close()  # Close the Bitwarden form after successful authentication
        $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    }
    catch {
        Write-Log "An error occurred during Bitwarden authentication: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred during Bitwarden authentication: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
    }
    
})

#########################################
# Create the main form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Script Manager - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size([Math]::Round(400 * $scaleX), [Math]::Round(190*$scaleY))  # Adjust size based on screen resolution
$main_form.StartPosition = "CenterScreen"
# Prevent resizing
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false

# Label
$label = New-Object System.Windows.Forms.Label
$label.Text = "Choose a script to execute"
$label.AutoSize = $true
$label.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY), [System.Drawing.FontStyle]::Bold)

# Calculate centered position (after text & font set)
$label_width  = $label.PreferredWidth
$label_height = $label.PreferredHeight
$label_x = [Math]::Round( ($main_form.ClientSize.Width  - $label_width) / 2 )
$label_y = [Math]::Round( 25 * $scaleY )
$label.Location = New-Object System.Drawing.Point($label_x, $label_y)
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
#$comboBox.Location = New-Object System.Drawing.Point(110, 50)  # Centered horizontally - REMOVE THIS LINE
$comboBox.Size = New-Object System.Drawing.Size ([Math]::Round(200 * $scaleX), [Math]::Round(25 * $scaleY)) # set the size of combobox
$comboBox.Items.AddRange(@('Low Free Space','Windows Performance'))  # Add items to the dropdown
$comboBox.DropDownStyle = 'DropDown' # Allow text editing in the ComboBox
# Calculate the horizontal center for the ComboBox
$combobox_width = $comboBox.Size.Width
$combobox_x = [Math]::Round(($main_form.ClientSize.Width - $combobox_width) / 2)
$combobox_y = [Math]::Round( 50 * $scaleY ) # set padding from top
$comboBox.Location = New-Object System.Drawing.Point($combobox_x, $combobox_y)
# Set the font size (keep the default font family)
$defaultFont = $comboBox.Font  # Get the default font
$comboBox.Font = New-Object System.Drawing.Font($defaultFont.FontFamily, [Math]::Round(11 * $scaleY))  # Change only the size to 12
$comboBox.Text = "------------------------------"
# Enable AutoComplete functionality
$comboBox.AutoCompleteMode = 'SuggestAppend'  # Suggest matching items and append the rest
$comboBox.AutoCompleteSource = 'ListItems'    # Use items from the ComboBox's list for suggestions
# Add key event handler for Ctrl+A and Ctrl+C
$comboBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $comboBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $okButton.PerformClick()
        $e.SuppressKeyPress = $true  # Prevents the "ding" sound
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($comboBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($comboBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($comboBox.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

# Create OK Button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = 'OK'
#$okButton.Location = New-Object System.Drawing.Point(120, 100) # Positioning below the dropdown
$okButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size for consistency


# Add Click event  to execute the selected script using a switch statement
$okButton.Add_Click({
    $selectedValue = $comboBox.Text
    switch ($selectedValue) {        "------------------------------" {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a script from the dropdown.",
                "Information",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        "Low Free Space" {
            . (Join-Path $PSScriptRoot "..\Scripts\LowFreeSpace\LowFreeSpace.ps1") -ADM_Credential $script:ADM_Credential
        }
        "Windows Performance" {
            . (Join-Path $PSScriptRoot "..\Scripts\WindowsPerformance\WindowsPerformance.ps1") -ADM_Credential $script:ADM_Credential
        }
        default {
            [System.Windows.Forms.MessageBox]::Show(
                "No script is associated with the selection '$selectedValue'.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return}
    }
})

# Create Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
#$cancelButton.Location = New-Object System.Drawing.Point(220, 100) # Positioning next to the OK button
$cancelButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size matching OK button
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({ $main_form.Dispose() })  # Close the form when Cancel is clicked

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25 * $scaleX  # Space between buttons
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, [Math]::Round(100 * $scaleY))
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), [Math]::Round(100 * $scaleY))

# Add controls to the form
$main_form.Controls.Add($comboBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show the form as a dialog
$bitwarden_form.ShowDialog()


if ($script:ADM_Credential) {
    # Close the Bitwarden form after authentication
    $bitwarden_form.Close()
    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    # Show the main form after Bitwarden authentication
    $main_form.ShowDialog()
}












































