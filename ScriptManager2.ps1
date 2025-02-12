# Name:   ScriptSelector.ps1
# Author:  Duc Le
# Version:  1.1
# Major Release History:
# 1.1 - Automatically populates the ComboBox with scripts from the Scripts folder.

#DESCRIPTION
# This script creates a Windows Forms application with a ComboBox to select and execute different PowerShell scripts.  It dynamically populates the ComboBox with scripts found in the Scripts folder.

#REQUIREMENT
# None

#INPUTS
# Select a script from the ComboBox to execute.

#OUTPUTS
# Executes the selected PowerShell script.

#EXAMPLE
# Run the script and select a script from the ComboBox to execute it.

# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms

# Create the main form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = 'Script Manager'
$main_form.Size = New-Object System.Drawing.Size(400, 190)
$main_form.StartPosition = "CenterScreen"
# Prevent resizing
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false

# Label
$label = New-Object System.Windows.Forms.Label
# Calculate horizontal center
$label.AutoSize = $true  # Important:  Let the label size itself to the text
$label.Text = "Choose a script to execute"
$label.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
$label_width = $label.PreferredWidth # get the actual width of the label based on the text
$label_x = ($main_form.ClientSize.Width - $label_width) / 2  # Center horizontally
$label_y = 25  # Top padding
$label.Location = New-Object System.Drawing.Point($label_x, $label_y)
#$label.Size = New-Object System.Drawing.Size(300, 30) #No need to specify size, as AutoSize set to true
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
#$comboBox.Location = New-Object System.Drawing.Point(110, 50)  # Centered horizontally - REMOVE THIS LINE
$comboBox.Size = New-Object System.Drawing.Size (200, 25) # set the size of combobox
#$comboBox.Items.AddRange(@("Low Free Space", "Option2", "Option3"))  # Add items to the dropdown - REMOVE THIS LINE
$comboBox.DropDownStyle = 'DropDown' # Allow text editing in the ComboBox
# Calculate the horizontal center for the ComboBox
$combobox_width = $comboBox.Size.Width
$combobox_x = ($main_form.ClientSize.Width - $combobox_width) / 2
$combobox_y = 50 # set padding from top
$comboBox.Location = New-Object System.Drawing.Point($combobox_x, $combobox_y) #positioning of combobox
# Set the font size (keep the default font family)
$defaultFont = $comboBox.Font  # Get the default font
$comboBox.Font = New-Object System.Drawing.Font($defaultFont.FontFamily, 11)  # Change only the size to 12
$comboBox.Text = "------------------------------"
# Enable AutoComplete functionality
$comboBox.AutoCompleteMode = 'SuggestAppend'  # Suggest matching items and append the rest
$comboBox.AutoCompleteSource = 'ListItems'    # Use items from the ComboBox's list for suggestions

# Dynamically populate the ComboBox with script names from the Scripts folder
$script_folder = Join-Path $PSScriptRoot 'Scripts'
$scripts = Get-ChildItem -Path $script_folder -Filter *.ps1 | Select-Object -ExpandProperty Name

# Add the script names to the ComboBox
$comboBox.Items.AddRange($scripts)

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
$okButton.Size = New-Object System.Drawing.Size(80, 30)  # Fixed size for consistency

# Create Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
#$cancelButton.Location = New-Object System.Drawing.Point(220, 100) # Positioning next to the OK button
$cancelButton.Size = New-Object System.Drawing.Size(80, 30)  # Fixed size matching OK button
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({ $main_form.Close() })

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, 100)
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), 100)

# Add controls to the form
$main_form.Controls.Add($comboBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Add Click event to execute the selected script using a switch statement
$okButton.Add_Click({
    $selectedValue = $comboBox.Text
    switch ($selectedValue) {
        "------------------------------"{
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a script from the dropdown.",
                "Information",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        Default {
            # Construct the full path to the selected script
            $scriptPath = Join-Path $PSScriptRoot "Scripts\$selectedValue"

            # Check if the script file exists
            if (Test-Path -Path $scriptPath -PathType Leaf) {
                # Execute the selected script
                try {
                    . $scriptPath
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show(
                        "An error occurred while executing the script: $($_.Exception.Message)",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                }
            }
            else {
                # Show an error message if the script file does not exist
                [System.Windows.Forms.MessageBox]::Show(
                    "The script file '$selectedValue' was not found.",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        }
    }
})


# Show the form as a dialog
$main_form.ShowDialog()
