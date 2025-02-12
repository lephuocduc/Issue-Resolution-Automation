# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
. (Join-Path $PSScriptRoot 'Scripts\LowFreeSpace.ps1')
# Create the main form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = 'Script Manager'
$main_form.Size = New-Object System.Drawing.Size(400, 190)
$main_form.StartPosition = "CenterScreen"
$main_form.FormBorderStyle = 'FixedSingle'
$main_form.MaximizeBox = $false

# Label
$label = New-Object System.Windows.Forms.Label
$label.AutoSize = $true
$label.Text = "Choose a script to execute"
$label.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
$label_width = $label.PreferredWidth
$label_x = ($main_form.ClientSize.Width - $label_width) / 2
$label_y = 25
$label.Location = New-Object System.Drawing.Point($label_x, $label_y)
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Size = New-Object System.Drawing.Size (200, 25)
$comboBox.DropDownStyle = 'DropDown'

# Get the list of .ps1 files from the .\Scripts folder and remove the .ps1 extension
$scriptsPath = Join-Path $PSScriptRoot 'Scripts'
$ps1Files = Get-ChildItem -Path $scriptsPath -Filter *.ps1 | ForEach-Object { $_.BaseName }
$comboBox.Items.AddRange($ps1Files)

$combobox_width = $comboBox.Size.Width
$combobox_x = ($main_form.ClientSize.Width - $combobox_width) / 2
$combobox_y = 50
$comboBox.Location = New-Object System.Drawing.Point($combobox_x, $combobox_y)
$defaultFont = $comboBox.Font
$comboBox.Font = New-Object System.Drawing.Font($defaultFont.FontFamily, 11)
$comboBox.Text = "------------------------------"
$comboBox.AutoCompleteMode = 'SuggestAppend'
$comboBox.AutoCompleteSource = 'ListItems'
$comboBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        $comboBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $okButton.PerformClick()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
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
$okButton.Size = New-Object System.Drawing.Size(80, 30)
$okButton.Add_Click({
    $selectedValue = $comboBox.Text
    if ($selectedValue -eq "------------------------------" -or $selectedValue -eq "") {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a script from the dropdown.",
            "Information",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }
    $scriptPath = Join-Path $scriptsPath ($selectedValue + ".ps1")
    if (Test-Path $scriptPath) {
        . $scriptPath
    } else {
        [System.Windows.Forms.MessageBox]::Show(
            "No script is associated with the selection '$selectedValue'.",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# Create Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
$cancelButton.Size = New-Object System.Drawing.Size(80, 30)
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

# Show the form as a dialog
$main_form.ShowDialog()
