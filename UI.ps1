#NOTES
# Name:   UI.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION
# This script provides a simple user interface to execute PowerShell scripts. The form contains buttons that, when clicked, execute the corresponding script. The script paths are hard-coded in the button definitions, but you can modify the script to load the paths from a configuration file or other source.

#REQUIREMENT
# Run this script as an administrator to ensure the execution of PowerShell scripts is allowed.

#INPUTS
# None

#OUTPUTS
# None

#EXAMPLE
# .\UI.ps1
# This example runs the script and displays the user interface form. Clicking the buttons will execute the corresponding PowerShell scripts.
# The "Exit" button closes the form.


# Load Windows Forms Assembly
$Parameters = @{
	AssemblyName = 'System.Windows.Forms'
}
Add-Type @Parameters

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Script Manager"
$form.Size = New-Object System.Drawing.Size(650, 300)
$form.StartPosition = "CenterScreen"

# Function to Execute PowerShell Script
function Invoke-Script {
    param ($scriptPath)
    try {
        if (-not (Test-Path -Path $scriptPath)) {
            [System.Windows.Forms.MessageBox]::Show("Script not found: $scriptPath", "Error")
            return
        }
        
        # Get server name and validate
        $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        $statusLabel.Text = "Connecting to server '$serverName'..."
        # Run script with server name parameter
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ServerName `"$serverName`""
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru
        
        
        if ($process.ExitCode -eq 0) {
            if (Test-Path "C:\temp\script_status.txt") {
                $statusLabel.Text = Get-Content "C:\temp\script_status.txt" -Raw
            }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
}

# Function to create responsive buttons with automatic placement
function New-ResponsiveButtons {
    param (
        [System.Windows.Forms.Form]$form,
        [Array]$buttonDefinitions
    )

    $yOffset = 20  # Initial offset from the top
    $spacing = 10  # Spacing between buttons

    foreach ($definition in $buttonDefinitions) {
        # Create the button
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $definition.Text

        # Measure the text size
        $graphics = [System.Drawing.Graphics]::FromImage((New-Object System.Drawing.Bitmap 1,1))
        $textSize = $graphics.MeasureString($button.Text, $button.Font)
        $button.Size = New-Object System.Drawing.Size(($textSize.Width + 50), ($textSize.Height + 20)) # Add padding

        # Set button location
        $button.Location = New-Object System.Drawing.Point(20, $yOffset)
        $yOffset += $button.Height + $spacing  # Update offset for next button

        # Add BackColor if specified
        if ($definition.BackColor) {
            $button.BackColor = $definition.BackColor
        }

        # Add click event
        $button.Add_Click($definition.OnClick)

        # Add the button to the form
        $form.Controls.Add($button)
        
    }
}

# Right Side Server Name Label
$labelServer = New-Object System.Windows.Forms.Label
$labelServer.Location = New-Object System.Drawing.Point(300, 30)
$labelServer.Size = New-Object System.Drawing.Size(100, 30)
$labelServer.Text = "Server Name:"
$form.Controls.Add($labelServer)

# Right Side Server Name TextBox
$textBoxServer = New-Object System.Windows.Forms.TextBox
$textBoxServer.Location = New-Object System.Drawing.Point(400, 30)
$textBoxServer.Size = New-Object System.Drawing.Size(200, 60)
$form.Controls.Add($textBoxServer)

# Create TextBox instead of Label for selection support
$statusLabel = New-Object System.Windows.Forms.TextBox
$statusLabel.Location = New-Object System.Drawing.Point(300, 60)
$statusLabel.Size = New-Object System.Drawing.Size(300, 60)
$statusLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
$statusLabel.Padding = New-Object System.Windows.Forms.Padding(5)
$statusLabel.ReadOnly = $true  # Make it read-only but selectable
$statusLabel.Multiline = $true # Support multiple lines
$statusLabel.BackColor = $form.BackColor  # Match form background
$statusLabel.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Left

# Add context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyMenuItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::C
$copyMenuItem.Add_Click({
    if ($statusLabel.SelectedText) {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.SelectedText)
    } else {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.Text)
    }
})

$statusLabel.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq 'A') {
        $statusLabel.SelectAll()
        $e.SuppressKeyPress = $true
    }
})

$contextMenu.Items.Add($copyMenuItem)
$statusLabel.ContextMenuStrip = $contextMenu

$form.Controls.Add($statusLabel)

# Define buttons
$buttons = @(
    @{
        Text = "Low Free Space - Data Disk"
        OnClick = {
            Invoke-Script -scriptPath ".\LowFreeSpace-DataDisk.ps1"
        }
    },
    @{
        Text = "Another Script"
        OnClick = {
            Invoke-Script -scriptPath "C:\AutomationProject\AutomationProject\AnotherScript.ps1"
        }
    },
    @{
        Text = "Exit"
        BackColor = [System.Drawing.Color]::LightCoral
        OnClick = {
            $form.Close()
        }
    }
)

# Create buttons
New-ResponsiveButtons -form $form -buttonDefinitions $buttons

# Show Form
$form.ShowDialog()