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
$form.Size = New-Object System.Drawing.Size(500, 300)
$form.StartPosition = "CenterScreen"

# Function to Execute PowerShell Script
function Invoke-Script {
    param ($scriptPath)
    try {
        # Verify script exists
        if (-not (Test-Path -Path $scriptPath)) {
            [System.Windows.Forms.MessageBox]::Show("Script not found: $scriptPath", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }

        # Run the script
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" -NoNewWindow -Wait -PassThru
        
        # Check exit code to ensure script ran successfully
        if ($process.ExitCode -eq 0) {
            # Script executed successfully
        } else {
            [System.Windows.Forms.MessageBox]::Show("Script execution failed with exit code $($process.ExitCode).", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to execute script. Error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
