# Load Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Script Manager"
$form.Size = New-Object System.Drawing.Size(500, 300)
$form.StartPosition = "CenterScreen"

# Function to Execute PowerShell Script
function Execute-Script {
    param ($scriptPath)
    try {
        # Verify script exists
        if (-not (Test-Path -Path $scriptPath)) {
            [System.Windows.Forms.MessageBox]::Show("Script not found: $scriptPath", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }

        # Run the script
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -NoNewWindow -Wait -PassThru
        
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
function Create-ResponsiveButtons {
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
            Execute-Script -scriptPath ".\LowFreeSpace-DataDisk.ps1"
        }
    },
    @{
        Text = "Another Script"
        OnClick = {
            Execute-Script -scriptPath "C:\AutomationProject\AutomationProject\AnotherScript.ps1"
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
Create-ResponsiveButtons -form $form -buttonDefinitions $buttons

# Show Form
$form.ShowDialog()
