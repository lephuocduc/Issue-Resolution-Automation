# Load Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "PowerShell Script Runner"
$form.Size = New-Object System.Drawing.Size(400, 300)
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
        } else {
            [System.Windows.Forms.MessageBox]::Show("Script execution failed with exit code $($process.ExitCode).", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to execute script. Error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}


# Create Buttons
$button1 = New-Object System.Windows.Forms.Button
$button1.Text = "Check Disk Space"
$button1.Location = New-Object System.Drawing.Point(50, 50)
$button1.Size = New-Object System.Drawing.Size(120, 40)
$button1.Add_Click({
    Execute-Script -scriptPath "C:\AutomationProject\AutomationProject\LowFreeSpace-DataDisk.ps1"
})

$button2 = New-Object System.Windows.Forms.Button
$button2.Text = "Exit"
$button2.Location = New-Object System.Drawing.Point(200, 50)
$button2.Size = New-Object System.Drawing.Size(120, 40)
$button2.Add_Click({
    $form.Close()
})

# Add Controls to Form
$form.Controls.Add($button1)
$form.Controls.Add($button2)

# Show Form
$form.ShowDialog()
