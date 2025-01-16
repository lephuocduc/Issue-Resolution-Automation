#NOTES
# Name:   AutomationTool.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

#DESCRIPTION
# This PowerShell script creates a graphical user interface (GUI) for managing and executing PowerShell scripts.
# It provides a centralized interface with a server name input field, status display, and dynamic buttons for
# launching different scripts. The GUI includes features such as copy/paste functionality, status monitoring,
# and responsive button layout. Status updates are monitored and displayed in real-time through a file-based
# communication system.

#REQUIREMENT
# - Write access to C:\temp directory for status updates
# - Script files in the following structure:
#   * ./Scripts/LowFreeSpace.ps1
#   * ./Scripts/AnotherScript.ps1
# - Administrative privileges (may be required depending on child scripts)

#INPUTS
# Via GUI:
# - Server Name [string]: Target server for script execution
# - Script Selection: Choose from available script buttons
#   * Low Free Space: Executes LowFreeSpace.ps1
#   * Another Script: Executes AnotherScript.ps1
#   * Exit: Closes the application
#
# File System:
# - C:\temp\script_status.txt: Used for real-time status updates

#OUTPUTS
# - GUI Window with:
#   * Status display showing real-time script execution progress
#   * Error messages via MessageBox for validation failures
#   * Copy-enabled status text with context menu
# - Script-specific outputs in their respective locations
# - Debug logging for status updates and file reading errors

#EXAMPLE
# Running the script:
# .\UI.ps1
#
# Usage example:
# 1. Launch script:
#    PS> .\UI.ps1
#
# 2. GUI Interaction:
#    - Enter server name: "SERVER01"
#    - Click "Low Free Space" button
#    - Monitor progress in status window
#    - Use Ctrl+A to select all status text
#    - Right-click to copy status text
#    - Click "Exit" to close
#
# 3. Status monitoring:
# Write-Message "Script starting..." | Out-File C:\temp\script_status.txt
# # Status will automatically appear in GUI


# Load module
. (Join-Path $PSScriptRoot 'modules\module.ps1')

# Write message at the start
Write-Message -message "Please input server name and select a script to execute."

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

# Set the icon
$iconPath = "$PSScriptRoot\icon.ico"  # Path to your icon file
if (Test-Path $iconPath) {
    $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
}
<#
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
        
        # Run script with server name parameter
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ServerName `"$serverName`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -NoNewWindow        
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
}#>

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

# Server Name Label
$labelServer = New-Object System.Windows.Forms.Label
$labelServer.Location = New-Object System.Drawing.Point(300, 30)
$labelServer.Size = New-Object System.Drawing.Size(100, 30)
$labelServer.Text = "Server Name:"
$form.Controls.Add($labelServer)

# Server Name TextBox
$textBoxServer = New-Object System.Windows.Forms.TextBox
$textBoxServer.Location = New-Object System.Drawing.Point(400, 30)
$textBoxServer.Size = New-Object System.Drawing.Size(200, 60)
$textBoxServer.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        $textBoxServer.SelectAll()
        $e.SuppressKeyPress = $true
    }
})
$form.Controls.Add($textBoxServer)

# Status Label
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
# Add click event to copy selected text or all text to clipboard
$copyMenuItem.Add_Click({
    if ($statusLabel.SelectedText) {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.SelectedText)
    } else {
        [System.Windows.Forms.Clipboard]::SetText($statusLabel.Text)
    }
})

# Add Ctrl+A shortcut to select all text
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
        Text = "Low Free Space"
        OnClick = {
            $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        . (Join-Path $PSScriptRoot 'Scripts\LowFreeSpace.ps1') -ServerName $serverName
        }
    },
    @{
        Text = "Another Script"
        OnClick = {
            $serverName = $textBoxServer.Text
        if ([string]::IsNullOrEmpty($serverName)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a server name", "Error")
            return
        }
        . (Join-Path $PSScriptRoot 'Scripts\AnotherScript.ps1') -ServerName $serverName -NoProfile -ExecutionPolicy Bypass -NoNewWindow
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

# Create timer for file monitoring
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100 # Check more frequently (100ms)
# Add tick event to update status label from file content if changed
$timer.Add_Tick({
    try {
        if (Test-Path "C:\temp\script_status.txt") {
            $newContent = [System.IO.File]::ReadAllText("C:\temp\script_status.txt")
            if ($newContent -ne $statusLabel.Text) {
                $statusLabel.Text = $newContent
                $statusLabel.Update() # Force immediate UI update
                [System.Windows.Forms.Application]::DoEvents() # Process UI events
                Write-Debug "Status updated: $newContent"
            }
        }
    }
    catch {
        Write-Debug "Error reading status file: $_"
    }
})

# Start timer
$timer.Start()

# Add form closing cleanup
$form.Add_FormClosing({
    $timer.Stop()
    $timer.Dispose()
})

# Show Form
$form.ShowDialog()
