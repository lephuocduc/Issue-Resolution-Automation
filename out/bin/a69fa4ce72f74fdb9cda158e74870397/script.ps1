& {
param($PoshToolsRoot)
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

# Load module
# Function to write message to user about script execution
function Write-Message {
    param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    # Create temp directory if not exists
    if (-not (Test-Path "C:\temp")) { 
        New-Item -ItemType Directory -Path "C:\temp"
    }

    $message | Out-File "C:\temp\script_status.txt" -Force
}

# Function to prompt for server name and check availability
function Test-ServerAvailability {
    param(
        [string]$serverName
    )
    return Test-Connection -ComputerName $serverName -Count 1 -Quiet
}

# Function to attempt to create a session and handle credential failures
function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName
    )
    $retryCount = 0
    $maxRetries = 3
    do {
        $retryCount++
        $credential = Get-Credential
        if ($null -eq $credential -or $retryCount -ge $maxRetries) {
            return $null
        }

        try {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$serverName" -Concatenate -Force
            $session = New-PSSession -ComputerName $serverName -Credential $credential -ErrorAction Stop
            return $session
        } catch {
            continue
        }
    } while ($true)
}


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
            $scriptPath = (Join-Path $PSScriptRoot 'Scripts\LowFreeSpace.ps1')
            Invoke-Script -scriptPath $scriptPath
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
}