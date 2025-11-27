# NOTES
# Name:        PerformanceIssue.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        August 10, 2025

# Release History:
# 1.0 - Author: Duc Le - Initial release with basic functionality to check server availability, collect performance metrics, and display a dashboard.

# DESCRIPTION
# This script creates a Windows Forms application that allows users to enter a server name, the script will then:
# 1. Check if the server is reachable via WinRM, ping, and DNS resolution.
# 2. If reachable, it will create a PowerShell session to the server.
# 3. Collect system uptime and performance metrics (CPU, memory, processes).
# 4. Display the results in a dashboard format.
# 5. Log all actions and errors to a log file.

# REQUIREMENTS
# - PowerShell 5.1 or later
# - Admin privileges to create PowerShell sessions on remote servers
# - Local write permissions to the log directory (default: C:\temp)

# PARAMETERS
# - ADM_Credential: Optional PSCredential object for admin credentials. If not provided, a default user and password will be used for testing.
# - ServerName: Mandatory string parameter for the server name to connect to.

# FUNCTIONS:
# - Write-Log: Logs messages to a specified log file.
# - Get-Session: Creates a PowerShell session to the specified server.
# - Test-ServerAvailability: Tests the availability of the server via WinRM, ping, and DNS resolution.
# - Update-StatusLabel: Updates the status label in the Windows Form.
# - Get-SystemUptime: Retrieves the system uptime from the remote server.
# - Get-PerformanceMetrics: Collects performance metrics from the remote server.
# - Get-TopCPUProcesses: Returns the top CPU-consuming processes.
# - Get-TopMemoryProcesses: Returns the top memory-consuming processes.
# - Show-PerformanceDashboard: Displays the performance dashboard in a Windows Form.
# - Remove-Session: Closes the PowerShell session and cleans up resources.
# - Test-ReportFileCreation: Tests the creation of a report file in the specified log directory.
# - Write-WindowsEventLog: Writes an event log entry to the Windows Event Log.
# - Get-VideoControllers: Retrieves video controller information to determine screen resolution and scaling factors.
# - Get-ProcessOwner: Retrieves the owner of a process by its ID, with caching for performance.

# OUTPUT
# - A Windows Form application that displays the server's uptime, performance metrics, and top processes.
# - A log file in C:\temp directory with all actions and errors.
# - A report file in the same directory with performance metrics and process information.

# EXAMPLE USAGE
# 1. Open PowerShell as Administrator.
# 2. Run the script: .\PerformanceIssue.ps1
# 3. Enter the server name when prompted.
# 4. The script will check server availability, create a session, collect metrics, and display the dashboard.
# 5. The log file will be created in C:\temp with all actions and errors.

Param(
    [Parameter(Mandatory= $false)]
    [System.Management.Automation.PSCredential]$ADM_Credential
)
<#
# Temporary workaround for testing
if (-not $ADM_Credential) {
    $userName = "user1"
    $password = ConvertTo-SecureString "Leduc123" -AsPlainText -Force
    $ADM_Credential = New-Object System.Management.Automation.PSCredential($userName, $password)
}#>

# Get current user
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()
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

# Vertical padding between objects
$verticalPadding = 7 * $scaleY

# Create ToolTip object
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 5000  # Time the tooltip remains visible (in milliseconds)
$toolTip.InitialDelay = 500   # Time before the tooltip appears (in milliseconds)
$toolTip.ReshowDelay = 500    # Time before tooltip reappears if mouse moves away and back
$toolTip.ShowAlways = $true   # Show tooltip even if the form is not active

# Server Name Label
$labelServerName = New-Object System.Windows.Forms.Label
$labelServerName.Location = New-Object System.Drawing.Point([Math]::Round(20 * $scaleX), [Math]::Round(20 * $scaleY))
$labelServerName.Size = New-Object System.Drawing.Size([Math]::Round(120 * $scaleX), [Math]::Round(30 * $scaleY))
$labelServerName.Text = "Server Name:"
$labelServerName.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY))
$toolTip.SetToolTip($labelServerName, "Enter the hostname or IP address of the remote server to analyze or clean.")

# Disk Name TextBox
$textBoxServerName = New-Object System.Windows.Forms.TextBox
$textBoxServerName.Location = New-Object System.Drawing.Point(($labelServerName.Location.X + $labelServerName.Width), $labelServerName.Location.Y)
$textBoxServerName.Size = New-Object System.Drawing.Size([Math]::Round(250 * $scaleX), $labelServerName.Height)
$textBoxServerName.Font = $labelServerName.Font
$textBoxServerName.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $textBoxServerName.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($textBoxServerName.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($textBoxServerName.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($textBoxServerName.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

# Main Form Width Calculation
$mainFormWidth = [Math]::Round(($textBoxServerName.Location.X + $textBoxServerName.Width + 40 * $scaleX))


# Ticket number Label
$ticketNumberLabel = New-Object System.Windows.Forms.Label
$ticketNumberLabel.Location = New-Object System.Drawing.Point($labelServerName.Location.X, ($labelServerName.Location.Y + $labelServerName.Height + $verticalPadding))
$ticketNumberLabel.Size = $labelServerName.Size
$ticketNumberLabel.Text = "Ticket Number:"
$ticketNumberLabel.Font = $labelServerName.Font
$toolTip.SetToolTip($ticketNumberLabel, "Enter the ticket number associated with this operation.")

# Ticket number TextBox
$ticketNumberTextBox = New-Object System.Windows.Forms.TextBox
$ticketNumberTextBox.Location = New-Object System.Drawing.Point($textBoxServerName.Location.X, $ticketNumberLabel.Location.Y)
$ticketNumberTextBox.Size = $textBoxServerName.Size
$ticketNumberTextBox.Font = $textBoxServerName.Font
$ticketNumberTextBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $ticketNumberTextBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($ticketNumberTextBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($ticketNumberTextBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($ticketNumberTextBox.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

$modulesToImport = @(
    "$PSScriptRoot\..\..\Modules\Get-Session.psm1",
    "$PSScriptRoot\..\..\Modules\Test-ServerAvailability.psm1",
    "$PSScriptRoot\..\..\Modules\Get-SystemUptime.psm1",
    "$PSScriptRoot\..\..\Modules\Get-PerformanceMetrics.psm1",
    "$PSScriptRoot\..\..\Modules\Get-TopCPUProcesses.psm1",
    "$PSScriptRoot\..\..\Modules\Get-TopMemoryProcesses.psm1",
    "$PSScriptRoot\..\..\Modules\Show-PerformanceDashboard.psm1",
    "$PSScriptRoot\..\..\Modules\Remove-Session.psm1",
    "$PSScriptRoot\..\..\Modules\Write-WindowsEventLog.psm1",
    "$PSScriptRoot\..\..\Modules\Write-Log.psm1"
)

$JumpHostSession = Get-Session -serverName $JumpHost -Credential $ADM_Credential

foreach ($modulePath in $modulesToImport) {
    try {
        # Read the module content
        $moduleContent = Get-Content -Path $modulePath -Raw

        # Execute the module content in the remote session
        Invoke-Command -Session $JumpHostSession -ScriptBlock {
            param($moduleContent, $moduleName)
            # Use Invoke-Expression to execute the module content
            Invoke-Expression -Command $moduleContent
            Write-Host "Successfully imported module $moduleName in remote session" -ForegroundColor Green
        } -ArgumentList $moduleContent, ([System.IO.Path]::GetFileNameWithoutExtension($modulePath)) -ErrorAction Stop
    } catch {
        Write-Host "Error importing module $modulePath : $_" -ForegroundColor Red
        [System.Windows.Forms.MessageBox]::Show("Error importing module $([System.IO.Path]::GetFileNameWithoutExtension($modulePath)) : $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        exit 1
    }
}

# OK Button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))
$okButton.Text = "OK"
$okButton.Add_Click({
    try {
        # Normalize inputs
        $serverName = $textBoxServerName.Text.Trim()
        $ticketNumber = $ticketNumberTextBox.Text

        # Imported modules in the remote session

        $params = @{
            ServerName     = $serverName      
            TicketNumber   = $ticketNumber
            ADM_Credential = $ADM_Credential
        }

        $ScriptBlock = {
            param ($params)
            $serverName = $params.ServerName
            $ticketNumber = $params.TicketNumber
            $ADM_Credential = $params.ADM_Credential

            try {
                # Initial variable assignments


                if ([string]::IsNullOrEmpty($serverName) -or [string]::IsNullOrEmpty($ticketNumber)) {
                    return "Please fill in all fields (Server Name, Ticket Number)."
                }

                $result = Test-ServerAvailability -serverName $serverName
                if (-not $result.RemotingAvailable) {
                    return "Server $serverName is not reachable or PowerShell Remoting is not available."
                }

                $session = Get-Session -serverName $serverName -Credential $ADM_Credential
                if ($null -eq $session) {
                    return "Failed to create a session to $serverName. Please check the server name and your credentials."
                }
            }catch {
                return "Error during initial checks: $_"
            }
        }
        $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
        if ($result) {
            Update-StatusLabel -text $result
            [System.Windows.Forms.MessageBox]::Show($result, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return
        }

        Update-StatusLabel -text "Collecting performance data from $serverName..."
        $ScriptBlock = {
            param ($params)
            $serverName = $params.ServerName
            $ticketNumber = $params.TicketNumber
            $ADM_Credential = $params.ADM_Credential

            try {
                # Collect data using separate functions
                $uptime = Get-SystemUptime -ServerName $serverName -Session $session
                $metrics = Get-PerformanceMetrics -Session $session -Samples 3 -Interval 2
                $topCPU = Get-TopCPUProcesses -PerformanceData $metrics -TopCount 5
                $topMemory = Get-TopMemoryProcesses -PerformanceData $metrics -TopCount 5

                # Write event log entry
                $eventMessage = "User: $CurrentUser`n" + "Ticket Number: $ticketNumber`n" + "Message: Performance analysis completed for $serverName. CPU usage: $($metrics.SystemMetrics.AvgCPU)%. Memory usage: $($metrics.SystemMetrics.AvgMemoryPercent)% ($([math]::Round($metrics.SystemMetrics.AvgMemoryBytes / 1GB, 2)) GB)`n" + "`nTop CPU Processes:`n$($topCPU | Out-String)`nTop Memory Processes:`n$($topMemory | Out-String)"
                Write-WindowsEventLog -LogName "Application" `
                                    -Source "PerformanceAnalysisScript" `
                                    -EventID 1000 `
                                    -EntryType "Information" `
                                    -Message $eventMessage `
                                    -Session $session

                # Show performance dashboard
                $reportPath = Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $metrics.SystemMetrics

                if ($null -eq $reportPath) {
                    return "Failed to create report file."
                } else {
                    return "Generating report..."
                }
            } catch {
                return "Error during performance analysis: $_"
            }
        }
        $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
        if ($result) {
            Update-StatusLabel -text $result
        }

        # Export the report back to the local machine
        $ScriptBlock = {
            if ($reportPath) {
                $fileContent = Get-Content -Path $reportPath -Raw
                # Return a custom object with both fileContent and filePath
                return [PSCustomObject]@{
                    FileContent = $fileContent
                    FilePath = $reportPath
                }
            }
        }
        $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock

        if ($result) {
            # Access the returned values:
            $fileContent = $result.FileContent
            $filePath = $result.FilePath

            # Save the content locally and open it
            $fileContent | Out-File "$filePath" -Encoding UTF8
            Start-Process "$filePath" -ErrorAction SilentlyContinue
        }
    } catch {
        Update-StatusLabel -text "An error occurred: $_"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error")
    }
})

# Exit Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Size = $okButton.Size
$cancelButton.Text = "Cancel"
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({
    $main_form.Close()
    Remove-Session
}
)

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($mainFormWidth - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, ($ticketNumberLabel.Location.Y + $ticketNumberLabel.Height + $verticalPadding))
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), $okButton.Location.Y)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$label_x = ($main_form.ClientSize.Width - $statusLabel_width) / 2  # Center horizontally
$label_y = $cancelButton.Location.Y + $cancelButton.Height + $verticalPadding
$statusLabel.Location = New-Object System.Drawing.Point($label_x, ($label_y + 10))  # Add some vertical padding

# Main Form Length Calculation
$mainFormLength = [Math]::Round($statusLabel.Location.Y + $statusLabel.Height + $verticalPadding + 50*$scaleY)

# Main Form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Windows Performance Issue - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size($mainFormWidth, $mainFormLength)
$main_form.StartPosition = "CenterScreen"
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false
$main_form.TopMost = $false  # Keep form on top
$main_form.KeyPreview = $true  # Important: This allows the form to receive key events before controls
$main_form.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        $cancelButton.PerformClick()
    }
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $okButton.PerformClick()
    }
})

# Add components to form
$main_form.Controls.Add($labelServerName)
$main_form.Controls.Add($textBoxServerName)
$main_form.Controls.Add($ticketNumberLabel)
$main_form.Controls.Add($ticketNumberTextBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)
$main_form.Controls.Add($statusLabel)


# Show form
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}