# NOTES
# Name:        LowFreeSpace.ps1
# Author:      Duc Le
# Version:     1.0
# Date:        April 15, 2025 

# Release History:
#   1.0 - Initial release with disk cleanup, IIS log compression, and detailed reporting

# DESCRIPTION
# A PowerShell script with a graphical user interface (GUI) designed to manage low disk space on remote Windows servers. It automates disk cleanup and analysis tasks, targeting both system and data drives. Key features include:
# - System cache cleanup: Removes temporary files, Windows Update caches, SCCM caches, Windows Installer patches, and Recycle Bin contents older than 5 days
# - IIS log management: Compresses and archives IIS log files older than 6 months to save space
# - Disk usage analysis: Generates detailed reports on disk space, including free space, used space, and total capacity
# - Large item identification: Detects the top space-consuming folders and files when disk space remains low (<10% free)
# - Remote execution: Supports running cleanup and analysis on remote servers via PowerShell sessions
# - Reporting: Produces HTML reports with before/after cleanup metrics and folder/file size breakdowns

# REQUIREMENTS
# - PowerShell 5.1 or later (compatible with Windows PowerShell; PowerShell Core untested)
# - Administrative credentials for target servers to perform cleanup and access protected areas
# - System.Windows.Forms and System.Drawing assemblies for GUI functionality
# - Network connectivity to target servers (ping and PowerShell remoting enabled)
# - TrustedHosts configuration for non-domain environments (handled automatically by script)
# - Local write permissions for report generation (C:\temp directory)

# PARAMETERS
# - ADM_Credential: PowerShell credential object for administrative access to remote servers (optional, defaults to current user credentials if not provided)
# - ServerName: The hostname or IP address of the remote server to analyze or clean
# - DiskName: The drive letter to process (e.g., "C" for system drive cleanup, "D" for data drive analysis)

# FUNCTIONS
# - Test-ServerAvailability: Pings the target server to confirm network reachability
# - Get-Session: Creates a PowerShell remoting session with retry logic for credential failures
# - Test-DiskAvailability: Verifies the specified disk exists on the remote server
# - Test-ReportFileCreation: Ensures the local system can create report files in C:\temp
# - Clear-SystemCache: Deletes cached files from Windows Update, SCCM, Installer, Temp, and Recycle Bin
# - Compress-IISLogs: Compresses IIS logs older than 6 months into ZIP archives and removes originals
# - Get-DiskSpaceDetails: Collects disk metrics (free space, used space, total size, free percentage)
# - Get-TopItems: Identifies the top 10 largest folders/files, including subfolder breakdowns
# - Export-DiskReport: Generates an HTML report with disk stats, cleanup logs, and large item details
# - Update-StatusLabel: Dynamically updates the GUI with progress messages
# - Remove-Session: Closes remote sessions and disposes of GUI resources

# OUTPUTS
# - HTML Reports: Saved to C:\temp with filenames like LowFreeSpace-<DiskName>-<ServerName>-<Timestamp>.html
#   - For C: drive: Includes before/after cleanup stats, cleanup logs, and top folder/user details
#   - For other drives: Includes disk usage and top folder/file analysis
# - GUI Updates: Real-time status messages during execution (e.g., "Cleaning system cache...")
# - MessageBox Notifications: Alerts for success, errors, or warnings (e.g., disk not found, session failures)
# - Log File: Execution details logged to C:\temp\LowFreeSpace-log.log for troubleshooting

# EXAMPLES
# 1. System Drive Cleanup:
#    - Input: Server name (e.g., "Server01") and DiskName "C"
#    - Actions: Cleans system caches, compresses IIS logs, generates a report comparing before/after stats
#    - Output: Report with cleanup details and top folders/users if free space remains below 10%
#    - Use Case: Free up space on a system drive with low disk space warnings
#
# 2. Data Drive Analysis:
#    - Input: Server name (e.g., "Server02") and DiskName "D"
#    - Actions: Analyzes disk usage and identifies the top 10 largest folders/files
#    - Output: Report with disk metrics and detailed folder/file size breakdown
#    - Use Case: Investigate space usage on a data drive to plan storage management
#
# 3. Error Handling:
#    - Scenario: Invalid server name or unreachable server
#    - Output: MessageBox with error details (e.g., "Server not reachable") and log entry
#    - Scenario: Non-existent disk
#    - Output: MessageBox indicating disk not found

Param(
    [Parameter(Mandatory= $false)]
    [System.Management.Automation.PSCredential]$ADM_Credential,
    [Parameter(Mandatory= $false)]
    [string]$JumpHost
)

# Temporary workaround for testing
if (-not $ADM_Credential) {
    $userName = "automation\adminuser"
    $password = ConvertTo-SecureString "Leduc123!@#" -AsPlainText -Force
    $ADM_Credential = New-Object System.Management.Automation.PSCredential($userName, $password)
}

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

$mainFormWidth = [Math]::Round(($textBoxServerName.Location.X + $textBoxServerName.Width + 40 * $scaleX))

# Disk Name Label
$diskLabel = New-Object System.Windows.Forms.Label
$diskLabel.Location = New-Object System.Drawing.Point($labelServerName.Location.X, ($labelServerName.Location.Y + $labelServerName.Height + $verticalPadding))
$diskLabel.Size = $labelServerName.Size
$diskLabel.Text = "Drive Letter:"
$diskLabel.Font = $labelServerName.Font
$toolTip.SetToolTip($diskLabel, "Enter the drive letter to process (e.g., C or C: or C:\).")

# Disk Name TextBox
$diskTextBox = New-Object System.Windows.Forms.TextBox
$diskTextBox.Location = New-Object System.Drawing.Point($textBoxServerName.Location.X, $diskLabel.Location.Y)
$diskTextBox.Size = $textBoxServerName.Size
$diskTextBox.Font = $labelServerName.Font
$diskTextBox.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        # Select all text in the ComboBox
        $diskTextBox.SelectAll()
        $e.SuppressKeyPress = $true
    }
    elseif ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::C) {
        # Copy selected text to clipboard
        if ($diskTextBox.SelectedText) {
            [System.Windows.Forms.Clipboard]::SetText($diskTextBox.SelectedText)
        } else {
            [System.Windows.Forms.Clipboard]::SetText($diskTextBox.Text)
        }
        $e.SuppressKeyPress = $true
    }
})

# Ticket number Label
$ticketNumberLabel = New-Object System.Windows.Forms.Label
$ticketNumberLabel.Location = New-Object System.Drawing.Point($labelServerName.Location.X, ($diskLabel.Location.Y + $diskLabel.Height + $verticalPadding))
$ticketNumberLabel.Size = $labelServerName.Size
$ticketNumberLabel.Text = "Ticket Number:"
$ticketNumberLabel.Font = $labelServerName.Font
$toolTip.SetToolTip($ticketNumberLabel, "Enter the ticket number associated with this operation.")

# Ticket number TextBox
$ticketNumberTextBox = New-Object System.Windows.Forms.TextBox
$ticketNumberTextBox.Location = New-Object System.Drawing.Point($textBoxServerName.Location.X, $ticketNumberLabel.Location.Y)
$ticketNumberTextBox.Size = $textBoxServerName.Size
$ticketNumberTextBox.Font = $labelServerName.Font
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
    "$PSScriptRoot\..\..\Modules\Get-DiskSpaceDetails.psm1",
    "$PSScriptRoot\..\..\Modules\Export-DiskReport.psm1",
    "$PSScriptRoot\..\..\Modules\Get-TopItems.psm1",
    "$PSScriptRoot\..\..\Modules\Clear-SystemCache.psm1",
    "$PSScriptRoot\..\..\Modules\Compress-IISLogs.psm1",
    "$PSScriptRoot\..\..\Modules\Test-DiskAvailability.psm1",
    "$PSScriptRoot\..\..\Modules\Test-ReportFileCreation.psm1",
    "$PSScriptRoot\..\..\Modules\Test-ServerAvailability.psm1",
    "$PSScriptRoot\..\..\Modules\Write-Log.psm1",
    "$PSScriptRoot\..\..\Modules\Write-WindowsEventLog.psm1"
)

$JumpHostSession = New-PSSession -ComputerName $JumpHost -Credential $ADM_Credential -ErrorAction Stop

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
        # Normalize disk name input
        $rawDiskName = $diskTextBox.Text.Trim()
        $diskName = $rawDiskName -replace '[:\\]', ''
        $diskName = $diskName.ToUpper()
        $serverName = $textBoxServerName.Text.Trim()
        $ticketNumber = $ticketNumberTextBox.Text

        # Import necessary modules to a variable then pass to remote session
        

        $params = @{
            ServerName     = $serverName      
            DiskName       = $diskName
            TicketNumber   = $ticketNumber
            ADM_Credential = $ADM_Credential
        }

        $ScriptBlock = {
            param ($params)
            # Extract values from the hashtable
            $ticketNumber   = $params.TicketNumber
            $diskName       = $params.DiskName
            $ADM_Credential = $params.ADM_Credential
            $serverName     = $params.ServerName      

            try {
                # Initial variable assignments
                $reportPath = $null
                $freePercentageDisk = $null
                $topRoot = $null
                $topUsers = $null
                $topItems = $null
                $diskInfo = $null
                $Before = $null
                $After = $null
                $clearSystemCache = $null
                $clearIISLogs = $null

                if ([string]::IsNullOrEmpty($diskName) -or [string]::IsNullOrEmpty($serverName) -or [string]::IsNullOrEmpty($ticketNumber)) {
                    return "Please fill in all fields (Server Name, Drive Letter, Ticket Number)."
                }
        
                $result = Test-ServerAvailability -serverName $serverName
                if (-not $result.RemotingAvailable) {
                    return "Server $serverName is not reachable or PowerShell Remoting is not available."
                }
        
        
                $session = Get-Session -serverName $serverName -Credential $ADM_Credential
                if ($null -eq $session) {
                    return "Failed to create a session to $serverName. Please check the server name and your credentials."
                }
        
                if (-not (Test-DiskAvailability -session $session -diskName $diskName)) {
                    return "Disk $($diskName):\ not found on server $serverName."
                }
        
                if (-not (Test-ReportFileCreation)) {
                    return "Cannot create report file in C:\temp. Please ensure you have write permissions."
                }
            }
            catch {
                return "Error during initial checks: $_"
            }
        }
        $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
        if ($result) {
            Update-StatusLabel -text $result
            [System.Windows.Forms.MessageBox]::Show($result, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return
        }

        if ($diskName -eq "C") {
            Update-StatusLabel -text "Cleaning system cache..."
            $ScriptBlock = {
                param ($params)
                # Extract values from the hashtable
                $ticketNumber   = $params.TicketNumber
                $diskName       = $params.DiskName
                $ADM_Credential = $params.ADM_Credential
                $serverName     = $params.ServerName   
                try {
                    $Before = Get-DiskSpaceDetails -session $session -diskName $diskName

                    $clearSystemCache = Clear-SystemCache -session $session -Verbose *>&1 | ForEach-Object {
                        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
                    } | Out-String

                    $clearIISLogs = Compress-IISLogs -session $session -Verbose *>&1 | ForEach-Object {
                        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss'): $_"
                    } | Out-String

                    $After = Get-DiskSpaceDetails -session $session -diskName $diskName
                    $freePercentageDisk = $After.FreePercentage
                    $topRoot = $null
                    $topUsers = $null

                    if ($After.FreePercentage -lt 10) {
                        $topRoot = Get-TopItems -session $session -path "$($diskName):\" -exclude @("Windows", "Program Files", "Program Files (x86)", "ProgramData","Users") -topN 10
                        $topUsers = Get-TopItems -session $session -path "$($diskName):\Users" -topN 10
                    }

                    # Write Windows Event Log Entry on the remote server
                    $eventMessage = "User: $CurrentUser`n" + "Ticket Number: $ticketNumber`n" + "Message: C drive cleanup performed. Free space is now $($freePercentageDisk)%.`n"

                    Write-WindowsEventLog -LogName "Application" -Source "DiskAnalysisScript" `
                        -EventID 1002 -EntryType "Information" `
                        -Message $eventMessage -Session $session

                    # Export disk report
                    $reportPath = Export-DiskReport -serverName $serverName -diskName $diskName `
                    -diskInfo $After -beforeDiskInfo $Before `
                    -systemCacheLog $clearSystemCache `
                    -iisLogCleanupLog $clearIISLogs `
                    -topUsers $topUsers -topRoot $topRoot

                    if ($null -eq $reportPath) {
                        return "Failed to create report file."
                    } else {
                        return "C drive cleanup completed. Free space is now $($freePercentageDisk)%. Generating report..."
                    }

                } catch {
                    return "Error during C drive cleanup: $_"
                }
            }
            $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
            if ($result) {
                Update-StatusLabel -text $result
            }
            
        } else {
            Update-StatusLabel -text "Analyzing disk $($diskName):\ ..."
            $ScriptBlock = {
                param ($params)
                # Extract values from the hashtable
                $ticketNumber   = $params.TicketNumber
                $diskName       = $params.DiskName
                $ADM_Credential = $params.ADM_Credential
                $serverName     = $params.ServerName  


                $diskInfo = Get-DiskSpaceDetails -session $session -diskName $diskName
                $topItems = Get-TopItems -session $session -path "$($diskName):\" -topN 10

                $freePercentageDisk = $diskInfo.FreePercentage

                # Write Windows Event Log Entry on the remote server
                $eventMessage = "User: $CurrentUser`n" + "Ticket Number: $ticketNumber`n" + "Message: Disk $($diskName) analysis performed. Free space is now $($freePercentageDisk)%.`n"
                Write-WindowsEventLog -LogName "Application" -Source "DiskAnalysisScript" `
                    -EventID 1002 -EntryType "Information" `
                    -Message $eventMessage -Session $session

                $reportPath = Export-DiskReport -serverName $serverName -diskName $diskName `
                    -diskInfo $diskInfo -topItems $topItems    

                if ($null -eq $reportPath) {
                        return "Failed to create report file."
                } else {
                        return "Disk $($diskName):\ analysis completed. Free space is now $($freePercentageDisk)%. Generating report..."
                }
            }
            $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
            if ($result) {
                Update-StatusLabel -text $result
            }
        }

        # Export the report
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
            Update-StatusLabel -text "Error in OK button click event: $_"
            [System.Windows.Forms.MessageBox]::Show("An error occurred: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }

})

# Exit Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Size = $okButton.Size
$cancelButton.Text = "Cancel"
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({
    $main_form.Close()
    #Remove-Session
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

# Main form setup
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Low Free Space - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size($mainFormWidth, $mainFormLength) #430x270 pixels
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
$main_form.Controls.Add($diskLabel)
$main_form.Controls.Add($diskTextBox)
$main_form.Controls.Add($ticketNumberLabel)
$main_form.Controls.Add($ticketNumberTextBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)
$main_form.Controls.Add($statusLabel)

# Show form
if ($null -eq $env:UNIT_TEST) {
    $main_form.ShowDialog()
}


# Note: 10/10/2025 https://chat.deepseek.com/a/chat/s/7e5f0f88-ec13-4e42-9372-4922d1c2fa8c

<#
$params = @{

        }

$ScriptBlock = {
}

Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
#>