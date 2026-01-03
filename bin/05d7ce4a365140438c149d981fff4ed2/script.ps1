& {
param($PoshToolsRoot)
# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
<#
# Import all the modules !@#$%^
. (Join-Path $PSScriptRoot "..\Modules\Clear-SystemCache.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Compress-IISLogs.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Export-DiskReport.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-DiskSpaceDetails.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-PerformanceMetrics.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-Session.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-SystemUptime.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-TopCPUProcesses.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-TopItems.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Get-TopMemoryProcesses.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Show-PerformanceDashboard.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Test-DiskAvailability.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Test-ReportFileCreation.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Test-ServerAvailability.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Write-Log.psm1")
. (Join-Path $PSScriptRoot "..\Modules\Write-WindowsEventLog.psm1")
#>
Import-Module -Name $PSScriptRoot\Write-WindowsEventLog.psm1 -Force



function Get-Session {
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null
    )
    try {
        if (Get-PSProvider -PSProvider WSMan -ErrorAction SilentlyContinue) {
            $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
            # Skip update if wildcard exists
                if ($currentTrustedHosts -ne "*") {
                    # Get current list as array
                    $hostList = if (-not [string]::IsNullOrEmpty($currentTrustedHosts)) {
                        $currentTrustedHosts -split ',' | ForEach-Object { $_.Trim() }
                    } else {
                        @()
                    }
                    
                    # Add server if not already present
                    if ($serverName -notin $hostList) {
                        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $serverName -Concatenate -Force -ErrorAction SilentlyContinue
                    }
                }
        }
        try {
            
            $session = New-PSSession -ComputerName $serverName -Credential $Credential -ErrorAction SilentlyContinue
            if ($null -eq $session) {
                return $null
            }
            return $session
        } catch {
            return $null
        }
    }
    catch {
        return $null
    }
}

. "$PSScriptRoot\..\Modules\Clear-SystemCache.psm1"
. "$PSScriptRoot\..\Modules\Compress-IISLogs.psm1"
. "$PSScriptRoot\..\Modules\Compress-IISLogs.psm1"

# Import the Get-BitwardenAuthentication module
Import-Module -Name $PSScriptRoot\Get-BitwardenAuthentication.psm1 -Force


$script:ADM_Credential = $null
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

function Unprotect-BitwardenConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    # Unprotect the encrypted file and convert from JSON
    try {
        $decryptedContent = Unprotect-CmsMessage -Path $ConfigPath | ConvertFrom-Json
        return $decryptedContent
    }
    catch {
        $ErrorMessage = $_.Exception.Message

        # Pop up an error message box
        [System.Windows.Forms.MessageBox]::Show(
            "Error: $ErrorMessage",
            "Decryption Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        throw
    }
}

# Decrypt the Bitwarden configuration
$DecryptedContent = Unprotect-BitwardenConfig -ConfigPath "$PSScriptRoot/EncryptedBitwarden.json"
# Extract values
$clientId = $DecryptedContent.bitwarden.clientId
$clientSecret = $DecryptedContent.bitwarden.clientSecret
$masterPassword = $DecryptedContent.bitwarden.masterPassword
$credentialName = $DecryptedContent.bitwarden.credentialName

# Check if any required value is missing
if (-not $clientId -or -not $clientSecret -or -not $masterPassword -or -not $credentialName) {
    throw "One or more Bitwarden configuration values are missing."
}

function Update-StatusLabel {
    param(
        [Parameter(Mandatory=$true)]
        [string]$text
    )
    
    $statusLabel.Text = $text
    $statusLabel_width = $statusLabel.PreferredWidth
    $label_x = ($bitwarden_form.ClientSize.Width - $statusLabel_width) / 2
    $statusLabel.Location = New-Object System.Drawing.Point($label_x, $statusLabel.Location.Y)
    $statusLabel.Refresh()
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp"
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "ScriptManager-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
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

# Bitwarden form
$bitwarden_form = New-Object System.Windows.Forms.Form
$bitwarden_form.Text = "Script Manager - Checking"
$bitwarden_form.Size = New-Object System.Drawing.Size([Math]::Round(410 * $scaleX) , [Math]::Round(120 * $scaleY))  # Adjust size based on screen resolution
$bitwarden_form.StartPosition = "CenterScreen"
$bitwarden_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$bitwarden_form.MaximizeBox = $false

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true  # Important:  Let the label size itself to the text
$statusLabel.Font = New-Object System.Drawing.Font($statusLabel.Font.FontFamily, [Math]::Round(11* $scaleY))  # Adjust font size based on screen resolution
$statusLabel_width = $statusLabel.PreferredWidth # get the actual width of the label based on the text
$statusLabel.Location = New-Object System.Drawing.Point([Math]::Round(([Math]::Round($bitwarden_form.Size.Width / 2) - $statusLabel_width) * $scaleX), [Math]::Round(([Math]::Round(($bitwarden_form.Size.Height / 2) - $statusLabel.PreferredHeight)) * $scaleY))

  # Initially hidden until the check is done
$bitwarden_form.Controls.Add($statusLabel)
$bitwarden_form.Add_Shown({
    try {
        # Retrieve the ADM_Credential
        Update-StatusLabel -text "Authenticating with Bitwarden..."
        $script:ADM_Credential = Get-BitwardenAuthentication -ClientId $clientId -ClientSecret $clientSecret -MasterPassword $masterPassword -CredentialName $credentialName
        if ($script:ADM_Credential) {       
            # Get all jump host names from the jumphost.json file
            # Test if the file exists
            $jumpHostsFileContent = Get-Content -Path $PSScriptRoot\"jumphost.json" | ConvertFrom-Json
            $jumpHosts = $jumpHostsFileContent.DCS.PSObject.Properties.Value
            if ( -not $jumpHosts -or $jumpHosts.Count -eq 0 ) {
                Write-Log "No jump hosts found in jumphost.json" -Level "Error"
                [System.Windows.Forms.MessageBox]::Show(
                    "No jump hosts found in jumphost.json",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                exit
            } else {
                # Remote session for each jump host on DCS environment and choose the first one
                $script:JumpHost = $null
                foreach ($jumpHost in $jumpHosts) {
                    try {
                        Import-Module "$PSScriptRoot\..\Modules\Get-Session.psm1" -Force

                        $session = Get-Session -serverName $jumpHost -Credential $script:ADM_Credential
                        if ($session) {
                            Write-Log "Successfully created session to $jumpHost" -Level "Info"
                            $script:JumpHost = $jumpHost

                            # 1. Define the correct path to modules
                            $scriptDir = if ($MyInvocation.MyCommand.Path) { 
                                Split-Path $MyInvocation.MyCommand.Path -Parent 
                            } else { 
                                $PSScriptRoot 
                            }
                            $localModulesPath = Join-Path $scriptDir "..\Modules"

                            # Check if the path actually exists before trying to copy
                            if (-not (Test-Path $localModulesPath)) {
                                Write-Log "Local modules path '$localModulesPath' does not exist." -Level "Error"
                                [system.windows.forms.messagebox]::Show(
                                    "Local modules path '$localModulesPath' does not exist.",
                                    "Error",
                                    [System.Windows.Forms.MessageBoxButtons]::OK,
                                    [System.Windows.Forms.MessageBoxIcon]::Error
                                )
                                return
                            }

                            # 2. Get all .psm1 files
                            $moduleFiles = Get-ChildItem -Path $localModulesPath -Filter *.psm1

                            foreach ($file in $moduleFiles) {
                                $moduleName = $file.BaseName
                                # Define the destination path on the remote server
                                $remoteBaseDir = "C:\Program Files\WindowsPowerShell\Modules"
                                $remoteModuleDir = "$remoteBaseDir\$moduleName"
                                
                                Write-Log "Copying module '$moduleName' to $jumpHost`:$remoteModuleDir"

                                # 3. Create the directory on the remote host if it doesn't exist
                                # We use Invoke-Command because Copy-Item fails if the destination folder isn't there.
                                Invoke-Command -Session $session -ArgumentList $remoteModuleDir -ScriptBlock {
                                    param($targetDir)
                                    if (-not (Test-Path -Path $targetDir)) {
                                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                                        Write-Log "Created directory $targetDir on remote host." -Level "Info"
                                    }
                                }

                                # 4. Copy the file to the session
                                # Destination must include the filename because we are copying a file to a folder
                                try {
                                    Copy-Item -Path $file.FullName -Destination "$remoteModuleDir\$($file.Name)" -ToSession $session -Force -ErrorAction Stop
                                    Write-Log "Successfully copied $($file.Name) to $jumpHost`:$remoteModuleDir" -Level "Info"
                                }
                                catch {
                                    Write-Log "Failed to copy $($file.Name) to $jumpHost`:$remoteModuleDir. Error: $_" -Level "Error"
                                    [System.Windows.Forms.MessageBox]::Show(
                                        "Error, check logs for details.",
                                        "Error",
                                        [System.Windows.Forms.MessageBoxButtons]::OK,
                                        [System.Windows.Forms.MessageBoxIcon]::Error
                                    )

                                }
                            }
                            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                            break  # Exit the loop if a session is successfully created
                        }
                    }
                    catch {
                        Write-Log "Failed to create session to `$jumpHost: $_" -Level "Warning"
                    }
                }
        
                if (-not $script:JumpHost) {
                    Write-Log "Could not connect to any jump host." -Level "Error"
                    [System.Windows.Forms.MessageBox]::Show(
                        "Could not connect to any jump host.",
                        "Error",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Error
                    )
                    $bitwarden_form.Close()
                    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
                }
            }
        }
        $bitwarden_form.Close()  # Close the Bitwarden form after successful authentication
        $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    }
    catch {
        Write-Log "An error occurred during Bitwarden authentication: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred during Bitwarden authentication: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
    }
    
})

#########################################
# Create the main form
$main_form = New-Object System.Windows.Forms.Form
$main_form.Text = "Script Manager - $CurrentUser"
$main_form.Size = New-Object System.Drawing.Size([Math]::Round(400 * $scaleX), [Math]::Round(190*$scaleY))  # Adjust size based on screen resolution
$main_form.StartPosition = "CenterScreen"
# Prevent resizing
$main_form.FormBorderStyle = 'FixedSingle'  # Or 'FixedDialog'
$main_form.MaximizeBox = $false

# Label
$label = New-Object System.Windows.Forms.Label
$label.Text = "Choose a script to execute"
$label.AutoSize = $true
$label.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY), [System.Drawing.FontStyle]::Bold)

# Calculate centered position (after text & font set)
$label_width  = $label.PreferredWidth
$label_height = $label.PreferredHeight
$label_x = [Math]::Round( ($main_form.ClientSize.Width  - $label_width) / 2 )
$label_y = [Math]::Round( 25 * $scaleY )
$label.Location = New-Object System.Drawing.Point($label_x, $label_y)
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
#$comboBox.Location = New-Object System.Drawing.Point(110, 50)  # Centered horizontally - REMOVE THIS LINE
$comboBox.Size = New-Object System.Drawing.Size ([Math]::Round(200 * $scaleX), [Math]::Round(25 * $scaleY)) # set the size of combobox
$comboBox.Items.AddRange(@('Low Free Space','Windows Performance'))  # Add items to the dropdown
$comboBox.DropDownStyle = 'DropDown' # Allow text editing in the ComboBox
# Calculate the horizontal center for the ComboBox
$combobox_width = $comboBox.Size.Width
$combobox_x = [Math]::Round(($main_form.ClientSize.Width - $combobox_width) / 2)
$combobox_y = [Math]::Round( 50 * $scaleY ) # set padding from top
$comboBox.Location = New-Object System.Drawing.Point($combobox_x, $combobox_y)
# Set the font size (keep the default font family)
$defaultFont = $comboBox.Font  # Get the default font
$comboBox.Font = New-Object System.Drawing.Font($defaultFont.FontFamily, [Math]::Round(11 * $scaleY))  # Change only the size to 12
$comboBox.Text = "------------------------------"
# Enable AutoComplete functionality
$comboBox.AutoCompleteMode = 'SuggestAppend'  # Suggest matching items and append the rest
$comboBox.AutoCompleteSource = 'ListItems'    # Use items from the ComboBox's list for suggestions
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
$okButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size for consistency


# Add Click event  to execute the selected script using a switch statement
$okButton.Add_Click({
    $selectedValue = $comboBox.Text
    switch ($selectedValue) {        "------------------------------" {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a script from the dropdown.",
                "Information",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }
        "Low Free Space" {
            Param(
    [Parameter(Mandatory= $false)]
    [System.Management.Automation.PSCredential]$ADM_Credential,
    [Parameter(Mandatory= $false)]
    [string]$JumpHost,
    [Parameter(Mandatory= $false)]
    [hashtable]$ModuleContents
)
#Test if module contents is passed, if not load from disk
if ($ModuleContents) {
    # Export all into C:\temp\Modules if yes
    foreach ($moduleName in $ModuleContents.Keys) {
        $content = $ModuleContents[$moduleName]
        $modulePath = "C:\temp\Modules\$moduleName.psm1"
        $directory = [System.IO.Path]::GetDirectoryName($modulePath)
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        $content | Out-File -FilePath $modulePath -Encoding UTF8 -Force
    }
}else {
        # Show error and exit
        [System.Windows.Forms.MessageBox]::Show("Module contents not provided. Cannot proceed.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    
}

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

<#$modulesToImport = @(
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
)#>

$JumpHostSession = Get-Session -serverName $JumpHost -Credential $ADM_Credential

<#foreach ($modulePath in $modulesToImport) {
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
}#>

foreach ($moduleName in $ModuleContents.Keys) {
    try {
        $content = $ModuleContents[$moduleName]
        Invoke-Command -Session $JumpHostSession -ScriptBlock {
            param($moduleContent)
            Invoke-Expression -Command $moduleContent
        } -ArgumentList $content
    }
    catch {
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
        }
        "Windows Performance" {
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
    [System.Management.Automation.PSCredential]$ADM_Credential,
    [Parameter(Mandatory= $false)]
    [string]$JumpHost
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
        }
        default {
            [System.Windows.Forms.MessageBox]::Show(
                "No script is associated with the selection '$selectedValue'.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return}
    }
})

# Create Cancel Button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = 'Cancel'
#$cancelButton.Location = New-Object System.Drawing.Point(220, 100) # Positioning next to the OK button
$cancelButton.Size = New-Object System.Drawing.Size([Math]::Round(80 * $scaleX), [Math]::Round(30 * $scaleY))  # Fixed size matching OK button
$cancelButton.BackColor = [System.Drawing.Color]::LightCoral
$cancelButton.Add_Click({ $main_form.Dispose() })  # Close the form when Cancel is clicked

# Calculate horizontal positions for centered alignment
$buttonWidth = $okButton.Size.Width
$spaceBetween = 25 * $scaleX  # Space between buttons
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point($startX, [Math]::Round(100 * $scaleY))
$cancelButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $spaceBetween), [Math]::Round(100 * $scaleY))

# Add controls to the form
$main_form.Controls.Add($comboBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show the form as a dialog
$bitwarden_form.ShowDialog()


if ($script:ADM_Credential -and $script:JumpHost) {
    # Close the Bitwarden form after authentication
    $bitwarden_form.Close()
    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    
    # Show the main form after Bitwarden authentication
    $main_form.ShowDialog()
}
}