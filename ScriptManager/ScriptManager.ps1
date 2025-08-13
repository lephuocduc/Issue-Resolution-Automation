#NOTES
# Name:   ScriptManager.ps1
# Author:  Duc Le

# Major Release History:

# Version:  1.0

# Version: 1.1
# - Added Bitwarden CLI installation check and authentication.

#DESCRIPTION
# This script creates a Windows Forms application with a ComboBox to select and execute different PowerShell scripts.

#REQUIREMENT
# None
 
#INPUTS
# Select a script from the ComboBox to execute.

#OUTPUTS
# Executes the selected PowerShell script.

#EXAMPLE
# Run the script and select "Low Free Space" from the ComboBox to execute the LowFreeSpace.ps1 script.

# Load the necessary assembly for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:ADM_Credential = $null
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)


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

function Get-BitwardenAuthentication {
    <#
    .SYNOPSIS
    This function checks if Bitwarden CLI is installed, installs it if not, and authenticates the user using credentials stored in a JSON configuration file.

    .DESCRIPTION
    The function checks for the presence of Bitwarden CLI. If it is not installed, it downloads and extracts the CLI from GitHub, moves it to the System32 directory, and verifies the installation. 
    It then reads the Bitwarden configuration from a JSON file, sets environment variables for authentication, and logs in to Bitwarden CLI. 
    Finally, it retrieves credentials from the Bitwarden vault and returns them as a PSCredential object.

    .PARAMETER ConfigPath
    The path to the Bitwarden configuration file in JSON format. Default is "$PSScriptRoot\bitwarden.json".

    .PARAMETER version
    The version of Bitwarden CLI to install. Default is "1.22.1".

    .OUTPUTS
    Returns a PSCredential object containing the username and password retrieved from Bitwarden.

    .EXAMPLE
    Get-BitwardenAuthentication -ConfigPath "C:\path\to\bitwarden.json" -version "1.22.1"
    This example retrieves Bitwarden credentials using the specified configuration file and version of the Bitwarden CLI.    
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ConfigPath = "$PSScriptRoot\bitwarden.json",
        [string]$version = "1.22.1"
    )

    # Check if Bitwarden CLI is installed
    if (-not (Get-Command 'bw' -ErrorAction SilentlyContinue)) {
        # URLs and paths
        $baseUrl = "https://github.com/bitwarden/cli/releases/download/v$version"
        $zipFileName = "bw-windows-$version.zip"
        $downloadUrl = "$baseUrl/$zipFileName"
        $zipPath = "$env:TEMP\$zipFileName"
        $extractPath = "$env:TEMP\bw-extract"
        $destinationPath = "$env:windir\System32\bw.exe"
        
        # Download the Bitwarden CLI zip file
        Update-StatusLabel -text "Downloading Bitwarden CLI version $version..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

        # Check if the download was successful
        if (-not (Test-Path $zipPath)) {
            throw "Failed to download Bitwarden CLI from $downloadUrl. Please check your internet connection or the URL."
        }

        # Remove any previous extraction folder
        if (Test-Path $extractPath) {
            Remove-Item -Recurse -Force $extractPath
        }

        # Extract the downloaded zip file
        Update-StatusLabel -text "Extracting Bitwarden CLI..."
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        # The extracted folder contains bw.exe directly, move it to System32
        $bwExePath = Join-Path -Path $extractPath -ChildPath "bw.exe"

        # Move bw.exe to System32
        Update-StatusLabel -text "Moving bw.exe to $destinationPath..."
        Write-Log "Moving bw.exe from $bwExePath to $destinationPath."
        Move-Item -Path $bwExePath -Destination $destinationPath -Force

        # Check if the move was successful
        if (-not (Test-Path $destinationPath)) {
            throw "Failed to move bw.exe to $destinationPath. Please check permissions or the destination path."
        }

        # Clean up downloaded zip and extracted files
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $extractPath -ErrorAction SilentlyContinue

        # Verify installation
        Update-StatusLabel -text "Verifying installation..."

        if (-not (Get-Command 'bw' -ErrorAction SilentlyContinue)) {
            throw "Bitwarden CLI installation failed."
        }
    } # End of Bitwarden CLI installation check


    Update-StatusLabel -text "Checking Bitwarden configuration..."
    
    # Get Bitwarden configuration
    if ((Test-Path $ConfigPath) -and (Get-Content $ConfigPath)) {
        $bwConfig = Get-Content $ConfigPath | ConvertFrom-Json
        if (-not $bwConfig.bitwarden.clientId -or -not $bwConfig.bitwarden.clientSecret -or -not $bwConfig.bitwarden.masterPassword -or -not $bwConfig.bitwarden.credentialName) {
            throw "Bitwarden configuration file is missing required fields"
        } else {
            $env:BW_CLIENTID = $bwConfig.bitwarden.clientId
            $env:BW_CLIENTSECRET = $bwConfig.bitwarden.clientSecret
            $env:BW_PASSWORD = $bwConfig.bitwarden.masterPassword
            $env:BW_CREDENTIALNAME = $bwConfig.bitwarden.credentialName
        }
    } else {
        throw "Bitwarden configuration file not found or is empty."
    }

    # If bw command is available, proceed with authentication
    Update-StatusLabel -text "Checking Bitwarden login status..."

    # Check if BW has been logged in before
    # Run bw status and capture the output
    $bwStatus = bw status | ConvertFrom-Json

    # Check the status field
    if ($bwStatus.status -eq "unauthenticated") {
        Update-StatusLabel -text "Logging in to Bitwarden CLI..."
        # Log in to Bitwarden
        bw login --apikey

        # Check if the login was successful
        $bwStatus = bw status | ConvertFrom-Json
        if ($bwStatus.status -eq "unauthenticated") {
            throw "Bitwarden CLI login failed."
        }
    } else {
        Update-StatusLabel -text "Already logged in to Bitwarden CLI."
    }
       
    Update-StatusLabel -text "Unlocking Bitwarden CLI session..."
    $sessionKey = bw unlock --passwordenv BW_PASSWORD --raw    

    if (-not $sessionKey) {
        throw "Failed to unlock Bitwarden CLI session. Please check your credentials."
    } else {
        # Set the session environment variable
        $env:BW_SESSION = $sessionKey
    }

    # Synchronize the Bitwarden vault
    Update-StatusLabel -text "Synchronizing Bitwarden vault..."
    bw sync --session $env:BW_SESSION | Out-Null

    $itemList = bw list items --session $env:BW_SESSION | ConvertFrom-Json
    $item = $itemList | Where-Object { $_.name -eq $env:BW_CREDENTIALNAME }
    if (-not $item) {
        throw "Credential '$env:BW_CREDENTIALNAME' not found in Bitwarden vault."
    }
    $username = $item.login.username
    $password = $item.login.password

    # Check if username and password are retrieved
    if (-not $username -or -not $password) {
        throw "Failed to retrieve username or password from Bitwarden vault."
    }

    $ADM_UserName = $username
    $ADM_Password = ConvertTo-SecureString -String $password -AsPlainText -Force
    $script:ADM_Credential = New-Object System.Management.Automation.PSCredential($ADM_UserName, $ADM_Password)

    return $script:ADM_Credential

    Update-StatusLabel -text "Script Manager is ready to use."
    
    Start-Sleep -Seconds 1
}

# Get all video controller objects
$screens = Get-WmiObject -Class Win32_VideoController

# Initialize scale factors
$scaleX = 1
$scaleY = 1

# Set design resolution
$designWidth = 1920
$designHeight = 1080

# Loop through all video controllers
foreach ($screen in $screens) {
    $screenWidth = $screen.CurrentHorizontalResolution
    $screenHeight = $screen.CurrentVerticalResolution
    if ($screenWidth -and $screenHeight) {
        $scaleX = $screenWidth / $designWidth
        $scaleY = $screenHeight / $designHeight
    }
}
    
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
        Get-BitwardenAuthentication
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
$comboBox.Items.AddRange(@('Heartbeat','Low Free Space','Windows Performance'))  # Add items to the dropdown
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
        "Heartbeat" {
            . (Join-Path $PSScriptRoot "..\Scripts\Heartbeat\Heartbeat.ps1") -ADM_Credential $script:ADM_Credential
        }
        "Low Free Space" {
            . (Join-Path $PSScriptRoot "..\Scripts\LowFreeSpace\LowFreeSpace.ps1") -ADM_Credential $script:ADM_Credential
        }
        "Windows Performance" {
            . (Join-Path $PSScriptRoot "..\Scripts\WindowsPerformance\WindowsPerformance.ps1") -ADM_Credential $script:ADM_Credential
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


if ($script:ADM_Credential) {
    # Close the Bitwarden form after authentication
    $bitwarden_form.Close()
    $bitwarden_form.Dispose()  # Dispose of the Bitwarden form to free resources
    # Show the main form after Bitwarden authentication
    $main_form.ShowDialog()
}





























