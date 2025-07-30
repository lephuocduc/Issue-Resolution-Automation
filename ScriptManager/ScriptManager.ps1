#NOTES
# Name:   ScriptManager.ps1
# Author:  Duc Le
# Version:  1.0
# Major Release History:

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
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[1]


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
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    $LogPath = Join-Path $LogDirectory "ScriptManager-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Get-BitwardenAuthentication {
    # Check if Bitwarden CLI is installed
    if (-not (Get-Command 'bw' -ErrorAction SilentlyContinue)) {
        # URLs and paths
        $version = "1.22.1"
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
            Write-Log "Failed to download Bitwarden CLI from $downloadUrl." -Level "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to download Bitwarden CLI. Please check your internet connection or the URL.",
                "Download Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            $bitwarden_form.Close()  # Close the Bitwarden form
            $bitwarden_form.Dispose()  # Close the Bitwarden form
            return
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
            Write-Log "Failed to move bw.exe to $destinationPath." -Level "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to install Bitwarden CLI.",
                "Installation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            $bitwarden_form.Close()  # Close the Bitwarden form
            $bitwarden_form.Dispose()  # Close the Bitwarden form
            return
        }

        # Clean up downloaded zip and extracted files
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $extractPath -ErrorAction SilentlyContinue

        # Verify installation
        Update-StatusLabel -text "Verifying installation..."

        if (-not (Get-Command 'bw' -ErrorAction SilentlyContinue)) {
            Write-Log "Bitwarden CLI installation failed." -Level "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Bitwarden CLI installation failed. Please try again.",
                "Installation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            $bitwarden_form.Close()  # Close the Bitwarden form
            $bitwarden_form.Dispose()  # Close the Bitwarden form
            return
        }
    } # End of Bitwarden CLI installation check

    # If bw command is available, proceed with authentication
    Update-StatusLabel -text "Checking Bitwarden login status..."

    # Check if BW has been logged in before
    # Run bw status and capture the output
    $bwStatus = bw status | ConvertFrom-Json

    # Check the status field
    if ($bwStatus.status -eq "unauthenticated") {
        Update-StatusLabel -text "Logging in to Bitwarden CLI..."
        # Log in to Bitwarden
        $env:BW_CLIENTID = "user.a70e6672-6b16-4539-be6c-b327002104f7"
        $env:BW_CLIENTSECRET = "LFXVMuhkdDcokVMAdWETV79fLy87Xn"
        bw login --apikey

        # Check if the login was successful
        $bwStatus = bw status | ConvertFrom-Json
        if ($bwStatus.status -eq "unauthenticated") {
            Write-Log "Bitwarden CLI login failed." -Level "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Bitwarden CLI login failed. Please check your credentials.",
                "Login Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            $bitwarden_form.Close()  # Close the Bitwarden form
            $bitwarden_form.Dispose()  # Close the Bitwarden form
            return
        }
    } else {
        Update-StatusLabel -text "Already logged in to Bitwarden CLI."
    }

    # Synchronize the Bitwarden vault
    Update-StatusLabel -text "Synchronizing Bitwarden vault..."
    bw sync

    $env:BW_PASSWORD = "#q+m:ZcQjhQ.M7q"
    
    # Capture the session key
    Update-StatusLabel -text "Unlocking Bitwarden CLI session..."
    $sessionKey = bw unlock --passwordenv BW_PASSWORD --raw
    if ($sessionKey) {
        $env:BW_SESSION = $sessionKey
    } else {
        Write-Log "Failed to unlock Bitwarden CLI session." -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to unlock Bitwarden CLI session.",
            "Unlock Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
        return
    }

    

    $itemList = bw list items --session $env:BW_SESSION | ConvertFrom-Json
    $item = $itemList | Where-Object { $_.name -eq "adm credentials" }
    if (-not $item) {
        Write-Log "No item found with the name 'adm credentials' in Bitwarden." -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "No item found with the name 'adm credentials' in Bitwarden.",
            "Retrieval Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        # Logout the Bitwarden session
        bw logout --session $env:BW_SESSION | Out-Null
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
        return
    }
    $username = $item.login.username
    $password = $item.login.password

    # Check if username and password are retrieved
    if (-not $username -or -not $password) {
        Write-Log "Username or password not found in Bitwarden." -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Username or password not found in Bitwarden.",
            "Retrieval Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        # Logout the Bitwarden session
        bw logout --session $env:BW_SESSION | Out-Null
        $bitwarden_form.Close()  # Close the Bitwarden form
        $bitwarden_form.Dispose()  # Close the Bitwarden form
        return
    }

    bw logout --session $env:BW_SESSION

    $ADM_UserName = $username
    $ADM_Password = ConvertTo-SecureString -String $password -AsPlainText -Force
    $script:ADM_Credential = New-Object System.Management.Automation.PSCredential($ADM_UserName, $ADM_Password)

    Update-StatusLabel -text "Script Manager is ready to use."
    # Logout the Bitwarden session
    
    Start-Sleep -Seconds 1
}

# Get screen resolution
$screen = Get-WmiObject -Class Win32_VideoController
$screenWidth = $screen.CurrentHorizontalResolution
$screenHeight = $screen.CurrentVerticalResolution
# Set scaling factors based on an assumed design size (e.g., 1920x1080)
$designWidth = 1920
$designHeight = 1080
$scaleX = $screenWidth / $designWidth
$scaleY = $screenHeight / $designHeight
    
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
    Get-BitwardenAuthentication
    $bitwarden_form.Close()  # Close the Bitwarden form
    $bitwarden_form.Dispose()  # Close the Bitwarden form
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
# Calculate horizontal center
$label.AutoSize = $true  # Important:  Let the label size itself to the text
$label.Text = "Choose a script to execute"
$label.Font = New-Object System.Drawing.Font("Arial", [Math]::Round(11 * $scaleY), [System.Drawing.FontStyle]::Bold)
$label_width = $label.PreferredWidth # get the actual width of the label based on the text
$label_x = ($main_form.ClientSize.Width - $label_width) / 2  # Center horizontally
$label_y = 25  # Top padding
$label.Location = New-Object System.Drawing.Point([Math]::Round($label_x * $scaleX), [Math]::Round($label_y * $scaleY))
#$label.Size = New-Object System.Drawing.Size(300, 30) #No need to specify size, as AutoSize set to true
$main_form.Controls.Add($label)

# Create a ComboBox (dropdown) and set its properties
$comboBox = New-Object System.Windows.Forms.ComboBox
#$comboBox.Location = New-Object System.Drawing.Point(110, 50)  # Centered horizontally - REMOVE THIS LINE
$comboBox.Size = New-Object System.Drawing.Size ([Math]::Round(200 * $scaleX), [Math]::Round(25 * $scaleY)) # set the size of combobox
$comboBox.Items.AddRange(@('Heartbeat','Low Free Space','Windows Performance'))  # Add items to the dropdown
$comboBox.DropDownStyle = 'DropDown' # Allow text editing in the ComboBox
# Calculate the horizontal center for the ComboBox
$combobox_width = $comboBox.Size.Width
$combobox_x = ($main_form.ClientSize.Width - $combobox_width) / 2
$combobox_y = 50 # set padding from top
$comboBox.Location = New-Object System.Drawing.Point([Math]::Round($combobox_x * $scaleX), [Math]::Round($combobox_y * $scaleY))
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
$spaceBetween = 25
$totalWidth = ($buttonWidth * 2) + $spaceBetween
$startX = ($main_form.ClientSize.Width - $totalWidth) / 2

# Position buttons
$okButton.Location = New-Object System.Drawing.Point([Math]::Round($startX * $scaleX), [Math]::Round(100 * $scaleY))
$cancelButton.Location = New-Object System.Drawing.Point([Math]::Round(($startX + $buttonWidth + $spaceBetween) * $scaleX), [Math]::Round(100 * $scaleY))

# Add controls to the form
$main_form.Controls.Add($comboBox)
$main_form.Controls.Add($okButton)
$main_form.Controls.Add($cancelButton)

# Show the form as a dialog
$bitwarden_form.ShowDialog()


if ($script:ADM_Credential) {
    # Show the main form after Bitwarden authentication
    $main_form.ShowDialog()
}















