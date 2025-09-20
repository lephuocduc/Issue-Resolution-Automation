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
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        # The extracted folder contains bw.exe directly, move it to System32
        $bwExePath = Join-Path -Path $extractPath -ChildPath "bw.exe"

        # Move bw.exe to System32
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

        if (-not (Get-Command 'bw' -ErrorAction SilentlyContinue)) {
            throw "Bitwarden CLI installation failed."
        }
    } # End of Bitwarden CLI installation check
   
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

    # Check if BW has been logged in before
    # Run bw status and capture the output
    $bwStatus = bw status | ConvertFrom-Json

    # Check the status field
    if ($bwStatus.status -eq "unauthenticated") {
        # Log in to Bitwarden
        bw login --apikey

        # Check if the login was successful
        $bwStatus = bw status | ConvertFrom-Json
        if ($bwStatus.status -eq "unauthenticated") {
            throw "Bitwarden CLI login failed."
        }
    }
       
    $sessionKey = bw unlock --passwordenv BW_PASSWORD --raw    

    if (-not $sessionKey) {
        throw "Failed to unlock Bitwarden CLI session. Please check your credentials."
    } else {
        # Set the session environment variable
        $env:BW_SESSION = $sessionKey
    }

    # Synchronize the Bitwarden vault
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

   
    Start-Sleep -Seconds 1
}