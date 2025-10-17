<#
1. UK team manage the Get-BitwardenAuthentication function and bitwarden.json file.
2. UK team create a self-signed certificate and import it for users.
3. UK team encrypt the file with a self-signed certificate, then they send us the encrypted file.
    
    ```powershell (an example for creating self-signed certificate and encrypting the file, should use a proper CA certificate in production)
    New-SelfSignedCertificate -DnsName "RecipientName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage KeyEncipherment,DataEncipherment -Type DocumentEncryptionCert
    
    Protect-CmsMessage -To "F0241B779B51B0EA58CC004E079EF52B921994DC" -Path "C:\IssueResolutionAutomation\ScriptManager\bitwarden.json" -OutFile "C:\IssueResolutionAutomation\ScriptManager\EncryptedBitwarden.json"
    ```
    
4. The script will decrypt the file content with certificate and get 4 values from the file like clientid, clientsecret, masterpassword, credentialname. We use them as parameters in Get-BitwardenAuthentication function.
5. The script get credentials from Bitwarden for server authentication under user context.
#>

function Get-BitwardenAuthentication {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$version = "1.22.1",
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$clientSecret,
        [Parameter(Mandatory=$true)]
        [string]$masterPassword,
        [Parameter(Mandatory=$true)]
        [string]$credentialName
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
   
    $env:BW_CLIENTID = $clientId
    $env:BW_CLIENTSECRET = $clientSecret
    $env:BW_PASSWORD = $masterPassword
    $env:BW_CREDENTIALNAME = $credentialName

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