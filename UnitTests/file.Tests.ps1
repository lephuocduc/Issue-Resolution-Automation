function Get-Session {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [scriptblock]$SetTrustedHosts = { param($server) Set-Item WSMan:\localhost\Client\TrustedHosts -Value $server -Concatenate -Force },
        [scriptblock]$CreateSession = { param($server, $cred) New-PSSession -ComputerName $server -Credential $cred -ErrorAction Stop }
    )

    $retryCount = 0
    $success = $false
    $session = $null

    # If no credential is provided, prompt for it
    $effectiveCredential = $Credential
    if ($null -eq $effectiveCredential) {
        $effectiveCredential = Get-Credential -Message "Enter credentials for $ServerName"
        if ($null -eq $effectiveCredential) {
            return $null # User canceled the prompt
        }
    }

    while ($retryCount -lt $MaxRetries -and -not $success) {
        try {
            # Suppress output from SetTrustedHosts
            $null = & $SetTrustedHosts -server $ServerName
            $session = & $CreateSession -server $ServerName -cred $effectiveCredential
            $success = $true
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                return $null
            }
        }
    }

    return $session
}

Describe "Get-Session" {
    BeforeAll {
        # Mock credentials for testing
        $credential = [PSCredential]::new("testuser", (ConvertTo-SecureString "testpass" -AsPlainText -Force))
        # Mock session object
        $mockSession = [PSCustomObject]@{ Name = "MockSession" }
    }

    Context "With provided credentials" {
        It "Returns a session when creation succeeds on first attempt" {
            $setTrustedHostsMock = { param($server) $true }
            $createSessionMock = { param($server, $cred) $mockSession }

            $result = Get-Session -ServerName "TestServer" -Credential $credential -MaxRetries 3 -SetTrustedHosts $setTrustedHostsMock -CreateSession $createSessionMock

            $result | Should -Be $mockSession
        }

        It "Retries up to MaxRetries and returns null on repeated failures" {
            $setTrustedHostsMock = { param($server) $true }
            $createSessionMock = { param($server, $cred) throw "Connection failed" }

            $result = Get-Session -ServerName "TestServer" -Credential $credential -MaxRetries 3 -SetTrustedHosts $setTrustedHostsMock -CreateSession $createSessionMock

            $result | Should -Be $null
        }
    }

    Context "With interactive credential prompt" {
        It "Returns null if Get-Credential is canceled" {
            Mock -CommandName Get-Credential { $null }

            $result = Get-Session -ServerName "TestServer" -MaxRetries 3

            $result | Should -Be $null
            Assert-MockCalled -CommandName Get-Credential -Times 1 -Exactly
        }

    }

    Context "Invalid inputs" {
        It "Throws an error if ServerName is empty" {
            { Get-Session -ServerName "" -Credential $credential } | Should -Throw
        }
    }

    Context "Custom scriptblocks" {
        It "Uses custom SetTrustedHosts and CreateSession scriptblocks" {
            $script:customSetTrustedHostsCalled = $false
            $script:customCreateSessionCalled = $false
            $customSetTrustedHosts = { param($server) $script:customSetTrustedHostsCalled = $true }
            $customCreateSession = { param($server, $cred) $script:customCreateSessionCalled = $true; return $mockSession }

            $result = Get-Session -ServerName "TestServer" -Credential $credential -SetTrustedHosts $customSetTrustedHosts -CreateSession $customCreateSession

            $result | Should -Be $mockSession
            $script:customSetTrustedHostsCalled | Should -Be $true
            $script:customCreateSessionCalled | Should -Be $true
        }
    }
}