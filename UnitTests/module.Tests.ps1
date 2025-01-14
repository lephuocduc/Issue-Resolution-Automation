# Load the script to be tested
. "$PSScriptRoot/../modules/module.ps1"
#. (Join-Path $PSScriptRoot '..\modules\module.ps1')

# Test the function Write-Message
Describe 'Write-Message' {
    
    BeforeAll {
        # Mock the Out-File and Test-Path commands
        Mock -CommandName Test-Path -MockWith { return $false }
        Mock -CommandName New-Item -MockWith { return $null }
        Mock -CommandName Out-File -MockWith { return $null }
    }

    # Test case 1: It creates the temp directory if it does not exist
    It 'Creates the temp directory if it does not exist' {
        # Act
        Write-Message -message "Test message"

        # Assert
        Assert-MockCalled -CommandName Test-Path -Exactly 1 -Scope It
        Assert-MockCalled -CommandName New-Item -Exactly 1 -Scope It
    }

    # Test case 2: It writes the message to script_status.txt
    It 'Writes the message to script_status.txt' {
        # Act
        Write-Message -message "This is a test message."

        # Assert
        Assert-MockCalled -CommandName Out-File -Exactly 1 -Scope It
    }
}


Describe "Test-ServerAvailability" {
    BeforeAll {
        Mock -CommandName Test-Connection -MockWith {
            param($ComputerName)
            if ($ComputerName -eq "reachableServer") {
                return $true
            } else {
                return $false
            }
        }
    }

    # Test case 1: It should return true for reachable servers
    It "Should return true for reachable servers" {
        $result = Test-ServerAvailability -serverName "reachableServer"
        $result | Should -Be $true
    }

    # Test case 2: It should return false for unreachable servers
    It "Should return false for unreachable servers" {
        $result = Test-ServerAvailability -serverName "unreachableServer"
        $result | Should -Be $false
    }
}

<#Describe 'Get-Session Function' {
    # Define a mock credential object
    $mockCredential = [PSCredential]::new(
        "testuser",
        (ConvertTo-SecureString "password" -AsPlainText -Force)
    )

    # Mock dependencies
    Mock -CommandName Get-Credential {
        $mockCredential
    }
    Mock -CommandName Set-Item
    Mock -CommandName New-PSSession {
        [PSCustomObject]@{ Name = "PSSession"; ComputerName = $serverName }
    }

    Context 'Successful Session Creation' {
        It 'Returns a session object when connection succeeds' {
            # Arrange
            $serverName = 'TestServer'

            # Act
            $result = Get-Session -serverName $serverName

            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSObject]
            Assert-MockCalled -CommandName New-PSSession -Exactly 1 -Scope It
        }
    }

    Context 'Max Retry Exceeded' {
        It 'Returns $null when max retries are exceeded' {
            # Arrange
            Mock -CommandName Get-Credential { $null } -Verifiable -Times 3
            $serverName = 'TestServer'

            # Act
            $result = Get-Session -serverName $serverName

            # Assert
            $result | Should -BeNull
            Assert-MockCalled -CommandName Get-Credential -Exactly 3 -Scope It
        }
    }

    Context 'Exception Handling' {
        It 'Retries when New-PSSession throws an exception' {
            # Arrange
            Mock -CommandName New-PSSession { throw "Connection failed" } -Verifiable -Times 2
            $serverName = 'TestServer'

            # Act
            $result = Get-Session -serverName $serverName

            # Assert
            $result | Should -BeNull
            Assert-MockCalled -CommandName New-PSSession -Exactly 2 -Scope It
        }
    }

    Context 'TrustedHosts Configuration' {
        It 'Sets TrustedHosts before creating a session' {
            # Arrange
            $serverName = 'TestServer'

            # Act
            Get-Session -serverName $serverName

            # Assert
            Assert-MockCalled -CommandName Set-Item -Exactly 1 -Scope It
        }
    }
}#>