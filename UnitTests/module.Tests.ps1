# module.Tests.ps1

# Load the script to be tested
. "$PSScriptRoot/../modules/module.ps1"

#. (Join-Path '..\modules\module.ps1')
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

# Save this as Get-Session.Tests.ps1

Describe "Get-Session Test" {
    BeforeAll {
        # Mock external commands
        # Mock credentials for testing
        $credential = [PSCredential]::new("testuser", (ConvertTo-SecureString "testpass" -AsPlainText -Force))

        <#Mock Set-Item -MockWith {
            # Simulate setting TrustedHosts successfully
            return $true
        }#>

        <#Mock New-PSSession -MockWith {
            # Return a mock PSSession object
            return [PSCustomObject]@{
                ComputerName = $args[2]  # This corresponds to -ComputerName parameter
                State        = "Opened"
                Id           = 1
            }
        }#>
    }

    Context "When connection succeeds on first attempt" {
        <#It "Returns a valid PSSession object" {
            $result = Get-Session -serverName "TestServer"
            
            $result | Should -Not -BeNullOrEmpty
            $result.ComputerName | Should -Be "TestServer"
            $result.State | Should -Be "Opened"
        }#>

        It "Returns null if Get-Credential is canceled" {
            Mock -CommandName Get-Credential { $null }

            $result = Get-Session -ServerName "TestServer"

            $result | Should -Be $null
            Assert-MockCalled -CommandName Get-Credential -Times 1 -Exactly
        }
    }

    <#Context "When connection fails once then succeeds" {
        BeforeEach {
            # Reset mock counts
            Clear-MockHistory

            # Mock New-PSSession to fail first time, succeed second time
            $callCount = 0
            Mock New-PSSession -MockWith {
                $callCount++
                if ($callCount -eq 1) {
                    throw "Connection failed"
                }
                return [PSCustomObject]@{
                    ComputerName = $args[2]
                    State        = "Opened"
                    Id           = 1
                }
            }
        }

        It "Retries and returns session on second attempt" {
            $result = Get-Session -serverName "TestServer"
            
            $result | Should -Not -BeNullOrEmpty
            $result.ComputerName | Should -Be "TestServer"
            Assert-MockCalled New-PSSession -Times 2 -Exactly
        }
    }

    Context "When connection fails maximum times" {
        BeforeEach {
            # Reset mock counts
            Clear-MockHistory

            # Mock New-PSSession to always fail
            Mock New-PSSession -MockWith {
                throw "Connection failed"
            }
        }

        It "Returns null after max retries" {
            $result = Get-Session -serverName "TestServer"
            
            $result | Should -BeNullOrEmpty
            Assert-MockCalled New-PSSession -Times 3 -Exactly
        }
    }

    Context "When serverName parameter is missing" {
        It "Throws parameter missing error" {
            { Get-Session -ErrorAction Stop } | Should -Throw -ErrorId "ParameterBindingValidationException"
        }
    }#>
}