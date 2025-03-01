<## module.Tests.ps1

# Load the script to be tested
. "$PSScriptRoot/../modules/module.ps1"

#. (Join-Path '..\modules\module.ps1')
Describe "Test Test-ServerAvailability" {
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

Describe "Test Get-Session" {    
    Context "When connection fails" {
        BeforeAll {
            Mock Get-Credential { return $credential }  # Add this mock
            Mock New-PSSession { throw "Connection failed" }
        }
        It "Returns null after max retries" {
            $credential = [PSCredential]::new("testuser", (ConvertTo-SecureString "testpass" -AsPlainText -Force))
            $result = Get-Session -serverName "TestServer" -Credential $credential
            $result | Should -Be $null
        }
    }
}#>