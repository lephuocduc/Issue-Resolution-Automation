# Set default ServerName for testing
$Global:ServerName = "TestServer"

# Load the script to be tested
. "$PSScriptRoot/../Scripts/LowFreeSpace-DataDisk.ps1"

Describe "Test-ServerAvailability" {
    BeforeAll {
        Mock Test-Connection {
            param($ComputerName)
            if ($ComputerName -eq "reachableServer") {
                return $true
            } else {
                return $false
            }
        }
    }

    It "should return true for reachable servers" {
        $result = Test-ServerAvailability -serverName "reachableServer"
        $result | Should -Be $true
    }

    
    It "should return false for unreachable servers" {
        $result = Test-ServerAvailability -serverName "unreachableServer"
        $result | Should -Be $false
    }
}