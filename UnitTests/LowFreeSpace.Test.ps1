# LowFreeSpace.Tests.ps1

# Load the script to be tested
. "$PSScriptRoot/../Scripts/LowFreeSpace.ps1"

Describe "Clear-SystemCache Tests" {
    Mock Invoke-Command {
        param ($Session, $ScriptBlock)
        Write-Host "Mocked Invoke-Command executed"
    }
    
    It "Should call Invoke-Command with a valid PSSession" {
        $mockSession = New-Object PSObject
        
        Clear-SystemCache -session $mockSession
        
        Assert-MockCalled Invoke-Command -Exactly 1 -Scope It
    }
    
    It "Should throw an error if session is not provided" {
        {
            Clear-SystemCache
        } | Should -Throw
    }
}

Describe 'Test function Compress-IISLogs'{

}