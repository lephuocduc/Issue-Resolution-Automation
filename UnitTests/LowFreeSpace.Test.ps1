# LowFreeSpace.Tests.ps1

# Load the script to be tested
. "$PSScriptRoot/../Scripts/LowFreeSpace.ps1"

# Clear-SystemCache.Tests.ps1
Describe "Clear-SystemCache" {
    BeforeAll {
        # Create a mock PSSession
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }

    Context "When paths exist and files are older than 5 days" {
        BeforeEach {
            # Set up TestDrive with mock file structure
            New-Item -Path "TestDrive:\Windows\SoftwareDistribution\Download" -ItemType Directory -Force
            New-Item -Path "TestDrive:\Windows\Installer\$PatchCache$" -ItemType Directory -Force
            New-Item -Path "TestDrive:\Windows\ccmcache" -ItemType Directory -Force
            New-Item -Path "TestDrive:\Windows\Temp" -ItemType Directory -Force

            # Create old test files (older than 5 days)
            $oldDate = (Get-Date).AddDays(-6)
            New-Item -Path "TestDrive:\Windows\SoftwareDistribution\Download\oldfile.txt" -ItemType File -Force | 
                Set-ItemProperty -Name LastWriteTime -Value $oldDate
            New-Item -Path "TestDrive:\Windows\Installer\$PatchCache$\oldpatch.msi" -ItemType File -Force | 
                Set-ItemProperty -Name LastWriteTime -Value $oldDate
            New-Item -Path "TestDrive:\Windows\ccmcache\oldcache.dat" -ItemType File -Force | 
                Set-ItemProperty -Name LastWriteTime -Value $oldDate
            New-Item -Path "TestDrive:\Windows\Temp\oldtemp.tmp" -ItemType File -Force | 
                Set-ItemProperty -Name LastWriteTime -Value $oldDate
        }

        It "Should clean Windows Update cache" {
            Mock Invoke-Command { 
                param ($Session, $ScriptBlock)
                & $ScriptBlock
            }

            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\" }
            Mock Get-ChildItem { Get-ChildItem "TestDrive:\Windows\SoftwareDistribution\Download" }
            Mock Remove-Item { }

            Clear-SystemCache -session $mockSession

            Assert-MockCalled Remove-Item -Times 1 -Scope It
        }

        It "Should clean Windows Installer patch cache" {
            Mock Invoke-Command { 
                param ($Session, $ScriptBlock)
                & $ScriptBlock
            }

            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Windows\Installer\`$PatchCache`$*" }
            Mock Get-ChildItem { Get-ChildItem "TestDrive:\Windows\Installer\`$PatchCache`$" }
            Mock Remove-Item { }

            Clear-SystemCache -session $mockSession

            Assert-MockCalled Remove-Item -Times 1 -Scope It
        }
    }

    Context "When paths don't exist" {
        It "Should handle missing Windows Update cache path" {
            Mock Invoke-Command { 
                param ($Session, $ScriptBlock)
                & $ScriptBlock
            }

            Mock Test-Path { $false } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\" }
            Mock Write-Host { }

            Clear-SystemCache -session $mockSession

            Assert-MockCalled Write-Host -Times 1 -Scope It -ParameterFilter { 
                $Object -eq "Windows Update cache path not found" 
            }
        }
    }

    Context "When errors occur" {
        It "Should handle errors in Windows Temp files cleaning" {
            Mock Invoke-Command { 
                param ($Session, $ScriptBlock)
                & $ScriptBlock
            }

            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\Windows\Temp\*" }
            Mock Get-ChildItem { throw "Access denied" }
            Mock Write-Host { }

            Clear-SystemCache -session $mockSession

            Assert-MockCalled Write-Host -Times 1 -Scope It -ParameterFilter { 
                $Object -like "Error cleaning Windows Temp files:*" 
            }
        }
    }

    Context "Parameter validation" {
        It "Should require session parameter" {
            { Clear-SystemCache -ErrorAction Stop } | Should -Throw -ExpectedMessage "*Missing an argument for parameter 'session'*"
        }

        It "Should accept valid PSSession object" {
            { Clear-SystemCache -session $mockSession } | Should -Not -Throw
        }
    }

    Context "Recycle Bin cleaning" {
        It "Should attempt to clear Recycle Bin" {
            Mock Invoke-Command { 
                param ($Session, $ScriptBlock)
                & $ScriptBlock
            }

            Mock Clear-RecycleBin { }
            Mock Write-Host { }

            Clear-SystemCache -session $mockSession

            Assert-MockCalled Clear-RecycleBin -Times 1 -Scope It
        }
    }
}

Describe 'Test function Compress-IISLogs'{

}