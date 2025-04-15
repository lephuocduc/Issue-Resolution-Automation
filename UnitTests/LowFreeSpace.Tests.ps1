<#
Test Clear-SystemCache function
Test case 1: It should invoke the cleanup script block on remote session
Test case 2: It should contain all required cleanup tasks (Windows Update Cache, Windows Installer Patch Cache, SCCM Cache, Windows Temp files)
Test case 3: It should throw an error for null session
Test case 4: It should only delete old Windows Update cache files older than 5 days
Test case 5: It should not delete any files if Windows Update cache files aren't found
Test case 6: It should only delete old Windows Installer patch cache files older than 5 days
Test case 7: It should clear Recycle Bin


Test Compress-IISLogs function
Test case 1: It should only compress and delete old IIS logs older than 6 months
Test case 2: It should not compress or delete when IIS log path does not exist
#>

# Check for Pester 5.7.1 and exit if not available
$PesterModule = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -eq "5.7.1" }
if (-not $PesterModule) {
    Write-Host "Pester version 5.7.1 is not installed. Attempting to install..."
    try {
        Install-Module -Name Pester -RequiredVersion 5.7.1 -Force -SkipPublisherCheck -ErrorAction Stop
        Import-Module Pester -RequiredVersion 5.7.1
        Write-Host "Pester 5.7.1 successfully installed and imported."
    }
    catch {
        Write-Host "Failed to install Pester 5.7.1. Error: $_"
        Write-Host "This script requires Pester 5.7.1 to run. Exiting..."
        exit 1
    }
}
else {
    Write-Host "Pester version 5.7.1 is installed."
    Import-Module Pester -RequiredVersion 5.7.1
}

$env:UNIT_TEST = "true"
# Load the script to be tested
. "$PSScriptRoot/../Scripts/LowFreeSpace.ps1"

Describe "Test Clear-SystemCache" {
    BeforeAll {
        # Create a proper mock PSSession
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }      

        Context "When session parameter is invalid" {
            #Test case 3: It should throw an error for null session
            It "Throws error for null session" {
                Write-Host "Throws error for null session"
                # Act & Assert
                { Clear-SystemCache -session $null } | 
                Should -Throw -ExpectedMessage "*Cannot bind argument to parameter 'session' because it is null.*"
            }
        }

        Context "2 files older than 5 days exist, 1 file newer than 5 days exists" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                $oldFiles = @(
                    [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile.txt"; LastWriteTime = (Get-Date).AddDays(-6) }
                    [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile2.txt"; LastWriteTime = (Get-Date).AddDays(-2) }
                    [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile3.txt"; LastWriteTime = (Get-Date).AddDays(-7) }
                )
                Mock Test-Path { return $true } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\" }

                # Mock other paths to return no files
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\*" }
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\ccmcache\*" }
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\Temp\*" }

                Mock Get-ChildItem { return $oldFiles } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download" }
                Mock Remove-Item {}
                Mock Write-Host {}

                # Mock Clear-RecycleBin (though it doesn’t call Remove-Item, for completeness)
                Mock Clear-RecycleBin {}
            }
    
            #Test case 4: It should delete old Windows Update cache files older than 5 days, ignore files newer than 5 days
            It "Only deletes old Windows Update cache files older than 5 days" {
                Write-Host "Only deletes old Windows Update cache files older than 5 days"
                Clear-SystemCache -session $mockSession
                Should -Invoke Remove-Item -Times 2 -Exactly
                Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile.txt" }
                Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile3.txt" }
                Should -Not -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile2.txt" }
            }
        }
    
        Context "When no files older than 5 days exist" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                Mock Test-Path { return $true } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\" }

                # Mock other paths to return no files
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\*" }
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\ccmcache\*" }
                Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Windows\Temp\*" }
                
                Mock Get-ChildItem { return @() } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download" }
                Mock Remove-Item {}
                Mock Write-Host {}
            }
    
            #Test case 5: It should not delete any files if Windows Update cache files aren't found
            It "Does not delete any files if Windows Update cache files aren't found" {
                Write-Host "Does not delete any files if Windows Update cache files aren't found"
                Clear-SystemCache -session $mockSession
                Should -Not -Invoke Remove-Item
            }
        }
        
    
    Context "Windows Installer patch cache cleanup, 2 files older than 5 days exist, 1 file newer than 5 days exists" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Test-Path { return $true } -ParameterFilter {
                $Path -eq "C:\Windows\Installer\$PatchCache$\*"
            }
            $oldFiles = @(
                [PSCustomObject]@{ FullName = "C:\Windows\Installer\$PatchCache$\patch.msp"; LastWriteTime = (Get-Date).AddDays(-10) };
                [PSCustomObject]@{ FullName = "C:\Windows\Installer\$PatchCache$\patch2.msp"; LastWriteTime = (Get-Date).AddDays(-2) };
                [PSCustomObject]@{ FullName = "C:\Windows\Installer\$PatchCache$\patch3.msp"; LastWriteTime = (Get-Date).AddDays(-7) }
            )
            Mock Get-ChildItem { return $oldFiles } -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\*" }
            Mock Remove-Item {}
            Mock Write-Host {}
        }
    
        #Test case 6: It should only delete old Windows Installer patch cache files older than 5 days, ignore files newer than 5 days
        It "Deletes old Windows Installer patch cache files older than 5 days" {
            Write-Host "Deletes old Windows Installer patch cache files older than 5 days"
            Clear-SystemCache -session $mockSession
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\patch.msp" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\patch3.msp" }
            Should -Not -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\patch2.msp" }
        }
    }
    
    Context "Recycle Bin cleanup verification" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Test-Path {return $false} -ParameterFilter { $Path -eq "C:\Windows\Temp\*" }
            Mock Test-Path {return $false} -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\*" }
            Mock Test-Path {return $false} -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\" }
            Mock Write-Host {}
            Mock Clear-RecycleBin            
        }
    
        #Test case 7: It should clear Recycle Bin with force
        It "Clears Recycle Bin with force" {
            Write-Host "Clears Recycle Bin with force"
            Clear-SystemCache -session $mockSession
            Should -Invoke Clear-RecycleBin -Times 1 -Exactly
        }
    }
}

Describe "Test Compress-IISLogs" {
    BeforeAll {
        # Create a mock PSSession for all tests
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }

    Context "When IIS log path exists and there are old logs (old and new)" {
        BeforeAll {
            # Define test paths and mock data
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            $oldLogs = @(
                [PSCustomObject]@{ FullName = "$IISLogPath\log1.log"; LastWriteTime = (Get-Date).AddMonths(-7) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log2.log"; LastWriteTime = (Get-Date).AddMonths(-8) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log3.log"; LastWriteTime = (Get-Date).AddMonths(-4) }
            )

            # Mock commands
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $ArchiveFileName }
            Mock Get-ChildItem { return $oldLogs } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Mock Remove-Item {Write-Host "Remove-Item called with Path: $Path"}  # Use Write-Host instead
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }

        #Test case 1: It should only compress and delete old IIS logs older than 6 months
        It "Only compresses and deletes old IIS logs older than 6 months" {
            Write-Host "Only compresses and deletes old IIS logs older than 6 months"
            # Act
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            # Assert
            Should -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log1.log" }
            Should -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log2.log" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log1.log" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log2.log" }
            Should -Invoke Compress-Archive -Times 2 -Exactly
            Should -Invoke Remove-Item -Times 2 -Exactly
            Should -Not -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log3.log" }
            Should -Not -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log3.log" }
        }
    }

    Context "When IIS log path does not exist" {
        BeforeAll {
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            Mock Test-Path { return $false } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem {} 
            Mock Compress-Archive {} 
            Mock Remove-Item {} 
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }
    
        #Test case 2: It should not compress or delete when IIS log path does not exist
        It "Does not compress or delete" {
            Write-Host "Does not compress or delete"
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            #Assert
            Should -Not -Invoke Get-ChildItem -ParameterFilter { $Path -eq $IISLogPath }
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
        }
    }
}

$env:UNIT_TEST = $null