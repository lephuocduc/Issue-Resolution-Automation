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
$env:UNIT_TEST = "true"
# Load the script to be tested
. "$PSScriptRoot/../Scripts/LowFreeSpace.ps1"

<#
Describe "Test Get-Session" {    
    Context "When parameters are valid" {
        BeforeAll {
            # Mock credentials for testing
            $credential = [PSCredential]::new("testuser", (ConvertTo-SecureString "testpass" -AsPlainText -Force))
            Mock Get-Credential { return $credential }  # Add this mock
            Mock Set-Item { return $true }
            Mock New-PSSession { return [PSCustomObject]@{Name = "TestSession"} }
        }

        It "Returns a session when connection succeeds on first try" {
            $result = Get-Session -serverName "TestServer" -Credential $credential
            $result.Name | Should -Be "TestSession"
        }

        It "Creates session with provided credential" {
            Get-Session -serverName "TestServer" -Credential $credential
            Assert-MockCalled New-PSSession -Times 1 -ParameterFilter { 
                $ComputerName -eq "TestServer" -and 
                $Credential -eq $credential
            }
        }
    }


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

<#
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
}#>
<#
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

Describe "Test Clear-SystemCache" {
    BeforeAll {
        # Create a proper mock PSSession
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }

        Context "When cleaning system cache" {
            BeforeAll{
                Mock Invoke-Command { & $ScriptBlock }
                Mock Write-Host {}
            }
            #Test case 1: It should invoke the cleanup script block on remote session
            It "Invokes the cleanup script block on remote session" {
                # Act
                Clear-SystemCache -session $mockSession

                # Assert
                Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                    $Session -eq $mockSession
                }
            }

            #Test case 2: It should contain all required cleanup tasks
            It "Script block contains all required cleanup tasks" {
                # Act
                Clear-SystemCache -session $mockSession

                # Assert
                Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                    $ScriptBlock.ToString() -match 'Windows Update cache' -and
                    $ScriptBlock.ToString() -match 'Windows Installer patch cache' -and
                    $ScriptBlock.ToString() -match 'SCCM cache' -and
                    $ScriptBlock.ToString() -match 'Windows Temp files'
                }
            }
        }

        Context "When session parameter is invalid" {
            #Test case 3: It should throw an error for null session
            It "Throws error for null session" {
                # Act & Assert
                { Clear-SystemCache -session $null } | 
                Should -Throw -ExpectedMessage "*Cannot bind argument to parameter 'session' because it is null.*"
            }
        }

        Context "2 files older than 5 days exist, 1 file newer than 5 days exists" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                $oldFiles = @(
                [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile.txt"; LastWriteTime = (Get-Date).AddDays(-6) };
                [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile2.txt"; LastWriteTime = (Get-Date).AddDays(-2) };
                [PSCustomObject]@{ FullName = "C:\Windows\SoftwareDistribution\Download\oldfile3.txt"; LastWriteTime = (Get-Date).AddDays(-7) }
                )
                #Mock Test-Path { return $true }
                Mock Test-Path { return $true } -ParameterFilter {
                    $Path -eq "C:\Windows\SoftwareDistribution\Download\"
                }
                Mock Get-ChildItem { return $oldFiles } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download" }
                Mock Remove-Item {}                
                Mock Write-Host {}
            }
    
            #Test case 4: It should only delete old Windows Update cache files older than 5 days
            It "Only deletes old Windows Update cache files older than 5 days" {
                Clear-SystemCache -session $mockSession
                Should -Invoke Remove-Item -Times 2 -Exactly
                Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile.txt" }
                Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile3.txt" }
                Should -Not -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\oldfile2.txt" }
                

                #Test-Path -Path "C:\Windows\SoftwareDistribution\Download\oldfile2.txt" | Should -Be $true
            }
        }
    
        Context "When no files older than 5 days exist" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                Mock Test-Path { return $true } -ParameterFilter {
                    $Path -eq "C:\Windows\SoftwareDistribution\Download\"
                }
                Mock Get-ChildItem { return @() } -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download" }
                Mock Remove-Item {}
                Mock Write-Host {}
            }
    
            #Test case 5: It should not delete any files if Windows Update cache files aren't found
            It "Does not delete any files if Windows Update cache files aren't found" {
                Clear-SystemCache -session $mockSession
                Should -Not -Invoke Remove-Item
            }
        }
        
    
    Context "Windows Installer patch cache cleanup" {
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
    
        #Test case 6: It should only delete old Windows Installer patch cache files older than 5 days
        It "Deletes old Windows Installer patch cache files older than 5 days" {
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
            Mock Test-Path {return $false} -ParameterFilter { $Path -eq "C:\Windows\SoftwareDistribution\Download\*" }
            Mock Write-Host {}
            Mock Clear-RecycleBin            
        }
    
        #Test case 7: It should clear Recycle Bin with force
        It "Clears Recycle Bin with force" {
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
            Mock Get-ChildItem { return $oldLogs } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Mock Remove-Item {}
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }

        #Test case 1: It should only compress and delete old IIS logs older than 6 months
        It "Only compresses and deletes old IIS logs older than 6 months" {
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
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            #Assert
            Should -Not -Invoke Get-ChildItem -ParameterFilter { $Path -eq $IISLogPath }
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
        }
    }
}

$env:UNIT_TEST = $null