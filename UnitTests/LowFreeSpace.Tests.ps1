<#
Test Clear-SystemCache function
Test case 1: It should invoke the cleanup script on remote session
Test case 2: It should contain all required cleanup tasks (Windows Update cache, Windows Installer patch cache, SCCM cache, Windows Temp files)
Test case 3: It should throw an error for null session
Test case 4: It should delete old Windows Update cache files older than 5 days
Test case 5: It should not delete Windows Update cache files newer than 5 days
Test case 6: It should delete old Windows Installer patch cache files older than 5 days
Test case 7: It should delete old Windows Temp files older than 5 days
Test case 8: It should clear Recycle Bin

Test Compress-IISLogs funcion
Test case 1: It should compress and delete old IIS logs older than 6 months and does not delete recent logs
Test case 2: It should delete the original IIS logs after compression
Test case 3: It should not attempt to compress or delete when IIS log path does not exist
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

Describe "Test Clear-SystemCache" {
    BeforeAll {
        # Create a proper mock PSSession
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
               
        # Mock Invoke-Command
        Mock Invoke-Command {
            return "Command executed successfully"
        }
    }

    Context "When cleaning system cache" {
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

    Context "Windows Update cache cleanup scenarios" {   
        Context "When files are older than 5 days" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                #Mock Test-Path { return $true }
                Mock Test-Path { return $true } -ParameterFilter {
                    $Path -eq "C:\Windows\SoftwareDistribution\Download\"
                }
                Mock Get-ChildItem {
                    [PSCustomObject]@{ 
                        FullName      = "C:\Windows\SoftwareDistribution\Download\oldfile.txt"
                        LastWriteTime = (Get-Date).AddDays(-6)
                    }
                }
                Mock Remove-Item {}                
                Mock Write-Host {}
            }
    
            #Test case 4: It should delete old Windows Update cache files older than 5 days
            It "Deletes old Windows Update cache files older than 5 days" {
                Clear-SystemCache -session $mockSession
                Should -Invoke Remove-Item -Times 1 
            }
        }
    
        Context "When no files older than 5 days exist" {
            BeforeAll {
                Mock Invoke-Command { & $ScriptBlock }
                Mock Test-Path { return $true } -ParameterFilter {
                    $Path -eq "C:\Windows\SoftwareDistribution\Download\"
                }
                Mock Get-ChildItem {
                    [PSCustomObject]@{ 
                        FullName      = "C:\Windows\SoftwareDistribution\Download\newfile.txt"
                        LastWriteTime = (Get-Date).AddDays(-3)
                    }
                }
                Mock Remove-Item {}
                Mock Write-Host {}
            }
    
            #Test case 5: It should not delete Windows Update cache files newer than 5 days
            It "Does not delete Windows Update cache files newer than 5 days" {
                Clear-SystemCache -session $mockSession
                Should -Not -Invoke Remove-Item
            }
        }
        
    }
    
    Context "Windows Installer patch cache cleanup" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Test-Path { return $true } -ParameterFilter {
                $Path -eq "C:\Windows\Installer\$PatchCache$\*"
            }
            Mock Get-ChildItem {
                [PSCustomObject]@{ 
                    FullName      = "C:\Windows\Installer\$PatchCache$\patch.msp"
                    LastWriteTime = (Get-Date).AddDays(-10)
                }
            }
            Mock Remove-Item {}
            Mock Write-Host {}
        }
    
        #Test case 6: It should delete old Windows Installer patch cache files older than 5 days
        It "Deletes old Windows Installer patch cache files older than 5 days" {
            Clear-SystemCache -session $mockSession
            Should -Invoke Remove-Item -Times 1 -ParameterFilter { $Path -eq "C:\Windows\Installer\$PatchCache$\patch.msp" }
        }
    }
   
    Context "Windows Temp files cleanup" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Test-Path { return $true }
                Mock Get-ChildItem {
                    [PSCustomObject]@{ 
                        FullName      = "C:\Windows\Temp\newfile.tmp"; LastWriteTime = (Get-Date).AddDays(-2)                   }
                }
            Mock Write-Host {}
            Mock Remove-Item {}
        }   
        #Test case 7: It should not delete old Windows Temp files newer than 5 days
        It "Does not delete Windows Temp files newer than 5 days" {
            Clear-SystemCache -session $mockSession
            Should -Not -Invoke Remove-Item
        }
    }
    Context "When files older than 5 days" {
        BeforeAll {
            $oldFiles = @(
                [PSCustomObject]@{ FullName = "C:\Windows\Temp\oldfile.tmp"; LastWriteTime = (Get-Date).AddDays(-6) };
                [PSCustomObject]@{ FullName = "C:\Windows\Temp\oldfile2.tmp"; LastWriteTime = (Get-Date).AddDays(-2) }
            )
            
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq "C:\Windows\Temp\*" }
            Mock Get-ChildItem {return $oldFiles} -ParameterFilter { $Path -eq "C:\Windows\Temp\*"}
            Mock Write-Host {}
            Mock Remove-Item {}
            Mock Invoke-Command { & $ScriptBlock }
            }
        #Test case 8: It should delete old Windows Temp files older than 5 days
        It "Only deletes old Windows Temp files older than 5 days" {
            Clear-SystemCache -session $mockSession
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "C:\Windows\Temp\oldfile.tmp" }
        }
    }
    
    Context "Recycle Bin cleanup verification" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Clear-RecycleBin {}
            Mock Write-Host {}
        }
    
        #Test case 10: It should clear Recycle Bin with force
        It "Clears Recycle Bin with force" {
            Clear-SystemCache -session $mockSession
            Should -Invoke Clear-RecycleBin -Times 1
        }
    }
}

Describe "Test Compress-IISLogs" {
    BeforeAll {
        # Create a mock PSSession for all tests
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }

    Context "When IIS log path exists and there are old logs" {
        BeforeAll {
            # Define test paths and mock data
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            $oldLogs = @(
                [PSCustomObject]@{ FullName = "$IISLogPath\log1.log"; LastWriteTime = (Get-Date).AddMonths(-7) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log2.log"; LastWriteTime = (Get-Date).AddMonths(-8) }
            )

            # Mock commands
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem { return $oldLogs } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Mock Remove-Item {}
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }

        #Test case 1: It should compress and delete old IIS logs older than 6 months
        It "Compresses and deletes old IIS logs older than 6 months" {
            # Act
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            # Assert
            Should -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log1.log" }
            Should -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log2.log" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log1.log" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log2.log" }
        }
    }

    Context "When old logs do not older than 6 months" {
        BeforeAll {
            # Define test paths and mock data
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            $oldLogs = @(
                [PSCustomObject]@{ FullName = "$IISLogPath\log3.log"; LastWriteTime = (Get-Date).AddMonths(-5) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log4.log"; LastWriteTime = (Get-Date).AddMonths(-4) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log5.log"; LastWriteTime = (Get-Date).AddMonths(-3) }
            )

            # Mock commands
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Mock Remove-Item {}
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }

        #Test cae 2: It should not compress or delete old IIS logs newer than 6 months
        It "Does not compress or delete recent IIS logs" {
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath
            
            #Assert
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
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
    
        #Test case 3: It should not compress or delete when IIS log path does not exist
        It "Does not compress or delete" {
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            #Assert
            Should -Not -Invoke Get-ChildItem
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
        }
    }
}

$env:UNIT_TEST = $null