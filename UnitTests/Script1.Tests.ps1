# Load the script to be tested
. "$PSScriptRoot/../Scripts/Script1.ps1"

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
}

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
        It "Invokes the cleanup script block on remote session" {
            # Act
            Clear-SystemCache -session $mockSession

            # Assert
            Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                $Session -eq $mockSession
            }
        }

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
        It "Throws error for null session" {
            # Act & Assert
            { Clear-SystemCache -session $null } | 
            Should -Throw -ExpectedMessage "*Cannot bind argument to parameter 'session' because it is null.*"
        }
    }

    Context "When remote command execution fails" {
        BeforeAll {
            Mock Invoke-Command { throw "Remote execution failed" }
        }

        It "Propagates error from remote execution" {
            # Act & Assert
            { Clear-SystemCache -session $mockSession } | 
            Should -Throw "Remote execution failed"
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
    
            It "Deletes old files" {
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
    
            It "Does not delete any files" {
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
    
        It "Deletes old patch files" {
            Clear-SystemCache -session $mockSession
            Should -Invoke Remove-Item -Times 1
        }
    }
   
    Context "Windows Temp files cleanup" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Test-Path { return $false }  # Default: all paths return $false
            Mock Test-Path { return $true } -ParameterFilter {
                $Path -eq "C:\Windows\Temp\*"
            }
            Mock Get-ChildItem {
                [PSCustomObject]@{ 
                    FullName      = "C:\Windows\Temp\tempfile.tmp"
                    LastWriteTime = (Get-Date).AddDays(-7)
                },
                [PSCustomObject]@{ 
                    FullName      = "C:\Windows\Temp\recentfile.tmp"
                    LastWriteTime = (Get-Date).AddDays(-1)
                }
            }
            Mock Remove-Item {}
            Mock Write-Host {}
        }
    
        It "Only deletes files older than 5 days" {
            Clear-SystemCache -session $mockSession
            Should -Invoke Remove-Item -Times 1 -Exactly
        }
    }
    
    Context "Recycle Bin cleanup verification" {
        BeforeAll {
            Mock Invoke-Command { & $ScriptBlock }
            Mock Clear-RecycleBin {}
            Mock Write-Host {}
        }
    
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
                [PSCustomObject]@{ FullName = "$IISLogPath\log1.log"; LastWriteTime = (Get-Date).AddDays(-1) },
                [PSCustomObject]@{ FullName = "$IISLogPath\log2.log"; LastWriteTime = (Get-Date).AddDays(-2) }
            )

            # Mock commands
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem { return $oldLogs } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Mock Remove-Item {}
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }

        It "Compresses and deletes old logs" {
            # Act
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath

            # Assert
            Should -Invoke Compress-Archive -Times 2 -Exactly
            Should -Invoke Remove-Item -Times 2 -Exactly
        }

        It "Calls Compress-Archive with correct parameters" {
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            $oldLogs = @(
                [PSCustomObject]@{ FullName = "$IISLogPath\log1.log"; Name = "log1.log"; LastWriteTime = (Get-Date).AddDays(-1) }
            )
            Mock Get-ChildItem { return $oldLogs } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath
            Should -Invoke Compress-Archive -Times 1 -Exactly -ParameterFilter {
                $Path -eq "$IISLogPath\log1.log" -and $DestinationPath -eq "$ArchivePath\log1.log.zip"
            }
        }

        It "Deletes the original logs after compression" {
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log1.log" }
            Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq "$IISLogPath\log2.log" }
        }
    }

    Context "When IIS log path does not exist" {
        BeforeAll {
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            Mock Test-Path { return $false } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem {}  # Add this
            Mock Compress-Archive {}  # Add this
            Mock Remove-Item {}  # Add this
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }
    
        It "Writes message and does not attempt to compress or delete" {
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath
            Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { 
                $Object -eq "IIS log path not found: $IISLogPath" 
            }
            Should -Not -Invoke Get-ChildItem
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
        }
    }

    Context "When there are no old logs" {
        BeforeAll {
            $IISLogPath = "C:\inetpub\logs\LogFiles"
            $ArchivePath = "C:\inetpub\logs\Archive"
            Mock Test-Path { return $true } -ParameterFilter { $Path -eq $IISLogPath }
            Mock Get-ChildItem { return @() } -ParameterFilter { $Path -eq "$IISLogPath\*" }
            Mock Compress-Archive {}  # Ensure this is present
            Mock Remove-Item {}  # Ensure this is present
            Mock Write-Host {}
            Mock Invoke-Command { & $ScriptBlock $ArgumentList[0] $ArgumentList[1] }
        }
    
        It "Does not compress or delete any logs" {
            Compress-IISLogs -session $mockSession -IISLogPath $IISLogPath -ArchivePath $ArchivePath
            Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { 
                $Object -eq "Found 0 old log(s) to process" 
            }
            Should -Not -Invoke Compress-Archive
            Should -Not -Invoke Remove-Item
        }
    }

    Context "When session parameter is invalid" {
        It "Throws error for null session" {
            { Compress-IISLogs -session $null } | Should -Throw -ExpectedMessage "*Cannot bind argument to parameter 'session' because it is null.*"
        }
    }
}