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
. "$PSScriptRoot/../../Scripts/WindowsPerformance/WindowsPerformance.ps1"

Describe "Test Get-SystemUptime" {
    BeforeAll {
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
        $ServerName = "TestServer"

        $sampleData = @{
            ServerName = $ServerName
            Days = 5
            Hours = 12
            Minutes = 30
        }
    }

    It "Throws error if session is null" {
        { Get-SystemUptime -ServerName $serverName -Session $null } | Should -Throw
    }

    It "Throws error if server name is null" {
        { Get-SystemUptime -ServerName $null -Session $mockSession } | Should -Throw
    }

    It "Returns uptime in correct format" {
        Mock Invoke-Command {
            return $sampleData
        }

        $result = Get-SystemUptime -ServerName $ServerName -Session $mockSession

        $result.ServerName | Should -Be $ServerName
        $result.Days | Should -Be 5
        $result.Hours | Should -Be 12
        $result.Minutes | Should -Be 30
    }
}

Describe "Test Get-PerformanceMetrics" {
    BeforeAll {

        # Mock external functions that are not core to the logic
        Mock Update-StatusLabel { }
        Mock Write-Log { }
        Mock Start-Sleep { }

        # Mock PSSession (create a dummy session object)
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }

    # Throw error if session is null
    It "Throws error if session is null" {
        { Get-PerformanceMetrics -Session $null } | Should -Throw
    }

    Context "Default parameters" {
        BeforeAll {
            # Mock Invoke-Command for static info
            Mock Invoke-Command {
                return @{
                    TotalMemory = 8589934592  # 8 GB
                }
            } -ParameterFilter { $Session -eq $mockSession -and $scriptBlock.ToString() -eq $staticScriptBlock.ToString() }

            # Mock Invoke-Command for samples (called twice by default)
            $script:sampleCalls = 0
            $mockOwnerCache = @{}
            Mock Invoke-Command {
                $script:sampleCalls++
                # Simulate sample data
                $cpuSample = @(50.0, 60.0)[$script:sampleCalls - 1]  # 50, 60
                $memorySample = @(40.0, 50.0)[$script:sampleCalls - 1]  # 40, 50
                $processData = @(
                    [PSCustomObject]@{ PID = 100; ProcessName = 'proc1'; CPU = 10.0; MemoryBytes = 1000000; User = 'User1' },
                    [PSCustomObject]@{ PID = 101; ProcessName = 'proc1'; CPU = 15.0; MemoryBytes = 1500000; User = 'User1' },
                    [PSCustomObject]@{ PID = 200; ProcessName = 'proc2'; CPU = 20.0; MemoryBytes = 2000000; User = 'User2' }
                )
                # Update mock cache
                foreach ($proc in $processData) {
                    $mockOwnerCache[$proc.PID] = $proc.User
                }
                return @{
                    CpuSample = $cpuSample
                    MemorySample = $memorySample
                    ProcessData = $processData
                    OwnerCache = $mockOwnerCache
                }
            } -ParameterFilter { $Session -eq $mockSession -and $scriptBlock.ToString() -eq $sampleScriptBlock.ToString() }
        }
        It "Collects metrics with default Samples=2 and Interval=2" {
            $result = Get-PerformanceMetrics -Session $mockSession -Samples 2 -Interval 2

            # Assert system metrics
            $result.SystemMetrics.AvgCPU | Should -Be 55.0  # Average of 50 and 60
            $result.SystemMetrics.AvgMemoryPercent | Should -Be 45.0  # Average of 40 and 50
            $result.SystemMetrics.AvgMemoryBytes | Should -Be 3865470566  # 45% of 8GB (approx)
            $result.SystemMetrics.TotalMemoryBytes | Should -Be 8589934592

            # Assert process metrics (grouped and summed)
            $result.ProcessMetrics.Count | Should -Be 2
            $proc1 = $result.ProcessMetrics | Where-Object { $_.ProcessName -eq 'proc1' }
            $proc1.AvgCPU | Should -Be 25.0  # (10+15)/1 per sample, but since same in both samples, avg per proc then sum
            $proc1.AvgMemoryBytes | Should -Be 2500000  # (1000000 + 1500000) avg over samples
            $proc1.User | Should -Be 'User1'
            $proc1.PID | Should -Be '100'  # Min PID

            $proc2 = $result.ProcessMetrics | Where-Object { $_.ProcessName -eq 'proc2' }
            $proc2.AvgCPU | Should -Be 20.0
            $proc2.AvgMemoryBytes | Should -Be 2000000
            $proc2.User | Should -Be 'User2'

            # Assert mocks called correctly
            Assert-MockCalled Invoke-Command -Times 1 -ParameterFilter { $null -eq $ArgumentList }
            Assert-MockCalled Invoke-Command -Times 2 -ParameterFilter { $null -ne $ArgumentList }
            Assert-MockCalled Update-StatusLabel -Times 2
        }
    }

    Context "Custom Samples and Interval" {
        BeforeAll {
            # Mock Invoke-Command for static info
            Mock Invoke-Command {
                return @{
                    TotalMemory = 4294967296  # 4 GB
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -eq $ArgumentList }

            $script:sampleCalls = 0
            $mockOwnerCache = @{}
            Mock Invoke-Command {
                $script:sampleCalls++
                $cpuSample = 30.0 + ($script:sampleCalls * 10)  # 40, 50, 60
                $memorySample = 20.0 + ($script:sampleCalls * 10)  # 30, 40, 50
                $processData = @(
                    [PSCustomObject]@{ PID = 300; ProcessName = 'proc3'; CPU = 5.0; MemoryBytes = 500000; User = 'User3' }
                )
                foreach ($proc in $processData) {
                    $mockOwnerCache[$proc.PID] = $proc.User
                }
                return @{
                    CpuSample = $cpuSample
                    MemorySample = $memorySample
                    ProcessData = $processData
                    OwnerCache = $mockOwnerCache
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -ne $ArgumentList }
        }

        It "Collects metrics with Samples=3 and Interval=1" {
            $result = Get-PerformanceMetrics -Session $mockSession -Samples 3 -Interval 1

            $result.SystemMetrics.AvgCPU | Should -Be 50.0  # Avg of 40,50,60
            $result.SystemMetrics.AvgMemoryPercent | Should -Be 40.0  # Avg of 30,40,50
            $result.SystemMetrics.AvgMemoryBytes | Should -Be 1717986918  # 40% of 4GB (approx)
            $result.SystemMetrics.TotalMemoryBytes | Should -Be 4294967296

            $result.ProcessMetrics.Count | Should -Be 1
            $proc3 = $result.ProcessMetrics[0]
            $proc3.ProcessName | Should -Be 'proc3'
            $proc3.AvgCPU | Should -Be 5.0
            $proc3.AvgMemoryBytes | Should -Be 500000
            $proc3.User | Should -Be 'User3'
            $proc3.PID | Should -Be '300'

            Assert-MockCalled Invoke-Command -Times 1 -ParameterFilter { $null -eq $ArgumentList }
            Assert-MockCalled Invoke-Command -Times 3 -ParameterFilter { $null -ne $ArgumentList }
            Assert-MockCalled Update-StatusLabel -Times 3
        }
    }

    Context "Single Sample" {
        BeforeAll {
            Mock Invoke-Command {
                return @{
                    TotalMemory = 8589934592
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -eq $ArgumentList }

            $mockOwnerCache = @{}
            Mock Invoke-Command {
                return @{
                    CpuSample = 75.0
                    MemorySample = 60.0
                    ProcessData = @(
                        [PSCustomObject]@{ PID = 400; ProcessName = 'proc4'; CPU = 30.0; MemoryBytes = 3000000; User = 'User4' },
                        [PSCustomObject]@{ PID = 401; ProcessName = 'proc4'; CPU = 40.0; MemoryBytes = 4000000; User = 'User4' }
                    )
                    OwnerCache = $mockOwnerCache
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -ne $ArgumentList }
        }

        It "Handles single sample correctly" {
            $result = Get-PerformanceMetrics -Session $mockSession -Samples 1

            $result.SystemMetrics.AvgCPU | Should -Be 75.0
            $result.SystemMetrics.AvgMemoryPercent | Should -Be 60.0
            $result.SystemMetrics.AvgMemoryBytes | Should -Be 5153960755  # 60% of 8GB (approx)

            $result.ProcessMetrics.Count | Should -Be 1
            $proc4 = $result.ProcessMetrics[0]
            $proc4.AvgCPU | Should -Be 70.0  # 30 + 40
            $proc4.AvgMemoryBytes | Should -Be 7000000  # 3000000 + 4000000
            $proc4.PID | Should -Be '400'  # Min PID

            Assert-MockCalled Invoke-Command -Times 1 -ParameterFilter { $null -eq $ArgumentList }
            Assert-MockCalled Invoke-Command -Times 1 -ParameterFilter { $null -ne $ArgumentList }
            Assert-MockCalled Update-StatusLabel -Times 1
        }
    }

    Context "Process Grouping and PID Display" {
        BeforeAll {
            Mock Invoke-Command {
                return @{
                    TotalMemory = 8589934592
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -eq $ArgumentList }

            $mockOwnerCache = @{}
            Mock Invoke-Command {
                return @{
                    CpuSample = 50.0
                    MemorySample = 40.0
                    ProcessData = @(
                        [PSCustomObject]@{ PID = 500; ProcessName = 'proc5'; CPU = 10.0; MemoryBytes = 1000000; User = 'User5' },
                        [PSCustomObject]@{ PID = 600; ProcessName = 'proc5'; CPU = 20.0; MemoryBytes = 2000000; User = 'User5' },
                        [PSCustomObject]@{ PID = 501; ProcessName = 'proc5'; CPU = 15.0; MemoryBytes = 1500000; User = 'User6' }  # Different user
                    )
                    OwnerCache = $mockOwnerCache
                }
            } -ParameterFilter { $Session -eq $mockSession -and $null -ne $ArgumentList }
        }

        It "Groups processes by ProcessName and User, sums correctly, and picks min PID" {
            $result = Get-PerformanceMetrics -Session $mockSession -Samples 1

            $result.ProcessMetrics.Count | Should -Be 2

            $group1 = $result.ProcessMetrics | Where-Object { $_.User -eq 'User5' }
            $group1.AvgCPU | Should -Be 30.0  # 10 + 20
            $group1.AvgMemoryBytes | Should -Be 3000000
            $group1.PID | Should -Be '500'  # Min of 500 and 600

            $group2 = $result.ProcessMetrics | Where-Object { $_.User -eq 'User6' }
            $group2.AvgCPU | Should -Be 15.0
            $group2.AvgMemoryBytes | Should -Be 1500000
            $group2.PID | Should -Be '501'
        }
    }
}

Describe "Test Get-TopCPUProcesses" {
    BeforeEach{
        $sampleData = @{
            SystemMetrics = @{
                AvgCPU = 55.0
                AvgMemoryPercent = 45.0
                AvgMemoryBytes = 3865470566
                TotalMemoryBytes = 8589934592
            }
            ProcessMetrics = @(
                [PSCustomObject]@{ ProcessName = 'proc1'; User = 'User1'; AvgCPU = 25.0; AvgMemoryBytes = 2500000; PID = '100' },
                [PSCustomObject]@{ ProcessName = 'proc2'; User = 'User2'; AvgCPU = 12.0; AvgMemoryBytes = 2000000; PID = '200' },
                [PSCustomObject]@{ ProcessName = 'proc3'; User = 'User3'; AvgCPU = 15.0; AvgMemoryBytes = 1500000; PID = '300' },
                [PSCustomObject]@{ ProcessName = 'proc4'; User = 'User4'; AvgCPU = 50.0; AvgMemoryBytes = 1000000; PID = '400' },
                [PSCustomObject]@{ ProcessName = 'proc5'; User = 'User5'; AvgCPU = 5.0; AvgMemoryBytes = 500000; PID = '500' },
                [PSCustomObject]@{ ProcessName = 'proc6'; User = 'User6'; AvgCPU = 8.0; AvgMemoryBytes = 800000; PID = '600' }
            )
        }
    }

    It "Should throw error if PerformanceData is null" {
        { Get-TopCPUProcesses -PerformanceData $null } | Should -Throw 
    }

    It "Returns top CPU processes with TopCount 2" {
        $result = Get-TopCPUProcesses -PerformanceData $sampleData -TopCount 2

        $result.Count | Should -Be 2
        $result[0].ProcessName | Should -Be 'proc4'
        $result[0].AvgCPU | Should -Be 50.0
        $result[0].User | Should -Be 'User4'
        $result[0].PID | Should -Be '400'
        $result[1].ProcessName | Should -Be 'proc1'
        $result[1].AvgCPU | Should -Be 25.0
        $result[1].User | Should -Be 'User1'
        $result[1].PID | Should -Be '100'
    }

    It "Returns top CPU processes with TopCount 5" {
        $result = Get-TopCPUProcesses -PerformanceData $sampleData -TopCount 5

        $result.Count | Should -Be 5
        $result[0].ProcessName | Should -Be 'proc4'
        $result[1].ProcessName | Should -Be 'proc1'
        $result[2].ProcessName | Should -Be 'proc3'
        $result[3].ProcessName | Should -Be 'proc2'
        $result[4].ProcessName | Should -Be 'proc6'
    }

}

Describe "Test Get-TopMemoryProcesses" {
    BeforeEach{
        $sampleData = @{
            SystemMetrics = @{
                AvgCPU = 55.0
                AvgMemoryPercent = 45.0
                AvgMemoryBytes = 3865470566
                TotalMemoryBytes = 8589934592
            }
            ProcessMetrics = @(
                [PSCustomObject]@{ ProcessName = 'proc1'; User = 'User1'; AvgCPU = 25.0; AvgMemoryBytes = 2500000; PID = '100' },
                [PSCustomObject]@{ ProcessName = 'proc2'; User = 'User2'; AvgCPU = 12.0; AvgMemoryBytes = 2000000; PID = '200' },
                [PSCustomObject]@{ ProcessName = 'proc3'; User = 'User3'; AvgCPU = 15.0; AvgMemoryBytes = 1500000; PID = '300' },
                [PSCustomObject]@{ ProcessName = 'proc4'; User = 'User4'; AvgCPU = 50.0; AvgMemoryBytes = 1000000; PID = '400' },
                [PSCustomObject]@{ ProcessName = 'proc5'; User = 'User5'; AvgCPU = 5.0; AvgMemoryBytes = 500000; PID = '500' },
                [PSCustomObject]@{ ProcessName = 'proc6'; User = 'User6'; AvgCPU = 8.0; AvgMemoryBytes = 800000; PID = '600' }
            )
        }
    }

    It "Should throw error if PerformanceData is null" {
        { Get-TopMemoryProcesses -PerformanceData $null } | Should -Throw 
    }

    It "Returns top memory processes with TopCount 2" {
        $result = Get-TopMemoryProcesses -PerformanceData $sampleData -TopCount 2

        $result.Count | Should -Be 2
        $result[0].ProcessName | Should -Be 'proc1'
        $result[0].AvgMemoryBytes | Should -Be 2500000
        $result[0].User | Should -Be 'User1'
        $result[0].PID | Should -Be '100'
        $result[1].ProcessName | Should -Be 'proc2'
        $result[1].AvgMemoryBytes | Should -Be 2000000
        $result[1].User | Should -Be 'User2'
        $result[1].PID | Should -Be '200'
    }

    It "Returns top memory processes with TopCount 5" {
        $result = Get-TopMemoryProcesses -PerformanceData $sampleData -TopCount 5

        $result.Count | Should -Be 5
        $result[0].ProcessName | Should -Be 'proc1'
        $result[1].ProcessName | Should -Be 'proc2'
        $result[2].ProcessName | Should -Be 'proc3'
        $result[3].ProcessName | Should -Be 'proc4'
        $result[4].ProcessName | Should -Be 'proc6'
    }
}


Describe "Write-WindowsEventLog" {
    BeforeAll {
        Mock Write-Log { }
    }

    BeforeEach {
        $testLogName = "Application"
        $testSource = "TestSource"
        $testEventID = 100
        $testEntryType = "Information"
        $testMessage = "Test message"
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
        $fixedTime = Get-Date "23-Aug-25 9:49:03 PM"

        $params = @{
            LogName = $testLogName
            Source = $testSource
            EventID = $testEventID
            EntryType = $testEntryType
            Message = $testMessage
            Session = $mockSession
        }
    }

    It "Throws when LogName is not provided" {
        { Write-WindowsEventLog -LogName $null -Source $testSource -EventID $testEventID -EntryType $testEntryType -Message $testMessage -Session $mockSession } | Should -Throw
    }

    It "Throws when Source is not provided" {
        { Write-WindowsEventLog -Source $null -LogName $testLogName -EventID $testEventID -EntryType $testEntryType -Message $testMessage -Session $mockSession } | Should -Throw
    }

    It "Throws when EventID is not provided" {
        { Write-WindowsEventLog -EventID $null -LogName $testLogName -Source $testSource -EntryType $testEntryType -Message $testMessage -Session $mockSession } | Should -Throw
    }

    It "Throws when EntryType is not provided" {
        { Write-WindowsEventLog -EntryType $null -LogName $testLogName -Source $testSource -EventID $testEventID -Message $testMessage -Session $mockSession } | Should -Throw
    }

    It "Throws when Message is not provided" {
        { Write-WindowsEventLog -Message $null -LogName $testLogName -Source $testSource -EventID $testEventID -EntryType $testEntryType -Session $mockSession } | Should -Throw
    }

    It "Throws when Session is not provided" {
        { Write-WindowsEventLog -Session $null -LogName $testLogName -Source $testSource -EventID $testEventID -EntryType $testEntryType -Message $testMessage } | Should -Throw
    }

    It "Succeeds when source exists, write and verify work" {
        $mockEventCalls = 0
        Mock Get-Date { $fixedTime }
        Mock Get-EventLog {
            $mockEventCalls++
            if ($mockEventCalls -eq 1) {
                # Existence check: source exists
                return @([pscustomobject]@{})
            } elseif ($mockEventCalls -eq 2) {
                # Verification: return matching event
                return @([pscustomobject]@{
                    TimeGenerated = $fixedTime.AddMilliseconds(600)
                    EventID = $testEventID
                    EntryType = $testEntryType
                })
            }
        }
        Mock Write-EventLog { }
        Mock New-EventLog { }
        Mock Start-Sleep { }
        Mock Invoke-Command {
            param ($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList

            return @{ Success = $true; Error = $null }
        }
        

        Write-WindowsEventLog @params

        Assert-MockCalled Invoke-Command -Times 1 -Exactly
        Assert-MockCalled Get-EventLog -Times 2 -Exactly
        Assert-MockCalled New-EventLog -Times 0
        Assert-MockCalled Write-EventLog -Times 1 -Exactly
        Assert-MockCalled Write-Log -Times 0
    }

    It "Succeeds when source does not exist, creates successfully, write and verify work" {
        $mockEventCalls = 0
        Mock Get-Date { $fixedTime }
        Mock Get-EventLog {
            $mockEventCalls++
            if ($mockEventCalls -eq 1) {
                # Existence check: source does not exist
                return @()
            } elseif ($mockEventCalls -eq 2) {
                # Verification: return matching event
                return @([pscustomobject]@{
                    TimeGenerated = $fixedTime.AddMilliseconds(600)
                    EventID = 100
                    EntryType = "Information"
                })
            }
        }
        Mock Write-EventLog { }
        Mock New-EventLog { }
        Mock Start-Sleep { }
        Mock Invoke-Command {
            param ($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList

            return @{ Success = $true; Error = $null }
        }
        Mock Write-Log { }

        Write-WindowsEventLog @params

        Assert-MockCalled Invoke-Command -Times 1 -Exactly
        Assert-MockCalled Get-EventLog -Times 2 -Exactly
        Assert-MockCalled New-EventLog -Times 1 -Exactly
        Assert-MockCalled Write-EventLog -Times 1 -Exactly
        Assert-MockCalled Start-Sleep -Times 1 -Exactly -ParameterFilter { $Milliseconds -eq 500 }
        Assert-MockCalled Write-Log -Times 0
    }

    It "Fails and logs error when creating source fails" {
        $mockEventCalls = 0
        Mock Get-Date { $fixedTime }
        Mock Get-EventLog {
            $mockEventCalls++
            if ($mockEventCalls -eq 1) {
                return @()
            }
        }
        Mock Write-EventLog { }
        Mock New-EventLog { throw }
        Mock Start-Sleep { }
        Mock Invoke-Command {
            param ($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList
        }
        Mock Write-Log { }

        Write-WindowsEventLog @params

        Assert-MockCalled Invoke-Command -Times 1 -Exactly
        Assert-MockCalled Get-EventLog -Times 1 -Exactly
        Assert-MockCalled New-EventLog -Times 1 -Exactly
        Assert-MockCalled Write-EventLog -Times 0
        Assert-MockCalled Start-Sleep -Times 0
        Assert-MockCalled Write-Log -Times 1 -Exactly -ParameterFilter { $Message -like "*Failed to create event source*" -and $Level -eq "Error" }
    }

    It "Fails and logs error when writing event fails" {
        $mockEventCalls = 0
        Mock Get-Date { $fixedTime }
        Mock Get-EventLog {
            $mockEventCalls++
            if ($mockEventCalls -eq 1) {
                return @([pscustomobject]@{})
            }
        }
        Mock Write-EventLog { throw }
        Mock New-EventLog { }
        Mock Start-Sleep { }
        Mock Invoke-Command {
            param ($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList
        }
        Mock Write-Log { }

        Write-WindowsEventLog @params

        Assert-MockCalled Invoke-Command -Times 1 -Exactly
        Assert-MockCalled Get-EventLog -Times 1 -Exactly
        Assert-MockCalled New-EventLog -Times 0
        Assert-MockCalled Write-EventLog -Times 1 -Exactly
        Assert-MockCalled Start-Sleep -Times 0
        Assert-MockCalled Write-Log -Times 1 -Exactly -ParameterFilter { $Message -like "*Failed to write/verify event*" -and $Level -eq "Error" }
    }

    It "Fails and logs error when verification fails" {
        $mockEventCalls = 0
        Mock Get-Date { $fixedTime }
        Mock Get-EventLog {
            $mockEventCalls++
            if ($mockEventCalls -eq 1) {
                return @([pscustomobject]@{})
            } elseif ($mockEventCalls -eq 2) {
                # Verification: return non-matching event
                return @([pscustomobject]@{
                    TimeGenerated = $fixedTime.AddMilliseconds(600)
                    EventID = 999
                    EntryType = "Information"
                })
            }
        }
        Mock Write-EventLog { }
        Mock New-EventLog { }
        Mock Start-Sleep { }
        Mock Invoke-Command {
            param ($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList
        }
        Mock Write-Log { }

        Write-WindowsEventLog @params

        Assert-MockCalled Invoke-Command -Times 1 -Exactly
        Assert-MockCalled Get-EventLog -Times 2 -Exactly
        Assert-MockCalled New-EventLog -Times 0
        Assert-MockCalled Write-EventLog -Times 1 -Exactly
        Assert-MockCalled Start-Sleep -Times 1 -Exactly -ParameterFilter { $Milliseconds -eq 500 }
        Assert-MockCalled Write-Log -Times 1 -Exactly -ParameterFilter { $Message -like "*Event log entry not found after writing*" -and $Level -eq "Error" }
    }
}

Describe "Show-PerformanceDashboard Function Tests" {

    BeforeAll {
        # Mock external commands and functions
        Mock Test-Path { $false } -ParameterFilter { $Path -eq "C:\temp" }
        Mock New-Item { } -ParameterFilter { $ItemType -eq "Directory" -and $Path -eq "C:\temp" }
        Mock Write-Log { }
        Mock Out-Host { }
        Mock Out-File { }
        Mock Join-Path { "C:\temp\PerformanceDashboard_TestServer_17092025_120000.txt" }
        Mock Get-Date {
            if ($Format -eq "hh:mm tt on MMMM dd, yyyy") {
                return "12:00 PM on September 17, 2025"
            } elseif ($Format -eq "ddMMyyyy_HHmmss") {
                return "17092025_120000"
            }
        }

        # Sample input data
        $uptime = [PSCustomObject]@{
            ServerName = "TestServer"
            Days = 5
            Hours = 3
            Minutes = 45
        }

        $topCPU = @(
            [PSCustomObject]@{ ProcessName = "Process1"; PID = 1234; AvgCPU = 25.5; AvgMemoryBytes = 1073741824; User = "User1" },
            [PSCustomObject]@{ ProcessName = "Process2"; PID = 5678; AvgCPU = 15.0; AvgMemoryBytes = 536870912; User = "User2" }
        )

        $topMemory = @(
            [PSCustomObject]@{ ProcessName = "Process3"; PID = 91011; AvgCPU = 5.0; AvgMemoryBytes = 2147483648; User = "User3" },
            [PSCustomObject]@{ ProcessName = "Process4"; PID = 121314; AvgCPU = 10.0; AvgMemoryBytes = 1610612736; User = "User4" }
        )

        $systemMetrics = [PSCustomObject]@{
            AvgCPU = 30
            AvgMemoryPercent = 40
            AvgMemoryBytes = 4294967296  # 4GB
            TotalMemoryBytes = 10737418240  # 10GB
        }
    }

    It "Creates temp directory if it does not exist" {
        $null = Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $systemMetrics
        Assert-MockCalled Test-Path -Times 1 -Exactly -Scope It
        Assert-MockCalled New-Item -Times 1 -Exactly -Scope It
    }

    It "Exports output to file successully" {
        $filePath = Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $systemMetrics
        $filePath | Should -Be "C:\temp\PerformanceDashboard_TestServer_17092025_120000.txt"
        Assert-MockCalled Out-File -Times 1 -Exactly -Scope It
    }

    Context "Parameter Validation" {
        It "Requires Uptime parameter" {
            { Show-PerformanceDashboard -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $systemMetrics -Uptime $null } | Should -Throw
        }

        It "Requires TopCPU parameter" {
            { Show-PerformanceDashboard -Uptime $uptime -TopMemory $topMemory -SystemMetrics $systemMetrics -TopCPU $null} | Should -Throw
        }

        It "Requires TopMemory parameter" {
            { Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -SystemMetrics $systemMetrics -TopMemory $null} | Should -Throw
        }

        It "Requires SystemMetrics parameter" {
            { Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $null} | Should -Throw
        }
    }

    Context "Output Formatting" {
        BeforeAll {
            # To test exact output, we can redirect Out-Host or capture output.
            # For simplicity, mock Out-Host to collect lines.
            $script:outputLines = @()
            Mock Out-Host {
                param (
                    [Parameter(ValueFromPipeline = $true)]
                    $InputObject
                )
                $script:outputLines += $InputObject
            }
        }

        It "Produces correctly formatted output" {
            $null = Show-PerformanceDashboard -Uptime $uptime -TopCPU $topCPU -TopMemory $topMemory -SystemMetrics $systemMetrics

            $script:outputLines[0] | Should -Be ("=" * 60)
            $script:outputLines[1] | Should -Be "SERVER: TestServer | UPTIME: 5 DAYS 3 HOURS 45 MINUTES"
            $script:outputLines[2] | Should -Be "Data Collected at 12:00 PM on September 17, 2025"
            $script:outputLines[3] | Should -Be ("=" * 60)
            $script:outputLines[4] | Should -Be "OVERVIEW:"
            $script:outputLines[5] | Should -Be "[CPU]: 30%`t[MEM]: 4GB (40%)"
            # Add more assertions for top processes, etc.
            # For example:
            $script:outputLines[9] | Should -Match "1. Process1\s+\(1234\)\s+-\s+25.50%\s+-\s+1.0GB \(10.0%\)\s+-\s+User1"
            
            $script:outputLines[14] | Should -Match "1. Process3\s+\(91011\)\s+-\s+5.00%\s+-\s+2.0GB \(20.0%\)\s+-\s+User3"
        }
    }
}

$env:UNIT_TEST = $null