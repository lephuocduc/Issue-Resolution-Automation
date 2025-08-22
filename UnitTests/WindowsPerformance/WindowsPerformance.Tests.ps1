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
        { Get-SystemUptime -ServerName $null -Session $null } | Should -Throw
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

    Context "Error Handling" {
        BeforeAll {
            Mock Invoke-Command { throw "Mocked error" } -ParameterFilter { $Session -eq $mockSession }
        }

        It "Throws error and logs on failure" {
            { Get-PerformanceMetrics -Session $mockSession } | Should -Throw "Mocked error"
            Assert-MockCalled Update-StatusLabel -Times 1 -ParameterFilter { $text -like "*Error collecting performance metrics*" }
            Assert-MockCalled Write-Log -Times 1 -ParameterFilter { $Message -like "*Error collecting performance metrics*" -and $Level -eq "Error" }
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

<#
Describe "Write-WindowsEventLog Tests" {
    BeforeAll {
        # Create a mock session object
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession

        # Mock Write-Log to suppress real calls
        Mock Write-Log {}

        # Mock Start-Sleep to avoid delays
        Mock Start-Sleep {}

        # Mock Test-EventLogSourceExists to simulate source not existing
        Mock Test-EventLogSourceExists { return $false }

        # Mock New-EventLog so no real event log is created
        Mock New-EventLog {}

        # Mock Write-EventLog to simulate writing event
        Mock Write-EventLog {}

        # Mock Get-EventLog to return event matching the criteria
        Mock Get-EventLog {
            return [PSCustomObject]@{
                TimeGenerated = Get-Date
                EventID = 1000
                EntryType = "Information"
            }
        }

        # Mock Invoke-Command to run the script block locally and pass arguments
        Mock Invoke-Command {
            param($Session, $ScriptBlock, $ArgumentList)
            & $ScriptBlock @ArgumentList
        }
    }

    Context "When event source does not exist" {
        It "Should create new event source and write event log" {
            # Call the function with mocks enabled
            Write-WindowsEventLog -Session $mockSession -LogName "Application" -Source "TestSource" -EventID 1000 -EntryType "Information" -Message "Test message"

            # Assert New-EventLog was called once to create source
            Assert-MockCalled New-EventLog -Times 1 -ParameterFilter {
                $Source -eq "TestSource" -and $LogName -eq "Application"
            }

            # Assert Write-EventLog was called once to write event
            Assert-MockCalled Write-EventLog -Times 1 -ParameterFilter {
                $Source -eq "TestSource" -and $LogName -eq "Application" -and $EventID -eq 1000 -and $EntryType -eq "Information"
            }
        }
    }
}
#>

$env:UNIT_TEST = $null