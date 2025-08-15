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

# Unit Tests for Get System Uptime Function
Describe "Get System Uptime Function Tests" {

}

# Unit Tests for Get Performance Metrics Function
Describe "Get-PerformanceMetrics" {
    BeforeAll {
        # Mock session
        $mockSession = New-MockObject -Type System.Management.Automation.Runspaces.PSSession
    }
    Context "When session parameter is invalid" {
        # Test case: Should throw an error when session is not a valid PSSession
        It "Should throw an error when session is not a valid PSSession" {
            { Get-PerformanceMetrics -Session $null} | Should -Throw
        }
    }

    Context "When collecting metrics from a healthy system" {
        BeforeAll {
            # Mock static system data
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq "Win32_OperatingSystem" } {
                [PSCustomObject]@{
                    TotalPhysicalMemory = 10000000000 # 10 GB
                }
            }

            # Mock Performance counters
            $mockCounterData = @{
                SystemCpuSamples = @(50.0, 55.0, 60.0) # Simulated CPU samples
                SystemMemorySamples = @(8000000000, 8500000000, 9000000000) # Simulated Memory samples
                ProcessSamples = @{
                    1001 = @{ CPU = @(10.0, 12.0, 11.0); Memory = @(500000000, 550000000, 600000000) } # Process ID 1001
                    1002 = @{ CPU = @(20.0, 22.0, 21.0); Memory = @(700000000, 750000000, 800000000) } # Process ID 1002
                }
            }

            Mock Get-Counter {
                param ($Counter)
                switch -Wildcard ($Counter) {
                    "*Processor Time" {
                        $value = $mockCounterData.SystemCpuSamples[$script:sampleIndex]
                        return [PSCustomObject]@{
                            CounterSamples = [PSCustomObject]@{
                                CookedValue = $value
                            }
                        }
                    }
                    "*Available Bytes" {
                        $value = $mockCounterData.SystemMemorySamples[$script:sampleIndex]
                        return [PSCustomObject]@{
                            CounterSamples = [PSCustomObject]@{
                                CookedValue = $value
                            }
                        }
                    }
                    "*Process(*)*" {
                        return [PSCustomObject]@{
                            CounterSamples = @(
                                [PSCustomObject]@{
                                    Path = "\Process(Test1)\% Processor Time"
                                    CookedValue = $mockCounterData.ProcessSamples[1001].CPU[$script:sampleIndex]
                                },
                                [PSCustomObject]@{
                                    Path = "\Process(Test2)\% Processor Time"
                                    CookedValue = $mockCounterData.ProcessSamples[1002].CPU[$script:sampleIndex]
                                }
                            )
                        }
                    }
                }
            }

            # Mock process information
            Mock Get-Process {
                [PSCustomObject]@{
                    Id = 1001
                    ProcessName = "TestProcess1"
                    WorkingSet64 = $mockCounterData.ProcessSamples[1001].Memory[$script:sampleIndex]
                },
                [PSCustomObject]@{
                    Id = 1002
                    ProcessName = "TestProcess2"
                    WorkingSet64 = $mockCounterData.ProcessSamples[1002].Memory[$script:sampleIndex]
                }
            }

            # Mock process owner resolution
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq "Win32_Process" } {
                [PSCustomObject]@{
                    ProcessId = $Id
                }
            }

            Mock Invoke-CimMethod -ParameterFilter { $Method -eq "GetOwner" } {
                [PSCustomObject]@{
                    Domain = "TestDomain"
                    User = "User$($InputObject.ProcessId % 10)"
                }
            }
        }

        BeforeEach {
            $script:sampleIndex = 0 # Reset sample index for each test
        }

        It "Shoud successfully collect performance metrics" {
            $result = Get-PerformanceMetrics -Session $mockSession -Samples 2 -Interval 0
            $result | Should -Not -Be $null
            $result.SystemMetrics.AvgCPU | Should -BeGreaterThan 0
            $result.ProcessMetrics.Count | Should -Be 2
        }

    # Test case: Successfully collect performance metrics from a healthy server

    # Test case: Verify that multiple samples are correctly averaged

    # Test case: Verify owner cache correctly associates processes with users

    # Test case: Verify process metrics contain expected fields (PID, ProcessName, User, AvgCPU, AvgMemoryBytes)

    # Test case: Verify process data is correctly aggregated over multiple samples
    }
}