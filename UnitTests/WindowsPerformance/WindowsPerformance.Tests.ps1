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
Describe "Get Performance Metrics Function Tests" {
# https://grok.com/chat/4949530a-41a7-473c-b551-ccf06fda80e9
# Test that the function correctly invokes the static scriptblock to fetch total physical memory and number of processor cores from the remote session

# Test that the loop runs exactly $Samples times, invoking the sample scriptblock each time

# For each sample, confirm that CPU percentage (\Processor(_Total)\% Processor Time) and memory usage (calculated from \Memory\Available Bytes) are collected correctly

# Ensure processes with WorkingSet64 > 10MB (excluding PID 0) are fetched

# Confirm that process owners are fetched

# 
}