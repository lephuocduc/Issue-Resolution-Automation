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
#. "$PSScriptRoot/../../Scripts/PerformanceIssue/PerformanceIssue.ps1"

