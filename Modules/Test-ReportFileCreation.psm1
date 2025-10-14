function Test-ReportFileCreation {
    [CmdletBinding()]
    param(
        [string]$LogPath = "C:\Temp",
        [string]$TestFile = "test_$(Get-Date -Format 'ddMMyyyy_HHmmss').html"
    )
    
    try {        
        # Use Join-Path for combining paths
        $testFilePath = Join-Path -Path $LogPath -ChildPath $TestFile

        # Create directory structure if needed
        if (-not (Test-Path -Path $LogPath -PathType Container)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }

        # Generate content with UTC timestamp for consistency
        $utcTimestamp = (Get-Date).ToUniversalTime().ToString("o")
        $testContent = "Log creation test: $utcTimestamp"

        # Write content to file
        Set-Content -Path $testFilePath -Value $testContent -Force

        # Verify file creation
        if (Test-Path -Path $testFilePath -PathType Leaf) {
            Remove-Item -Path $testFilePath -Force
            return $true
        }

        throw "File verification failed after write operation"
    }
    catch {
        return $false
    }
}