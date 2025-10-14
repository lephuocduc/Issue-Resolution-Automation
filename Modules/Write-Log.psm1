function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [string]$LogDirectory = "C:\temp",
        [string]$LogFile
    )

    # Create directory if needed (more efficient check)
    if (-not [System.IO.Directory]::Exists($LogDirectory)) {
        [System.IO.Directory]::CreateDirectory($LogDirectory) | Out-Null -ErrorAction SilentlyContinue
    }

    # Generate all date strings in a single call
    $currentDate = Get-Date
    $datePart = $currentDate.ToString("dd-MM-yyyy")
    #$LogPath = Join-Path $LogDirectory "LowFreeSpace-log-$datePart.log"
    $LogPath = Join-Path $LogDirectory "$LogFile-log-$datePart.log"
    $timestamp = $currentDate.ToString("dd-MM-yyyy HH:mm:ss")

    # Construct and write log entry
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}