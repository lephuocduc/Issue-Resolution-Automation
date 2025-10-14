function Test-DiskAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-zA-Z]$')]
        [string]$DiskName
    )

    try {       
        # Optimized remote check using direct WMI access
        $diskExists = Invoke-Command -Session $Session -ScriptBlock {
            $driveLetter = $args[0] + ':'
            try {
                $drive = Get-CimInstance -ClassName Win32_LogicalDisk `
                         -Filter "DeviceID = '$driveLetter'" `
                         -ErrorAction Stop
                return [bool]$drive
            }
            catch {
                return $false
            }
        } -ArgumentList $DiskName -ErrorAction Stop

        if ($diskExists) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        return $false
    }
}