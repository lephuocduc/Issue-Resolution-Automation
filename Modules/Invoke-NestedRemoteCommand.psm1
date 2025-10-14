function Invoke-NestedRemoteCommand {
    param (
        [hashtable]$params,
        [scriptblock]$ScriptBlock,
        [System.Management.Automation.PSCredential]$ADM_Credential
    )
    
    try {
        # Validate required parameters
        if (-not $params.ContainsKey('JumpHost')) {
            throw "Missing required parameter: JumpHost"
        }
        if (-not $params.ContainsKey('ADM_Credential')) {
            throw "Missing required parameter: ADM_Credential"
        }
        
        $JumpHost = $params.JumpHost
        $ADM_Credential = $params.ADM_Credential
        
        Write-Log "Starting nested remote command to JumpHost: $JumpHost"
        
        # Create session to JumpHost
        $JumpHostSession = Get-Session -serverName $JumpHost -Credential $ADM_Credential
        if ($null -eq $JumpHostSession) {
            throw "Failed to establish session to JumpHost: $JumpHost"
        }
        
        Write-Log "Successfully connected to JumpHost. Executing remote script block..."
        
        # Execute the script block on the JumpHost
        $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
        
        Write-Log "Remote script block execution completed"
        
        return $result
        
    } catch {
        Write-Log "Error in Invoke-NestedRemoteCommand: $($_.Exception.Message)" "Error"
        throw
    } finally {
        # Clean up the JumpHost session
        if ($JumpHostSession) {
            Remove-PSSession -Session $JumpHostSession -ErrorAction SilentlyContinue
            Write-Log "JumpHost session cleaned up"
        }
    }
}