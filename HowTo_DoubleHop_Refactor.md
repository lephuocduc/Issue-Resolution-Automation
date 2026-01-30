# How to Refactor a Script for Double Hop (Nested Remoting)

This guide details how to convert a standard "Single Hop" PowerShell script (Local Machine → Target Server) into a "Double Hop" script (Local Machine → Jump Host → Target Server).

## The Core Concept
**Double Hop** solves network or security segmentation where your local machine cannot reach the Target Server directly, but can reach a "Jump Host" which can.

*   **Before:** Execution happens on **Local Machine**. Logic connects directly to Target.
*   **After:** Execution happens on **Jump Host**. Local Machine sends instructions (ScriptBlock) to Jump Host. Jump Host connects to Target.

---

## 5-Step Refactoring Process

### 1. Update Parameters (The Setup)
**Modify the `Param` block:**
```powershell
Param(   
    # Credential is used for connecting to the jump host and target server
    [Parameter(Mandatory=$true)]
    [System.Management.Automation.PSCredential]$ADM_Credential,

    # The intermediate servers
    [Parameter(Mandatory=$true)]
    [string[]]$JumpHost,

    # Allow passing module code content directly
    [Parameter(Mandatory=$true)]
    [string]$ModuleContents
)
```

### 2. Establish Outer Session & Hydrate (The Bridge)
Before the GUI opens, connect to the Jump Host and send it the necessary functions/modules. The Jump Host doesn't have local files, so we must pass to it.

**Add this after inputs:**
```powershell
# 1. Connect to Jump Host
$JumpHostSession = New-PSSession -ComputerName $JumpHost -Credential $ADM_Credential

# 2. Send local modules to Jump Host
Invoke-Command -Session $JumpHostSession -ScriptBlock $ModuleContents
```

### 3. Split the Brain (GUI vs. Logic)
In a normal script, the GUI Event Handler (e.g., `$okButton_Click`) runs the logic. In Double Hop, the GUI **only** gathers inputs.

**Refactor `$okButton_Click`:**
*   **KEEP:** Validation logic (Checking if text boxes are empty).
*   **REMOVE:** Direct calls to functional cmdlets (`Get-Service`, `Test-ServerAvailability`).
*   **ADD:** Parameter packaging.

```powershell
$okButton.Add_Click({
    # 1. Gather Inputs
    $serverName = $textBoxServerName.Text
    $diskName = $diskTextBox.Text
    $ticket = $ticketNumberTextBox.Text

    # 2. Package everything (including credentials!) into a Hashtable
    # The remote session cannot see local variables.
    $params = @{
        ServerName     = $serverName
        DiskName       = $diskName
        TicketNumber   = $ticket
        ADM_Credential = $ADM_Credential
    }

    # ... Continued in Step 4 ...
})
```

### 4. Wrapper ScriptBlock (The Remote Payload)
This is the most critical step. You must wrap your original business logic into a `ScriptBlock`. This block will be serialized and sent to the Jump Host.

```powershell
    # ... Inside $okButton.Add_Click ...

    $ScriptBlock = {
        param ($params) # Accepts the hashtable we created

        # UNPACK parameters
        $Target    = $params.ServerName
        $Creds     = $params.ADM_Credential
        $Disk      = $params.DiskName
        $Ticket    = $params.TicketNumber

        # --- LOGIC RUNNING ON JUMP HOST START ---

        # 1. Create Inner Session (The Second Hop)
        # We use the passed $Creds.
        $TargetSession = Get-Session -serverName $Target -Credential $Creds
        
        if (-not $TargetSession) { return "Failed to connect to target" }

        # 2. Run your original logic using the Inner Session
        # Replace local calls with calls using the session
        $DiskInfo = Get-DiskSpaceDetails -Session $TargetSession -DiskName $Disk

        # 3. Return results
        # Return simple objects (Strings, Numbers, PSCustomObjects)
        return "Analysis complete. Free space: $($DiskInfo.FreePercentage)%"

        # --- LOGIC RUNNING ON JUMP HOST END ---
    }

    # EXECUTE the block
    $result = Invoke-Command -Session $JumpHostSession -ScriptBlock $ScriptBlock -ArgumentList $params
    
    # Then we can update Local GUI with result $result
    # E.g Update-StatusLabel -text $result
```

### 5. Return File Handling (Serialization)
If your script typically generates a report (HTML/CSV) and opens it, you can't just `Start-Process` inside the ScriptBlock (that would open a window on the Jump Host!).

**Pattern:**
1.  **Remote:** Read the file content.
2.  **Return:** Return an object with the content string.
3.  **Local:** Save content to a temp file and `Start-Process` locally.

**In Remote Logic ($ScriptBlock):**
```powershell
$reportPath = Export-DiskReport ...
if ($reportPath) {
    $content = Get-Content $reportPath -Raw
    return [PSCustomObject]@{
        Type = "File"
        Name = "Report.html"
        Content = $content
    }
}
```

**In Local Logic (After Invoke-Command):**
```powershell
$result = Invoke-Command ...
if ($result.Type -eq "File") {
    $localPath = "$env:TEMP\$($result.Name)"
    $result.Content | Out-File $localPath
    Start-Process $localPath
}
```