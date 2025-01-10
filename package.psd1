@{
    Root = 'C:\AutomationProject\UI.ps1'
    OutputPath = 'C:\AutomationProject\'
    Package = @{
        Enabled = $true
        Obfuscate = $false
        HideConsoleWindow = $false
        DotNetVersion = 'v4.8'
        Resources = [string[]]@('Scripts', 'modules')  # Explicitly cast as string array
    }
}