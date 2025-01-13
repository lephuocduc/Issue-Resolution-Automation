@{
    Root = 'AutomationTool.ps1'
    OutputPath = 'out'
    Package = @{
        Enabled = $true
        Obfuscate = $false
        HideConsoleWindow = $true
        DotNetVersion = 'v4.6.2'
        FileVersion = '1.0.0'
        FileDescription = ''
        ProductName = 'AutomationProject'
        ProductVersion = ''
        Copyright = ''
        RequireElevation = $true
        ApplicationIconPath = 'icon.ico'
        PackageType = 'Console'
    }
    Bundle = @{
        Enabled = $true
        Modules = $true
        # IgnoredModules = @()
    }
}
        