@{
    Root = 'ScriptManager.ps1'
    OutputPath = ''
    Package = @{
        Enabled = $true
        Obfuscate = $false
        HideConsoleWindow = $true
        DotNetVersion = ''
        FileVersion = '1.0.0'
        FileDescription = ''
        ProductName = 'ScriptManager'
        ProductVersion = ''
        Copyright = 'Duc Le'
        RequireElevation = $true
        ApplicationIconPath = ''
        PackageType = 'Console'
    }
    Bundle = @{
        Enabled = $true
        Modules = $true
        # IgnoredModules = @()
    }
}
