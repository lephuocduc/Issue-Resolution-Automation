@{
    Root = 'ScriptManager2.ps1'
    OutputPath = ''  # Set output path
    Package = @{
        Enabled = $true
        Obfuscate = $false
        HideConsoleWindow = $true
        DotNetVersion = 'v4.6.2'
        FileVersion = '1.0.0'
        FileDescription = ''
        ProductName = 'ScriptManager'
        ProductVersion = ''
        Copyright = 'Duc Le'
        RequireElevation = $true
        ApplicationIconPath = '.\bin\icon.ico'  # Update icon path
        PackageType = 'Console'
    }
    Bundle = @{
        Enabled = $true
        Modules = $true
    }
}