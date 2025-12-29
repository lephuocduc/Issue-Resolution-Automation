@{
    Root = '.\ScriptManager\ScriptManager.ps1'
    OutputPath = ''
    Package = @{
        Enabled = $true
        AdditionalFiles = @( '..\Modules\*' )
        Obfuscate = $false
        HideConsoleWindow = $true
        DotNetVersion = 'v4.6.2'
        FileVersion = '1.0.0'
        FileDescription = ''
        ProductName = 'ScriptManager'
        ProductVersion = ''
        Copyright = 'Duc Le'
        RequireElevation = $true
        ApplicationIconPath = 'C:\icon.ico'
        PackageType = 'Console'
    }
    Bundle = @{
        Enabled = $true
        Modules = $true
    }
}